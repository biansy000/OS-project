/*
 *  linux/mm/oom_kill.c
 * 
 *  Copyright (C)  1998,2000  Rik van Riel
 *	Thanks go out to Claus Fischer for some serious inspiration and
 *	for goading me into coding this file...
 *  Copyright (C)  2010  Google, Inc.
 *	Rewritten by David Rientjes
 *
 *  The routines in this file are used to kill a process when
 *  we're seriously out of memory. This gets called from __alloc_pages()
 *  in mm/page_alloc.c when we really run out of memory.
 *
 *  Since we won't call these routines often (on a well-configured
 *  machine) this file will double as a 'coding guide' and a signpost
 *  for newbie kernel hackers. It features several pointers to major
 *  kernel subsystems and hints as to where to find out what things do.
 */

#include <linux/oom.h>
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/sched.h>
#include <linux/swap.h>
#include <linux/timex.h>
#include <linux/jiffies.h>
#include <linux/cpuset.h>
#include <linux/export.h>
#include <linux/notifier.h>
#include <linux/memcontrol.h>
#include <linux/mempolicy.h>
#include <linux/security.h>
#include <linux/ptrace.h>
#include <linux/freezer.h>
#include <linux/ftrace.h>
#include <linux/ratelimit.h>
#include <linux/time.h>

#define CREATE_TRACE_POINTS
#include <trace/events/oom.h>

int sysctl_panic_on_oom;
int sysctl_oom_kill_allocating_task;
int sysctl_oom_dump_tasks = 1;
static DEFINE_SPINLOCK(zone_scan_lock);


// MY NEWLY ADDED STRUCT AND FUNCTIONS, DETAILED EXPLANATIONS ARE IN THE INPLEMENTATION OF FUNCTIONS
struct MMLimits {
    uid_t uid; 						// user id
    long mm_max;					// the memory limit
	long time_limit;				// how long it can exceed its memory limit
    struct list_head next;			// point to next element
};

struct oom_time_record{
	uid_t uid; 	
	long estart_t;					// start time of memory exceeding
	struct list_head next;
};

LIST_HEAD(time_limit_head);

DEFINE_MUTEX(oom_time_record_mutex);

/* FUNCTIONS ARE ADDED IN LINE 875 - 1140 */
extern struct list_head mm_limit_head;
long get_total_mm_rss(uid_t uid);
int set_oom_time(uid_t uid, unsigned int t_limit);
void remove_oom_time(uid_t uid);

unsigned int new_oom_badness(struct task_struct *p,  long t_limit, long m_limit, long smallest_stime,
		struct mem_cgroup *memcg, const nodemask_t *nodemask, unsigned long totalpages);

struct task_struct* _find_largest_p(uid_t uid, long mlimit, long tlimit,
		unsigned long totalpages, struct mem_cgroup *memcg, const nodemask_t *nodemask);

struct task_struct* find_largest_p(unsigned long totalpages, 
		struct mem_cgroup *memcg, const nodemask_t *nodemask);

static void new_oom_kill_process(struct task_struct *p, gfp_t gfp_mask, int order,
			     unsigned int points, unsigned long totalpages,
			     struct mem_cgroup *memcg, nodemask_t *nodemask,
			     const char *message);

/*
 * compare_swap_oom_score_adj() - compare and swap current's oom_score_adj
 * @old_val: old oom_score_adj for compare
 * @new_val: new oom_score_adj for swap
 *
 * Sets the oom_score_adj value for current to @new_val iff its present value is
 * @old_val.  Usually used to reinstate a previous value to prevent racing with
 * userspacing tuning the value in the interim.
 */
void compare_swap_oom_score_adj(int old_val, int new_val)
{
	struct sighand_struct *sighand = current->sighand;

	spin_lock_irq(&sighand->siglock);
	if (current->signal->oom_score_adj == old_val)
		current->signal->oom_score_adj = new_val;
	trace_oom_score_adj_update(current);
	spin_unlock_irq(&sighand->siglock);
}

/**
 * test_set_oom_score_adj() - set current's oom_score_adj and return old value
 * @new_val: new oom_score_adj value
 *
 * Sets the oom_score_adj value for current to @new_val with proper
 * synchronization and returns the old value.  Usually used to temporarily
 * set a value, save the old value in the caller, and then reinstate it later.
 */
int test_set_oom_score_adj(int new_val)
{
	struct sighand_struct *sighand = current->sighand;
	int old_val;

	spin_lock_irq(&sighand->siglock);
	old_val = current->signal->oom_score_adj;
	current->signal->oom_score_adj = new_val;
	trace_oom_score_adj_update(current);
	spin_unlock_irq(&sighand->siglock);

	return old_val;
}

#ifdef CONFIG_NUMA
/**
 * has_intersects_mems_allowed() - check task eligiblity for kill
 * @tsk: task struct of which task to consider
 * @mask: nodemask passed to page allocator for mempolicy ooms
 *
 * Task eligibility is determined by whether or not a candidate task, @tsk,
 * shares the same mempolicy nodes as current if it is bound by such a policy
 * and whether or not it has the same set of allowed cpuset nodes.
 */
static bool has_intersects_mems_allowed(struct task_struct *tsk,
					const nodemask_t *mask)
{
	struct task_struct *start = tsk;

	do {
		if (mask) {
			/*
			 * If this is a mempolicy constrained oom, tsk's
			 * cpuset is irrelevant.  Only return true if its
			 * mempolicy intersects current, otherwise it may be
			 * needlessly killed.
			 */
			if (mempolicy_nodemask_intersects(tsk, mask))
				return true;
		} else {
			/*
			 * This is not a mempolicy constrained oom, so only
			 * check the mems of tsk's cpuset.
			 */
			if (cpuset_mems_allowed_intersects(current, tsk))
				return true;
		}
	} while_each_thread(start, tsk);

	return false;
}
#else
static bool has_intersects_mems_allowed(struct task_struct *tsk,
					const nodemask_t *mask)
{
	return true;
}
#endif /* CONFIG_NUMA */

/*
 * The process p may have detached its own ->mm while exiting or through
 * use_mm(), but one or more of its subthreads may still have a valid
 * pointer.  Return p, or any of its subthreads with a valid ->mm, with
 * task_lock() held.
 */
struct task_struct *find_lock_task_mm(struct task_struct *p)
{
	struct task_struct *t = p;

	do {
		task_lock(t);
		if (likely(t->mm))
			return t;
		task_unlock(t);
	} while_each_thread(p, t);

	return NULL;
}

/* return true if the task is not adequate as candidate victim task. */
static bool oom_unkillable_task(struct task_struct *p,
		const struct mem_cgroup *memcg, const nodemask_t *nodemask)
{
	if (is_global_init(p))
		return true;
	if (p->flags & PF_KTHREAD)
		return true;

	/* When mem_cgroup_out_of_memory() and p is not member of the group */
	if (memcg && !task_in_mem_cgroup(p, memcg))
		return true;

	/* p may not have freeable memory in nodemask */
	if (!has_intersects_mems_allowed(p, nodemask))
		return true;

	return false;
}


/**
 * oom_badness - heuristic function to determine which candidate task to kill
 * @p: task struct of which task we should calculate
 * @totalpages: total present RAM allowed for page allocation
 *
 * The heuristic for determining which task to kill is made to be as simple and
 * predictable as possible.  The goal is to return the highest value for the
 * task consuming the most memory to avoid subsequent oom failures.
 */
unsigned int oom_badness(struct task_struct *p, struct mem_cgroup *memcg,
		      const nodemask_t *nodemask, unsigned long totalpages)
{
	long points;

	if (oom_unkillable_task(p, memcg, nodemask))
		return 0;

	p = find_lock_task_mm(p);
	if (!p)
		return 0;

	if (p->signal->oom_score_adj == OOM_SCORE_ADJ_MIN) {
		task_unlock(p);
		return 0;
	}

	/*
	 * The memory controller may have a limit of 0 bytes, so avoid a divide
	 * by zero, if necessary.
	 */
	if (!totalpages)
		totalpages = 1;

	/*
	 * The baseline for the badness score is the proportion of RAM that each
	 * task's rss, pagetable and swap space use.
	 */
	points = get_mm_rss(p->mm) + p->mm->nr_ptes;
	points += get_mm_counter(p->mm, MM_SWAPENTS);

	points *= 1000;
	points /= totalpages;
	task_unlock(p);

	/*
	 * Root processes get 3% bonus, just like the __vm_enough_memory()
	 * implementation used by LSMs.
	 */
	if (has_capability_noaudit(p, CAP_SYS_ADMIN))
		points -= 30;

	/*
	 * /proc/pid/oom_score_adj ranges from -1000 to +1000 such that it may
	 * either completely disable oom killing or always prefer a certain
	 * task.
	 */
	points += p->signal->oom_score_adj;

	/*
	 * Never return 0 for an eligible task that may be killed since it's
	 * possible that no single user task uses more than 0.1% of memory and
	 * no single admin tasks uses more than 3.0%.
	 */
	if (points <= 0)
		return 1;
	return (points < 1000) ? points : 1000;
}


/*
 * Determine the type of allocation constraint.
 */
#ifdef CONFIG_NUMA
static enum oom_constraint constrained_alloc(struct zonelist *zonelist,
				gfp_t gfp_mask, nodemask_t *nodemask,
				unsigned long *totalpages)
{
	struct zone *zone;
	struct zoneref *z;
	enum zone_type high_zoneidx = gfp_zone(gfp_mask);
	bool cpuset_limited = false;
	int nid;

	/* Default to all available memory */
	*totalpages = totalram_pages + total_swap_pages;

	if (!zonelist)
		return CONSTRAINT_NONE;
	/*
	 * Reach here only when __GFP_NOFAIL is used. So, we should avoid
	 * to kill current.We have to random task kill in this case.
	 * Hopefully, CONSTRAINT_THISNODE...but no way to handle it, now.
	 */
	if (gfp_mask & __GFP_THISNODE)
		return CONSTRAINT_NONE;

	/*
	 * This is not a __GFP_THISNODE allocation, so a truncated nodemask in
	 * the page allocator means a mempolicy is in effect.  Cpuset policy
	 * is enforced in get_page_from_freelist().
	 */
	if (nodemask && !nodes_subset(node_states[N_HIGH_MEMORY], *nodemask)) {
		*totalpages = total_swap_pages;
		for_each_node_mask(nid, *nodemask)
			*totalpages += node_spanned_pages(nid);
		return CONSTRAINT_MEMORY_POLICY;
	}

	/* Check this allocation failure is caused by cpuset's wall function */
	for_each_zone_zonelist_nodemask(zone, z, zonelist,
			high_zoneidx, nodemask)
		if (!cpuset_zone_allowed_softwall(zone, gfp_mask))
			cpuset_limited = true;

	if (cpuset_limited) {
		*totalpages = total_swap_pages;
		for_each_node_mask(nid, cpuset_current_mems_allowed)
			*totalpages += node_spanned_pages(nid);
		return CONSTRAINT_CPUSET;
	}
	return CONSTRAINT_NONE;
}
#else
static enum oom_constraint constrained_alloc(struct zonelist *zonelist,
				gfp_t gfp_mask, nodemask_t *nodemask,
				unsigned long *totalpages)
{
	*totalpages = totalram_pages + total_swap_pages;
	return CONSTRAINT_NONE;
}
#endif



/*
 * Simple selection loop. We chose the process with the highest
 * number of 'points'. We expect the caller will lock the tasklist.
 *
 * (not docbooked, we don't want this one cluttering up the manual)
 */
static struct task_struct *select_bad_process(unsigned int *ppoints,
		unsigned long totalpages, struct mem_cgroup *memcg,
		const nodemask_t *nodemask, bool force_kill)
{
	struct task_struct *g, *p;
	struct task_struct *chosen = NULL;
	*ppoints = 0;

	do_each_thread(g, p) {
		unsigned int points;

		if (p->exit_state)
			continue;
		if (oom_unkillable_task(p, memcg, nodemask))
			continue;

		/*
		 * This task already has access to memory reserves and is
		 * being killed. Don't allow any other task access to the
		 * memory reserve.
		 *
		 * Note: this may have a chance of deadlock if it gets
		 * blocked waiting for another task which itself is waiting
		 * for memory. Is there a better alternative?
		 */
		if (test_tsk_thread_flag(p, TIF_MEMDIE)) {
			if (unlikely(frozen(p)))
				__thaw_task(p);
			if (!force_kill)
				return ERR_PTR(-1UL);
		}
		if (!p->mm)
			continue;

		if (p->flags & PF_EXITING) {
			/*
			 * If p is the current task and is in the process of
			 * releasing memory, we allow the "kill" to set
			 * TIF_MEMDIE, which will allow it to gain access to
			 * memory reserves.  Otherwise, it may stall forever.
			 *
			 * The loop isn't broken here, however, in case other
			 * threads are found to have already been oom killed.
			 */
			if (p == current) {
				chosen = p;
				*ppoints = 1000;
			} else if (!force_kill) {
				/*
				 * If this task is not being ptraced on exit,
				 * then wait for it to finish before killing
				 * some other task unnecessarily.
				 */
				if (!(p->group_leader->ptrace & PT_TRACE_EXIT))
					return ERR_PTR(-1UL);
			}
		}

		points = oom_badness(p, memcg, nodemask, totalpages);

		if (points > *ppoints) {
			chosen = p;
			*ppoints = points;
		}
	} while_each_thread(g, p);

	return chosen;
}

/**
 * dump_tasks - dump current memory state of all system tasks
 * @mem: current's memory controller, if constrained
 * @nodemask: nodemask passed to page allocator for mempolicy ooms
 *
 * Dumps the current memory state of all eligible tasks.  Tasks not in the same
 * memcg, not in the same cpuset, or bound to a disjoint set of mempolicy nodes
 * are not shown.
 * State information includes task's pid, uid, tgid, vm size, rss, cpu, oom_adj
 * value, oom_score_adj value, and name.
 *
 * Call with tasklist_lock read-locked.
 */
static void dump_tasks(const struct mem_cgroup *memcg, const nodemask_t *nodemask)
{
	struct task_struct *p;
	struct task_struct *task;

	pr_info("[ pid ]   uid  tgid total_vm      rss cpu oom_adj oom_score_adj name\n");
	for_each_process(p) {
		if (oom_unkillable_task(p, memcg, nodemask))
			continue;

		task = find_lock_task_mm(p);
		if (!task) {
			/*
			 * This is a kthread or all of p's threads have already
			 * detached their mm's.  There's no need to report
			 * them; they can't be oom killed anyway.
			 */
			continue;
		}

		pr_info("[%5d] %5d %5d %8lu %8lu %3u     %3d         %5d %s\n",
			task->pid, task_uid(task), task->tgid,
			task->mm->total_vm, get_mm_rss(task->mm),
			task_cpu(task), task->signal->oom_adj,
			task->signal->oom_score_adj, task->comm);
		task_unlock(task);
	}
}

static void dump_header(struct task_struct *p, gfp_t gfp_mask, int order,
			struct mem_cgroup *memcg, const nodemask_t *nodemask)
{
	task_lock(current);
	pr_warning("%s invoked oom-killer: gfp_mask=0x%x, order=%d, "
		"oom_adj=%d, oom_score_adj=%d\n",
		current->comm, gfp_mask, order, current->signal->oom_adj,
		current->signal->oom_score_adj);
	cpuset_print_task_mems_allowed(current);
	task_unlock(current);
	dump_stack();
	mem_cgroup_print_oom_info(memcg, p);
	show_mem(SHOW_MEM_FILTER_NODES);
	if (sysctl_oom_dump_tasks)
		dump_tasks(memcg, nodemask);
}

#define K(x) ((x) << (PAGE_SHIFT-10))
static void oom_kill_process(struct task_struct *p, gfp_t gfp_mask, int order,
			     unsigned int points, unsigned long totalpages,
			     struct mem_cgroup *memcg, nodemask_t *nodemask,
			     const char *message)
{
	struct task_struct *victim = p;
	struct task_struct *child;
	struct task_struct *t = p;
	struct mm_struct *mm;
	unsigned int victim_points = 0;
	static DEFINE_RATELIMIT_STATE(oom_rs, DEFAULT_RATELIMIT_INTERVAL,
					      DEFAULT_RATELIMIT_BURST);

	/*
	 * If the task is already exiting, don't alarm the sysadmin or kill
	 * its children or threads, just set TIF_MEMDIE so it can die quickly
	 */
	if (p->flags & PF_EXITING) {
		set_tsk_thread_flag(p, TIF_MEMDIE);
		return;
	}

	if (__ratelimit(&oom_rs))
		dump_header(p, gfp_mask, order, memcg, nodemask);

	task_lock(p);
	pr_err("%s: Kill process %d (%s) score %d or sacrifice child\n",
		message, task_pid_nr(p), p->comm, points);
	task_unlock(p);

	/*
	 * If any of p's children has a different mm and is eligible for kill,
	 * the one with the highest oom_badness() score is sacrificed for its
	 * parent.  This attempts to lose the minimal amount of work done while
	 * still freeing memory.
	 */
	do {
		list_for_each_entry(child, &t->children, sibling) {
			unsigned int child_points;

			if (child->mm == p->mm)
				continue;
			/*
			 * oom_badness() returns 0 if the thread is unkillable
			 */
			child_points = oom_badness(child, memcg, nodemask,
								totalpages);
			if (child_points > victim_points) {
				victim = child;
				victim_points = child_points;
			}
		}
	} while_each_thread(p, t);

	victim = find_lock_task_mm(victim);
	if (!victim)
		return;

	/* mm cannot safely be dereferenced after task_unlock(victim) */
	mm = victim->mm;
	pr_err("Killed process %d (%s) total-vm:%lukB, anon-rss:%lukB, file-rss:%lukB\n",
		task_pid_nr(victim), victim->comm, K(victim->mm->total_vm),
		K(get_mm_counter(victim->mm, MM_ANONPAGES)),
		K(get_mm_counter(victim->mm, MM_FILEPAGES)));
	task_unlock(victim);

	/*
	 * Kill all user processes sharing victim->mm in other thread groups, if
	 * any.  They don't get access to memory reserves, though, to avoid
	 * depletion of all memory.  This prevents mm->mmap_sem livelock when an
	 * oom killed thread cannot exit because it requires the semaphore and
	 * its contended by another thread trying to allocate memory itself.
	 * That thread will now get access to memory reserves since it has a
	 * pending fatal signal.
	 */
	for_each_process(p)
		if (p->mm == mm && !same_thread_group(p, victim) &&
		    !(p->flags & PF_KTHREAD)) {
			if (p->signal->oom_score_adj == OOM_SCORE_ADJ_MIN)
				continue;

			task_lock(p);	/* Protect ->comm from prctl() */
			pr_err("Kill process %d (%s) sharing same memory\n",
				task_pid_nr(p), p->comm);
			task_unlock(p);
			do_send_sig_info(SIGKILL, SEND_SIG_FORCED, p, true);
		}
	
	set_tsk_thread_flag(victim, TIF_MEMDIE);
	do_send_sig_info(SIGKILL, SEND_SIG_FORCED, victim, true);
}
#undef K

#define K(x) ((x) << (PAGE_SHIFT-10))
static void new_oom_kill_process(struct task_struct *p, gfp_t gfp_mask, int order,
			     unsigned int points, unsigned long totalpages,
			     struct mem_cgroup *memcg, nodemask_t *nodemask,
			     const char *message)
{
	struct task_struct *victim = p;
	struct mm_struct *mm;
	int i = 0;
	static DEFINE_RATELIMIT_STATE(oom_rs, DEFAULT_RATELIMIT_INTERVAL,
					      DEFAULT_RATELIMIT_BURST);

	/*
	 * If the task is already exiting, don't alarm the sysadmin or kill
	 * its children or threads, just set TIF_MEMDIE so it can die quickly
	 */
	
	if (p->flags & PF_EXITING) {
		set_tsk_thread_flag(p, TIF_MEMDIE);
		return;
	}
	
	/*
	if (__ratelimit(&oom_rs))
		dump_header(p, gfp_mask, order, memcg, nodemask);
	*/

	victim = find_lock_task_mm(victim);
	if (!victim)
		return;

	/* mm cannot safely be dereferenced after task_unlock(victim) */
	
	mm = victim->mm;
	pr_err("Killed process %d (%s) total-vm:%lukB, anon-rss:%lukB, file-rss:%lukB\n",
		task_pid_nr(victim), victim->comm, K(victim->mm->total_vm),
		K(get_mm_counter(victim->mm, MM_ANONPAGES)),
		K(get_mm_counter(victim->mm, MM_FILEPAGES)));

	task_unlock(victim);

	/*
	 * Kill all user processes sharing victim->mm in other thread groups, if
	 * any.  They don't get access to memory reserves, though, to avoid
	 * depletion of all memory.  This prevents mm->mmap_sem livelock when an
	 * oom killed thread cannot exit because it requires the semaphore and
	 * its contended by another thread trying to allocate memory itself.
	 * That thread will now get access to memory reserves since it has a
	 * pending fatal signal.
	 */
	for_each_process(p){
		if (p->mm == mm && !same_thread_group(p, victim) &&
		    !(p->flags & PF_KTHREAD)) {
			if (p->signal->oom_score_adj == OOM_SCORE_ADJ_MIN)
				continue;

			task_lock(p);	/* Protect ->comm from prctl() */
			pr_err("Kill process %d (%s) sharing same memory\n",
				task_pid_nr(p), p->comm);
			task_unlock(p);
			do_send_sig_info(SIGKILL, SEND_SIG_FORCED, p, true);
			printk("It is %dth time\n", i);
			i++;
		}
	}
	set_tsk_thread_flag(victim, TIF_MEMDIE);
	do_send_sig_info(SIGKILL, SEND_SIG_FORCED, victim, true);
}
#undef K

/*
 * Determines whether the kernel must panic because of the panic_on_oom sysctl.
 */
static void check_panic_on_oom(enum oom_constraint constraint, gfp_t gfp_mask,
				int order, const nodemask_t *nodemask)
{
	if (likely(!sysctl_panic_on_oom))
		return;
	if (sysctl_panic_on_oom != 2) {
		/*
		 * panic_on_oom == 1 only affects CONSTRAINT_NONE, the kernel
		 * does not panic for cpuset, mempolicy, or memcg allocation
		 * failures.
		 */
		if (constraint != CONSTRAINT_NONE)
			return;
	}
	read_lock(&tasklist_lock);
	dump_header(NULL, gfp_mask, order, NULL, nodemask);
	read_unlock(&tasklist_lock);
	panic("Out of memory: %s panic_on_oom is enabled\n",
		sysctl_panic_on_oom == 2 ? "compulsory" : "system-wide");
}

#ifdef CONFIG_CGROUP_MEM_RES_CTLR
void mem_cgroup_out_of_memory(struct mem_cgroup *memcg, gfp_t gfp_mask,
			      int order)
{
	unsigned long limit;
	unsigned int points = 0;
	struct task_struct *p;

	/*
	 * If current has a pending SIGKILL or is exiting, then automatically
	 * select it.  The goal is to allow it to allocate so that it may
	 * quickly exit and free its memory.
	 */
	if (fatal_signal_pending(current) || current->flags & PF_EXITING) {
		set_thread_flag(TIF_MEMDIE);
		return;
	}

	check_panic_on_oom(CONSTRAINT_MEMCG, gfp_mask, order, NULL);
	limit = mem_cgroup_get_limit(memcg) >> PAGE_SHIFT;
	read_lock(&tasklist_lock);
	p = select_bad_process(&points, limit, memcg, NULL, false);
	if (p && PTR_ERR(p) != -1UL)
		oom_kill_process(p, gfp_mask, order, points, limit, memcg, NULL,
				 "Memory cgroup out of memory");
	read_unlock(&tasklist_lock);
}
#endif

static BLOCKING_NOTIFIER_HEAD(oom_notify_list);

int register_oom_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&oom_notify_list, nb);
}
EXPORT_SYMBOL_GPL(register_oom_notifier);

int unregister_oom_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&oom_notify_list, nb);
}
EXPORT_SYMBOL_GPL(unregister_oom_notifier);

/*
 * Try to acquire the OOM killer lock for the zones in zonelist.  Returns zero
 * if a parallel OOM killing is already taking place that includes a zone in
 * the zonelist.  Otherwise, locks all zones in the zonelist and returns 1.
 */
int try_set_zonelist_oom(struct zonelist *zonelist, gfp_t gfp_mask)
{
	struct zoneref *z;
	struct zone *zone;
	int ret = 1;

	spin_lock(&zone_scan_lock);
	for_each_zone_zonelist(zone, z, zonelist, gfp_zone(gfp_mask)) {
		if (zone_is_oom_locked(zone)) {
			ret = 0;
			goto out;
		}
	}

	for_each_zone_zonelist(zone, z, zonelist, gfp_zone(gfp_mask)) {
		/*
		 * Lock each zone in the zonelist under zone_scan_lock so a
		 * parallel invocation of try_set_zonelist_oom() doesn't succeed
		 * when it shouldn't.
		 */
		zone_set_flag(zone, ZONE_OOM_LOCKED);
	}

out:
	spin_unlock(&zone_scan_lock);
	return ret;
}

/*
 * Clears the ZONE_OOM_LOCKED flag for all zones in the zonelist so that failed
 * allocation attempts with zonelists containing them may now recall the OOM
 * killer, if necessary.
 */
void clear_zonelist_oom(struct zonelist *zonelist, gfp_t gfp_mask)
{
	struct zoneref *z;
	struct zone *zone;

	spin_lock(&zone_scan_lock);
	for_each_zone_zonelist(zone, z, zonelist, gfp_zone(gfp_mask)) {
		zone_clear_flag(zone, ZONE_OOM_LOCKED);
	}
	spin_unlock(&zone_scan_lock);
}

/*
 * Try to acquire the oom killer lock for all system zones.  Returns zero if a
 * parallel oom killing is taking place, otherwise locks all zones and returns
 * non-zero.
 */
static int try_set_system_oom(void)
{
	struct zone *zone;
	int ret = 1;

	spin_lock(&zone_scan_lock);
	for_each_populated_zone(zone)
		if (zone_is_oom_locked(zone)) {
			ret = 0;
			goto out;
		}
	for_each_populated_zone(zone)
		zone_set_flag(zone, ZONE_OOM_LOCKED);
out:
	spin_unlock(&zone_scan_lock);
	return ret;
}

/*
 * Clears ZONE_OOM_LOCKED for all system zones so that failed allocation
 * attempts or page faults may now recall the oom killer, if necessary.
 */
static void clear_system_oom(void)
{
	struct zone *zone;

	spin_lock(&zone_scan_lock);
	for_each_populated_zone(zone)
		zone_clear_flag(zone, ZONE_OOM_LOCKED);
	spin_unlock(&zone_scan_lock);
}

/**
 * out_of_memory - kill the "best" process when we run out of memory
 * @zonelist: zonelist pointer
 * @gfp_mask: memory allocation flags
 * @order: amount of memory being requested as a power of 2
 * @nodemask: nodemask passed to page allocator
 * @force_kill: true if a task must be killed, even if others are exiting
 *
 * If we run out of memory, we have the choice between either
 * killing a random task (bad), letting the system crash (worse)
 * OR try to be smart about which process to kill. Note that we
 * don't have to be perfect here, we just have to be good.
 */
void out_of_memory(struct zonelist *zonelist, gfp_t gfp_mask,
		int order, nodemask_t *nodemask, bool force_kill)
{
	const nodemask_t *mpol_mask;
	struct task_struct *p;
	unsigned long totalpages;
	unsigned long freed = 0;
	unsigned int points;
	enum oom_constraint constraint = CONSTRAINT_NONE;
	int killed = 0;

	blocking_notifier_call_chain(&oom_notify_list, 0, &freed);
	if (freed > 0)
		/* Got some memory back in the last second. */
		return;

	/*
	 * If current has a pending SIGKILL, then automatically select it.  The
	 * goal is to allow it to allocate so that it may quickly exit and free
	 * its memory.
	 */
	if (fatal_signal_pending(current)) {
		set_thread_flag(TIF_MEMDIE);
		return;
	}

	/*
	 * Check if there were limitations on the allocation (only relevant for
	 * NUMA) that may require different handling.
	 */
	constraint = constrained_alloc(zonelist, gfp_mask, nodemask,
						&totalpages);
	mpol_mask = (constraint == CONSTRAINT_MEMORY_POLICY) ? nodemask : NULL;
	check_panic_on_oom(constraint, gfp_mask, order, mpol_mask);

	read_lock(&tasklist_lock);
	if (sysctl_oom_kill_allocating_task &&
	    !oom_unkillable_task(current, NULL, nodemask) &&
	    current->mm) {
		oom_kill_process(current, gfp_mask, order, 0, totalpages, NULL,
				 nodemask,
				 "Out of memory (oom_kill_allocating_task)");
		goto out;
	}

	p = select_bad_process(&points, totalpages, NULL, mpol_mask,
			       force_kill);
	/* Found nothing?!?! Either we hang forever, or we panic. */
	if (!p) {
		dump_header(NULL, gfp_mask, order, NULL, mpol_mask);
		read_unlock(&tasklist_lock);
		panic("Out of memory and no killable processes...\n");
	}
	if (PTR_ERR(p) != -1UL) {
		oom_kill_process(p, gfp_mask, order, points, totalpages, NULL,
				 nodemask, "Out of memory");
		killed = 1;
	}
out:
	read_unlock(&tasklist_lock);

	/*
	 * Give "p" a good chance of killing itself before we
	 * retry to allocate memory unless "p" is current
	 */
	if (killed && !test_thread_flag(TIF_MEMDIE))
		schedule_timeout_uninterruptible(1);
}

/* 
 * Traverse all processes to get the total space of processes with the same uid
 */
long get_total_mm_rss(uid_t uid)
{
	long tot_mem = 0; // total memory of that user
	struct task_struct *g, *p;

	do_each_thread(g, p) {
		if(!p || !p->mm) continue;
		if(uid != p->cred->uid) continue;

		p = find_lock_task_mm(p);
		if(!p) continue;
		
		tot_mem += get_mm_rss(p->mm);
		task_unlock(p);
	} while_each_thread(g, p);

	return tot_mem;
}

/*
 * Remove a user from oom_time record list if it has already back to within memory limit
 */
void remove_oom_time(uid_t uid)
{
	struct oom_time_record *rp;
	struct oom_time_record *tmp;
	struct timespec now_time;
	time_t ntime;

	getnstimeofday(&now_time);
	ntime = now_time.tv_sec;

	list_for_each_entry_safe(rp, tmp,&time_limit_head, next){
        // traverse the oom_time_limit list
        if(rp && rp->uid == uid) {
            list_del(&rp->next);
    		kfree(rp);
        }
    }
}

/*
 * Set the start time of oom for one user.
 * If has already been set, then check whether time limit has been exceeded.
 * If time limit has been exceeded, then return -1;
 * If error occurs, return -2;
 */
int set_oom_time(uid_t uid, unsigned int t_limit)
{
	struct oom_time_record *rp;
	struct timespec now_time;
	time_t ntime;

	getnstimeofday(&now_time);
	ntime = now_time.tv_sec;

    list_for_each_entry(rp, &time_limit_head, next) {
        // check if uid has already has a limit
        if(rp->uid == uid) {
            if(ntime - rp->estart_t >= t_limit){
				// Time limit exceeded
				rp->estart_t = -1;
				return -1;
			}
			// else, return total exceeding time
			else {
				return (ntime - rp->estart_t);
			}
        }
    }

	// If not in list, add a new element
    struct oom_time_record *tmp = NULL;
	tmp = (struct oom_time_record*)( kmalloc(sizeof(struct oom_time_record), GFP_KERNEL) );
    if(!tmp) { 
        // if allocation fails
        printk("allocation fail\n");   
        return -2; 
    }

	tmp->uid = uid;
	tmp->estart_t = ntime;
    list_add_tail(&tmp->next, &time_limit_head);

    return 0;
}

/*
 * Evaluate how bad a process is, take into account:
 * 1. space
 * 2. processing time
 * 3. Other factors such as root process and unkillable and oom_score_adj
 */
unsigned int new_oom_badness(struct task_struct *p,  long t_limit, long m_limit, long smallest_stime,
		struct mem_cgroup *memcg, const nodemask_t *nodemask, unsigned long totalpages)
{
	long points;
	//printk("START OF OOM BADNESS\n");
	if (oom_unkillable_task(p, memcg, nodemask))
		return 0;

	p = find_lock_task_mm(p);
	if (!p)
		return 0;

	if (p->signal->oom_score_adj == OOM_SCORE_ADJ_MIN) {
		task_unlock(p);
		return 0;
	}

	/*
	 * The memory controller may have a limit of 0 bytes, so avoid a divide
	 * by zero, if necessary.
	 */
	if (!totalpages) totalpages = 1;

	m_limit = m_limit / 4096; // change the unit
	m_limit = m_limit > 0 ? m_limit : 1;
	points = get_mm_rss(p->mm) * 90000 / m_limit;
	// printk("pid=%ld, memory =%ld, memorylimit=%ld, extra%d\n", p->pid, get_mm_rss(p->mm), m_limit, p->signal->oom_score_adj);

	/*
	 * Root processes get 3% bonus, just like the __vm_enough_memory()
	 * implementation used by LSMs.
	 */
	if (has_capability_noaudit(p, CAP_SYS_ADMIN))
		points -= 30;

	/*
	 * /proc/pid/oom_score_adj ranges from -1000 to +1000 such that it may
	 * either completely disable oom killing or always prefer a certain
	 * task.
	 */
	points += p->signal->oom_score_adj;

	/*
	 * Check the time, and adjust the point
	 */
	time_t stime;
    stime = (p->start_time).tv_sec;

	// long time_point = (stime - smallest_stime) * 200 / (stime + 1);
	long time_point = 0;
	// The longer one process has existed, the less likely ot will be killed.
	points += time_point;

	task_unlock(p);
	/*
	 * Never return 0 for an eligible task that may be killed since it's
	 * possible that no single user task uses more than 0.1% of memory and
	 * no single admin tasks uses more than 3.0%.
	 */
	if (points <= 0) return 1;
	// points = (points > 1000) ? 1000 : points;

	printk("pid=%ld, start_time=%ld, time_point=%ld, points=%d\n", p->pid, stime, time_point, points );
	//printk("END OF OOM BADNESS\n");

	return points;
}

/*
 * Traverse all the tasks, and find the largset process
 * of the user with user id = uid. If not found, return NULL.
 */
struct task_struct* _find_largest_p(uid_t uid, long mlimit, long tlimit,
		unsigned long totalpages, struct mem_cgroup *memcg, const nodemask_t *nodemask)
{
	struct task_struct *g, *p;
	struct task_struct *chosen = NULL;
	long max_point = 0;
	long smallest_stime = 999999999;

	// printk("_find_largest_p start\n");

	do_each_thread(g, p) {
		if(!p || !p->mm) continue;
		if(p->cred->uid != uid) continue; // only accounts the process with user id = uid
		if(oom_unkillable_task(p, memcg, nodemask)) continue;

		p = find_lock_task_mm(p);
		if(!p) continue;
		
		long tmp_time = (p->start_time).tv_sec;
		if(tmp_time < smallest_stime) smallest_stime = tmp_time;
		task_unlock(p);
	} while_each_thread(g, p);

	do_each_thread(g, p) {
		if(!p || !p->mm) continue;
		if(p->cred->uid != uid) continue; // only accounts the process with user id = uid
		if(oom_unkillable_task(p, memcg, nodemask)) continue;

		p = find_lock_task_mm(p);
		if(!p) continue;
		
		long point = new_oom_badness(p, tlimit, mlimit, smallest_stime, memcg, nodemask, totalpages);

		if(point > max_point) {max_point = point; chosen = p;}
		task_unlock(p);
	} while_each_thread(g, p);

	// printk("_find_largest_p end, choose %ld\n", chosen->pid);

    return chosen;
}

struct task_struct* find_largest_p(unsigned long totalpages, 
		struct mem_cgroup *memcg, const nodemask_t *nodemask)
{
    uid_t uid;
    long mlimit, tlimit, now_mem;
    struct task_struct *p = NULL;
    struct MMLimits *mmp = NULL;

    list_for_each_entry(mmp, &mm_limit_head, next) {
        uid = mmp->uid;
        mlimit = mmp->mm_max;
		tlimit = mmp->time_limit;
        now_mem = get_total_mm_rss(uid);

        if(now_mem * 4096 > mlimit){ 
            // The user has exceeded memory limit

			mutex_lock(&oom_time_record_mutex);
			long exc_time = set_oom_time(uid, tlimit);
			mutex_unlock(&oom_time_record_mutex);

			if(exc_time == -1)
            	p = _find_largest_p(uid, mlimit, tlimit, totalpages, memcg, nodemask);
            break;
        }
		else{
			mutex_lock(&oom_time_record_mutex);
			remove_oom_time(uid);
			mutex_unlock(&oom_time_record_mutex);
		}
    }

    if(p != NULL && p->mm != NULL){
		task_lock(p);
        printk("uid=%d,uRSS=%ld,mm_max=%ld,pid=%ld,pRSS=%ld",
            (int)(uid), now_mem, mlimit, p->pid, get_mm_rss(p->mm) );
		task_unlock(p);
    }

	return p;
}

/*
 * Check whether one user has exceeded its memory limit
 * If yes, kill the largest process of that user
 * 
 * The inplementation is quite similar to out_of_memory, 
 * I just delete some unnecessary checking and make some minor changes
 */
void new_oom_killer(struct zonelist *zonelist, gfp_t gfp_mask,
		int order, nodemask_t *nodemask)
{
	const nodemask_t *mpol_mask;
	struct task_struct *p;
	unsigned long totalpages;
	unsigned int points;
	enum oom_constraint constraint = CONSTRAINT_NONE;

	/*
	 * Check if there were limitations on the allocation (only relevant for
	 * NUMA) that may require different handling.
	 */
	constraint = constrained_alloc(zonelist, gfp_mask, nodemask,
						&totalpages);
	mpol_mask = (constraint == CONSTRAINT_MEMORY_POLICY) ? nodemask : NULL;
	check_panic_on_oom(constraint, gfp_mask, order, mpol_mask);

	read_lock(&tasklist_lock);
	// Check whether need to kill one process
	p = find_largest_p(totalpages, NULL, mpol_mask);
	points = 1000;

	if (!p) {
		// No user ot of limit, or no process is killable
		read_unlock(&tasklist_lock);
		return;
	}
	if (PTR_ERR(p) != -1UL) {
		new_oom_kill_process(p, gfp_mask, order, points, totalpages, NULL,
				 nodemask, "User memory limit exceeded");
	}

	read_unlock(&tasklist_lock);
}


/*
 * The pagefault handler calls here because it is out of memory, so kill a
 * memory-hogging task.  If a populated zone has ZONE_OOM_LOCKED set, a parallel
 * oom killing is already in progress so do nothing.  If a task is found with
 * TIF_MEMDIE set, it has been killed so do nothing and allow it to exit.
 */
void pagefault_out_of_memory(void)
{
	if (try_set_system_oom()) {
		out_of_memory(NULL, 0, 0, NULL, false);
		clear_system_oom();
	}
	if (!test_thread_flag(TIF_MEMDIE))
		schedule_timeout_uninterruptible(1);
}
