
int sys_set_mm_limit(uid_t uid, unsigned long mm_max, long time_allow_exceed) ;

LIST_HEAD(mm_limit_head);

struct MMLimits {
    uid_t uid; 				        // user id
    long mm_max;			        // the memory limit
	long time_limit;		// how long it can exceed its memory limit
    struct list_head next;	        // point to next element
};

/*
 * This is the newly added system call.
 * Add memory limit to users
 */
int sys_set_mm_limit(uid_t uid, unsigned long mm_max, long time_allow_exceed) // newly added
{
    struct MMLimits *mmp;
    int flag = 0;

	mutex_lock(&init_mutex);
    list_for_each_entry(mmp, &mm_limit_head, next) {
        // check if uid has already has a limit
        if(mmp->uid == uid) {
            mmp->mm_max = mm_max;
            mmp->time_limit = time_allow_exceed;
            flag = 1;
            break;
        }
    }

    if(flag == 0){
        // if uid has no limit before, add a new one
		struct MMLimits *tmp = NULL;
		tmp = (struct MMLimits*)( kmalloc(sizeof(struct MMLimits), GFP_KERNEL) );
        if(!tmp) {
            // if allocation fails
            printk("allocation fail\n");
            mutex_unlock(&init_mutex);
            return 1;
        }

		tmp->uid = uid;
		tmp->mm_max = mm_max;
        tmp->time_limit = time_allow_exceed;

        list_add_tail(&tmp->next, &mm_limit_head);
    }

    list_for_each_entry(mmp, &mm_limit_head, next) {
        printk("uid=%d, mm_max=%ld, mm_time_limit=%ld\n", mmp->uid, mmp->mm_max, mmp->time_limit);
    }
	mutex_unlock(&init_mutex);

    return 0;
}
