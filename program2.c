#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/wait.h>

MODULE_LICENSE("GPL");

//*******************************************
static struct task_struct *PROCESS;

// SOURCE:kernel/fork.c, line 2498 (as a function)
extern pid_t kernel_thread(int (*fn)(void *), void *arg, unsigned long flags);

// SOURCE:fs/namei.c, line 213 (as a function)
extern struct filename *getname_kernel(const char *filename);

// SOURCE:fs/exec.c, line 1977 (as a function)
extern int do_execve(struct filename *filename,
		     const char __user *const __user *__argv,
		     const char __user *const __user *__envp);

// SOURCE:kernel/exit.c, line 712 (as a function)
extern void __noreturn do_exit(long code);

// SOURCE:kernel/exit.c, line 929 (as a struct)
static struct wait_opts {
	enum pid_type wo_type;
	int wo_flags;
	struct pid *wo_pid;

	struct waitid_info *wo_info;
	int wo_stat;
	struct rusage *wo_rusage;

	wait_queue_entry_t child_wait;
	int notask_error;
};

// kernel/exit.c, line 1426 (as a function)
extern long do_wait(struct wait_opts *wo);
//*******************************************

// Function as a dictionary to look the name of the signal
const char *LinuxSingal(int i)
{
	if (i == 1) {
		char *Singal = "SIGHUP";
		return Singal;
	} else if (i == 2) {
		char *Singal = "SIGINT";
		return Singal;
	} else if (i == 3) {
		char *Singal = "SIGQUIT";
		return Singal;
	} else if (i == 4) {
		char *Singal = "SIGILL";
		return Singal;
	} else if (i == 5) {
		char *Singal = "SIGTRAP";
		return Singal;
	} else if (i == 6) {
		char *Singal = "SIGABRT";
		return Singal;
	} else if (i == 7) {
		char *Singal = "SIGBUS";
		return Singal;
	} else if (i == 8) {
		char *Singal = "SIGFPE";
		return Singal;
	} else if (i == 9) {
		char *Singal = "SIGKILL";
		return Singal;
	} else if (i == 11) {
		char *Singal = "SIGSEGV";
		return Singal;
	} else if (i == 13) {
		char *Singal = "SIGPIPE";
		return Singal;
	} else if (i == 14) {
		char *Singal = "SIGALRM";
		return Singal;
	} else if (i == 15) {
		char *Singal = "SIGTERM";
		return Singal;
	} else if (i == 16) {
		char *Singal = "SIGSTKFLT";
		return Singal;
	} else if (i == 17) {
		char *Singal = "SIGCHLD";
		return Singal;
	} else if (i == 18) {
		char *Singal = "SIGCONT";
		return Singal;
	} else if (i == 19) {
		char *Singal = "SIGSTOP";
		return Singal;
	}
	return "";
}

// EXECUTE PART
int my_execute(void *argc)
{
	// Absolute path is required
	struct filename *my_file;
	my_file = getname_kernel("/tmp/test");

	// When status=0, the function do_execve run successfully
	int STATUS;
	STATUS = do_execve(my_file, NULL, NULL);

	if (!STATUS) {
		return 0;
	}

	do_exit(STATUS);
}

// FOR WAIT PART(Quoted from Tutorial2's PPT）
void my_wait(pid_t pid)
{
	int status;
	struct wait_opts wo;
	struct pid *wo_pid = NULL;
	enum pid_type type;
	type = PIDTYPE_PID;
	// Look up a PID from hash table and return with it’s count evaluated.
	wo_pid = find_get_pid(pid);

	wo.wo_type = type;
	wo.wo_pid = wo_pid;
	wo.wo_flags = WEXITED | WUNTRACED;
	wo.wo_info = NULL;
	wo.wo_stat = status; // In the new version wo.wo_stat is an integer
	wo.wo_rusage = NULL;

	int a;
	a = do_wait(
		&wo); // For the code above I quoted and modified from Tutorial2's PPT

	int Signal;
	//Equivalent to clearing bit7 (the highest bit) without affecting the other lower 7 bit
	Signal =
		wo.wo_stat &
		0x7f; //This calculation only holds when WIFSIGNALED(STATUS) and normal termination
	/* If WIFSIGNALED(STATUS), the terminating signal.  */
	/*#define __WTERMSIG(status) ((status) & 0x7f)      */
	/* Nonzero if STATUS indicates normal termination.  */
	/*#define __WIFEXITED(status) (__WTERMSIG(status) == 0)       */
	/* If WIFSTOPPED(STATUS), the signal that stopped the child.  */
	/*#define __WSTOPSIG(status) __WEXITSTATUS(status)            */
	if (Signal == 127) {
		Signal = 19;
	}

	// output child process exit status

	// take normal.c into consideration
	if (Signal == 0) {
		printk("[program2] : normal termination ");
	} else {
		printk("[program2] : get %s signal\n", LinuxSingal(Signal));
	}

	printk("[program2] : child process terminated\n");
	printk("[program2] : The return signal is %d\n", Signal);

	// Decrease the count and free memory
	put_pid(wo_pid);
	return;
}

// For fork part
int my_fork(void *argc)
{
	// set default sigaction for current process
	int i;
	struct k_sigaction *k_action = &current->sighand->action[0];
	for (i = 0; i < _NSIG; i++) {
		k_action->sa.sa_handler = SIG_DFL;
		k_action->sa.sa_flags = 0;
		k_action->sa.sa_restorer = NULL;
		sigemptyset(&k_action->sa.sa_mask);
		k_action++;
	}

	// fork a process using kernel_thread
	pid_t pid;
	// flag = 17
	/* execute a test program in child process */
	pid = kernel_thread(&my_execute, NULL, 17);

	printk("[program2] : The child process has pid = %d\n", pid);
	printk("[program2] : This is the parent process, pid = %d\n",
	       current->pid);

	/* wait until child process terminates */
	printk("[program2] : child process");
	my_wait(pid);

	return 0;
}

static int __init program2_init(void)
{
	/* write your code here */
	printk("[program2] : module_init {Zekai Chen} {120090539}\n");
	printk("[program2] : module_init create kthread start\n");

	/* create a kernel thread to run my_fork */
	PROCESS = kthread_create(&my_fork, NULL, "My_Thread");

	/* To wake up a new thread if it is OK(Quoted from Tutorial2's PPT）*/
	if (!IS_ERR(PROCESS)) {
		printk("[program2] : module_init kthread start\n");
		wake_up_process(PROCESS);
	} else {
		printk("[program2] : ERR_PTR in starting kernel thread.\n");
	}

	return 0;
}

static void __exit program2_exit(void)
{
	printk("[program2] : Module_exit\n");
}

module_init(program2_init);
module_exit(program2_exit);