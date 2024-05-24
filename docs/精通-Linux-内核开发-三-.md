# 精通 Linux 内核开发（三）

> 原文：[`zh.annas-archive.org/md5/B50238228DC7DE75D9C3CCE2886AAED2`](https://zh.annas-archive.org/md5/B50238228DC7DE75D9C3CCE2886AAED2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：进程间通信

复杂的应用程序编程模型可能包括许多进程，每个进程都实现为处理特定的工作，这些工作共同为应用程序的最终功能做出贡献。根据目标、设计和应用程序所托管的环境，所涉及的进程可能是相关的（父子、兄弟）或无关的。通常，这些进程需要各种资源来进行通信、共享数据并同步它们的执行以实现期望的结果。这些资源由操作系统的内核作为称为**进程间通信**（**IPC**）的服务提供。我们已经讨论了信号作为 IPC 机制的使用；在本章中，我们将开始探索各种其他可用于进程通信和数据共享的资源。

在本章中，我们将涵盖以下主题：

+   管道和 FIFO 作为消息资源

+   SysV IPC 资源

+   POSX IPC 机制

# 管道和 FIFO

管道形成了进程之间基本的单向、自同步的通信方式。顾名思义，它们有两端：一个进程写入数据，另一个进程从另一端读取数据。在这种设置中，首先输入的数据将首先被读取。由于管道的有限容量，管道本身会导致通信同步：如果写入进程写入速度比读取进程读取速度快得多，管道的容量将无法容纳多余的数据，并且不可避免地阻塞写入进程，直到读取者读取并释放数据。同样，如果读取者读取数据的速度比写入者快，它将没有数据可供读取，因此会被阻塞，直到数据变得可用。

管道可以用作通信的消息资源，用于相关进程之间和无关进程之间的通信。当应用于相关进程之间时，管道被称为**未命名管道**，因为它们不被列为`rootfs`树下的文件。未命名管道可以通过`pipe()`API 分配。

```
int pipe2(int pipefd[2], int flags);
```

API 调用相应的系统调用，分配适当的数据结构并设置管道缓冲区。它映射一对文件描述符，一个用于在管道缓冲区上读取，另一个用于在管道缓冲区上写入。这些描述符将返回给调用者。调用者进程通常会 fork 子进程，子进程会继承可以用于消息传递的管道文件描述符。

以下代码摘录显示了管道系统调用的实现：

```
SYSCALL_DEFINE2(pipe2, int __user *, fildes, int, flags)
{
        struct file *files[2];
        int fd[2];
        int error;

        error = __do_pipe_flags(fd, files, flags);
        if (!error) {
                if (unlikely(copy_to_user(fildes, fd, sizeof(fd)))) {
                        fput(files[0]);
                        fput(files[1]);
                        put_unused_fd(fd[0]);
                        put_unused_fd(fd[1]);
                        error = -EFAULT;
                 } else {
                        fd_install(fd[0], files[0]);
                        fd_install(fd[1], files[1]);
                }
           }
           return error;
}
```

无关进程之间的通信需要将管道文件列入**rootfs**。这种管道通常被称为**命名管道**，可以通过命令行（`mkfifo`）或使用`mkfifo` API 的进程创建。

```
int mkfifo(const char *pathname, mode_t mode);
```

命名管道是使用指定的名称和适当的权限创建的，如模式参数所指定的那样。调用`mknod`系统调用来创建 FIFO，它在内部调用 VFS 例程来设置命名管道。具有访问权限的进程可以通过常见的 VFS 文件 API `open`、`read`、`write`和`close`在 FIFO 上启动操作。

# pipefs

管道和 FIFO 由一个名为`pipefs`的特殊文件系统创建和管理。它在 VFS 中注册为特殊文件系统。以下是来自`fs/pipe.c`的代码摘录：

```
static struct file_system_type pipe_fs_type = {
           .name = "pipefs",
           .mount = pipefs_mount,
           .kill_sb = kill_anon_super,
};

static int __init init_pipe_fs(void)
{
        int err = register_filesystem(&pipe_fs_type);

        if (!err) {
                pipe_mnt = kern_mount(&pipe_fs_type);
                if (IS_ERR(pipe_mnt)) {
                        err = PTR_ERR(pipe_mnt);
                        unregister_filesystem(&pipe_fs_type);
                }
      }
      return err;
}

fs_initcall(init_pipe_fs);
```

它通过列举代表每个管道的`inode`实例将管道文件集成到 VFS 中；这允许应用程序使用常见的文件 API `read`和`write`。`inode`结构包含了一组指针，这些指针与管道和设备文件等特殊文件相关。对于管道文件`inodes`，其中一个指针`i_pipe`被初始化为`pipefs`，定义为`pipe_inode_info`类型的实例。

```
struct inode {
        umode_t        i_mode;
        unsigned short i_opflags;
        kuid_t         i_uid;
        kgid_t         i_gid;
        unsigned int   i_flags;
        ...
        ...
        ...
         union {
                 struct pipe_inode_info *i_pipe;
                 struct block_device *i_bdev;
                 struct cdev *i_cdev;
                 char *i_link;
                 unsigned i_dir_seq;
         };
        ...
        ...
        ...
};
```

`struct pipe_inode_info`包含由`pipefs`定义的所有与管道相关的元数据，包括管道缓冲区的信息和其他重要的管理数据。此结构在`<linux/pipe_fs_i.h>`中定义。

```
struct pipe_inode_info {
        struct mutex mutex;  
        wait_queue_head_t wait;  
        unsigned int nrbufs, curbuf, buffers;
        unsigned int readers;
        unsigned int writers;
        unsigned int files;
        unsigned int waiting_writers;
        unsigned int r_counter;
        unsigned int w_counter;
        struct page *tmp_page;
        struct fasync_struct *fasync_readers;
        struct fasync_struct *fasync_writers;
        struct pipe_buffer *bufs;
        struct user_struct *user;
};
```

`bufs`指针指向管道缓冲区；每个管道默认分配总缓冲区大小为 65,535 字节（64k），排列为 16 页的循环数组。用户进程可以通过管道描述符上的`fcntl()`操作改变管道缓冲区的总大小。管道缓冲区的默认最大限制为 1,048,576 字节，可以通过特权进程通过`/proc/sys/fs/pipe-max-size`文件接口进行更改。以下是一个总结表，描述了其他重要元素：

| **名称** | **描述** |
| --- | --- |
| `mutex` | 保护管道的排他锁 |
| `wait` | 读取者和写入者的等待队列 |
| `nrbufs` | 此管道的非空管道缓冲区计数 |
| `curbuf` | 当前管道缓冲区 |
| `buffers` | 缓冲区的总数 |
| `readers` | 当前读取者的数量 |
| `writers` | 当前写入者的数量 |
| `files` | 当前引用此管道的 struct 文件实例的数量 |
| `waiting_writers` | 当前在管道上阻塞的写入者数量 |
| `r_coutner` | 读取者计数器（FIFO 相关） |
| `w_counter` | 写入者计数器（FIFO 相关） |
| `*fasync_readers` | 读取者端的 fasync |
| `*fasync_writers` | 写入者端的 fasync |
| `*bufs` | 指向管道缓冲区的循环数组的指针 |
| `*user` | 指向表示创建此管道的用户的`user_struct`实例的指针 |

对管道缓冲区的每个页面的引用被封装到*类型*`struct pipe_buffer`的实例的循环数组中。此结构在`<linux/pipe_fs_i.h>`中定义。

```
struct pipe_buffer {
        struct page *page;    
        unsigned int offset, len;
        const struct pipe_buf_operations *ops;
        unsigned int flags;
        unsigned long private;
};
```

`*page`是指向页面缓冲区的页面描述符的指针，`offset`和`len`字段包含页面缓冲区中数据的偏移量和长度。`*ops`是指向`pipe_buf_operations`类型的结构的指针，它封装了`pipefs`实现的管道缓冲区操作。它还实现了绑定到管道和 FIFO 索引节点的文件操作：

```
const struct file_operations pipefifo_fops = {
         .open = fifo_open,
         .llseek = no_llseek,
         .read_iter = pipe_read,
         .write_iter = pipe_write,
         .poll = pipe_poll,
         .unlocked_ioctl = pipe_ioctl,
         .release = pipe_release,
         .fasync = pipe_fasync,
};
```

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00039.jpeg)

# 消息队列

**消息队列**是消息缓冲区的列表，通过它可以进行任意数量的进程通信。与管道不同，写入者无需等待读取者打开管道并监听数据。类似于邮箱，写入者可以将包含在缓冲区中的固定长度消息放入队列中，读取者可以在准备好时随时提取。消息队列在读取者提取后不保留消息包，这意味着每个消息包都是进程持久的。Linux 支持两种不同的消息队列实现：经典的 Unix SYSV 消息队列和当代的 POSIX 消息队列。

# System V 消息队列

这是经典的 AT&T 消息队列实现，适用于任意数量的不相关进程之间的消息传递。发送进程将每条消息封装成一个包，其中包含消息数据和消息编号。消息队列的实现不定义消息编号的含义，而是由应用程序设计者定义消息编号和程序读者和写者解释相同的适当含义。这种机制为程序员提供了灵活性，可以将消息编号用作消息 ID 或接收者 ID。它使读取进程能够选择性地读取与特定 ID 匹配的消息。但是，具有相同 ID 的消息始终按照 FIFO 顺序（先进先出）读取。

进程可以使用以下命令创建和打开 SysV 消息队列：

```
 int msgget(key_t key, int msgflg);
```

`key`参数是一个唯一的常数，用作魔术数字来标识消息队列。所有需要访问此消息队列的程序都需要使用相同的魔术数字；这个数字通常在编译时硬编码到相关进程中。但是，应用程序需要确保每个消息队列的键值是唯一的，并且有可通过其动态生成唯一键的替代库函数。

如果将唯一键和`msgflag`参数值设置为`IPC_CREATE`，将会建立一个新的消息队列。有权访问队列的有效进程可以使用`msgsnd`和`msgrcv`例程向队列中读取或写入消息（我们这里不会详细讨论它们；请参考 Linux 系统编程手册）：

```
int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg);

ssize_t msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp,
               int msgflg);
```

# 数据结构

每个消息队列都是通过底层 SysV IPC 子系统枚举一组数据结构来创建的。`struct msg_queue`是核心数据结构，每个消息队列都会枚举一个该结构的实例：

```

struct msg_queue {
        struct kern_ipc_perm q_perm;
        time_t q_stime; /* last msgsnd time */
        time_t q_rtime; /* last msgrcv time */
        time_t q_ctime; /* last change time */
        unsigned long q_cbytes; /* current number of bytes on queue */
        unsigned long q_qnum; /* number of messages in queue */
        unsigned long q_qbytes; /* max number of bytes on queue */
        pid_t q_lspid; /* pid of last msgsnd */
        pid_t q_lrpid; /* last receive pid */

       struct list_head q_messages; /* message list */
       struct list_head q_receivers;/* reader process list */
       struct list_head q_senders;  /*writer process list */
};
```

`q_messages`字段表示双向循环链表的头节点，该链表包含当前队列中的所有消息。每条消息以标头开头，后跟消息数据；每条消息可以根据消息数据的长度占用一个或多个页面。消息标头始终位于第一页的开头，并由`struct msg_msg`的一个实例表示：

```
/* one msg_msg structure for each message */
struct msg_msg {
        struct list_head m_list;
        long m_type;
        size_t m_ts; /* message text size */
        struct msg_msgseg *next;
        void *security;
       /* the actual message follows immediately */
};
```

`m_list`字段包含队列中前一条和后一条消息的指针。`*next`指针指向`struct msg_msgseg`的一个实例，该实例包含消息数据的下一页的地址。当消息数据超过第一页时，此指针才相关。第二页框架以`msg_msgseg`描述符开头，该描述符进一步包含指向后续页面的指针，这种顺序一直持续到消息数据的最后一页：

```
struct msg_msgseg {
        struct msg_msgseg *next;
        /* the next part of the message follows immediately */
};
```

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00040.jpeg)

# POSIX 消息队列

POSIX 消息队列实现了按优先级排序的消息。发送进程写入的每条消息都与一个整数相关联，该整数被解释为消息优先级；数字越大的消息被认为优先级越高。消息队列按优先级对当前消息进行排序，并按降序（优先级最高的先）将它们传递给读取进程。该实现还支持更广泛的 API 接口，包括有界等待发送和接收操作，以及通过信号或线程进行异步消息到达通知的接收者。

该实现提供了一个独特的 API 接口来创建、打开、读取、写入和销毁消息队列。以下是 API 的摘要描述（我们这里不会讨论使用语义，请参考系统编程手册了解更多细节）：

| **API 接口** | **描述** |
| --- | --- |
| `mq_open()` | 创建或打开一个 POSIX 消息队列 |
| `mq_send()` | 将消息写入队列 |
| `mq_timedsend()` | 类似于`mq_send`，但具有用于有界操作的超时参数 |
| `mq_receive()` | 从队列中获取消息；这个操作可以在无界阻塞调用上执行 |
| `mq_timedreceive()` | 类似于`mq_receive()`，但具有限制可能阻塞一段时间的超时参数 |
| `mq_close()` | 关闭消息队列 |
| `mq_unlink()` | 销毁消息队列 |
| `mq_notify()` | 自定义和设置消息到达通知 |
| `mq_getattr()` | 获取与消息队列关联的属性 |
| `mq_setattr()` | 设置消息队列上指定的属性 |

POSIX 消息队列由一个名为`mqueue`的特殊文件系统管理。每个消息队列都由文件名标识。每个队列的元数据由`mqueue_inode_info`结构的一个实例描述，该结构表示与`mqueue`文件系统中消息队列文件关联的 inode 对象：

```
struct mqueue_inode_info {
        spinlock_t lock;
        struct inode vfs_inode;
        wait_queue_head_t wait_q;

        struct rb_root msg_tree;
        struct posix_msg_tree_node *node_cache;
        struct mq_attr attr;

        struct sigevent notify;
        struct pid *notify_owner;
        struct user_namespace *notify_user_ns;
        struct user_struct *user; /* user who created, for accounting */
        struct sock *notify_sock;
        struct sk_buff *notify_cookie;

        /* for tasks waiting for free space and messages, respectively */
        struct ext_wait_queue e_wait_q[2];

        unsigned long qsize; /* size of queue in memory (sum of all msgs) */
};
```

`*node_cache`指针指向包含消息节点链表头的`posix_msg_tree_node`描述符，其中每条消息由`msg_msg`类型的描述符表示：

```

 struct posix_msg_tree_node {
         struct rb_node rb_node;
         struct list_head msg_list;
         int priority;
};
```

# 共享内存

与提供进程持久消息基础设施的消息队列不同，IPC 的共享内存服务提供了可以被任意数量的共享相同数据的进程附加的内核持久内存。共享内存基础设施提供了用于分配、附加、分离和销毁共享内存区域的操作接口。需要访问共享数据的进程将共享内存区域*附加*或*映射*到其地址空间中；然后它可以通过映射例程返回的地址访问共享内存中的数据。这使得共享内存成为 IPC 的最快手段之一，因为从进程的角度来看，它类似于访问本地内存，不涉及切换到内核模式。

# System V 共享内存

Linux 支持 IPC 子系统下的传统 SysV 共享内存实现。与 SysV 消息队列类似，每个共享内存区域都由唯一的 IPC 标识符标识。

# 操作接口

内核为启动共享内存操作提供了不同的系统调用接口，如下所示：

# 分配共享内存

进程通过调用`shmget()`系统调用来获取共享内存区域的 IPC 标识符；如果该区域不存在，则创建一个：

```
int shmget(key_t key, size_t size, int shmflg);
```

此函数返回与*key*参数中包含的值对应的共享内存段的标识符。如果其他进程打算使用现有段，它们可以在查找其标识符时使用段的*key*值。但是，如果*key*参数是唯一的或具有值`IPC_PRIVATE`，则会创建一个新段。`size`表示需要分配的字节数，因为段是分配为内存页面。要分配的页面数是通过将*size*值四舍五入到页面大小的最近倍数来获得的。

`shmflg`标志指定了如何创建段。它可以包含两个值：

+   `IPC_CREATE`：这表示创建一个新段。如果未使用此标志，则找到与键值关联的段，并且如果用户具有访问权限，则返回段的标识符。

+   `IPC_EXCL`：此标志始终与`IPC_CREAT`一起使用，以确保如果*key*值存在，则调用失败。

# 附加共享内存

共享内存区域必须附加到其地址空间，进程才能访问它。调用`shmat()`将共享内存附加到调用进程的地址空间：

```
void *shmat(int shmid, const void *shmaddr, int shmflg);
```

此函数附加了由`shmid`指示的段。`shmaddr`指定了一个指针，指示了段要映射到的进程地址空间中的位置。第三个参数`shmflg`是一个标志，可以是以下之一：

+   `SHM_RND`：当`shmaddr`不是 NULL 值时指定，表示函数将在地址处附加段，该地址由将`shmaddr`值四舍五入到页面大小的最近倍数计算得出；否则，用户必须确保`shmaddr`是页面对齐的，以便正确附加段。

+   `SHM_RDONLY`：这是指定如果用户具有必要的读权限，则段将仅被读取。否则，为段提供读写访问权限（进程必须具有相应的权限）。

+   `SHM_REMAP`：这是一个特定于 Linux 的标志，表示在由`shmaddr`指定的地址处的任何现有映射将被新映射替换。

# 分离共享内存

同样，要将共享内存从进程地址空间分离出来，会调用`shmdt()`。由于 IPC 共享内存区域在内核中是持久的，它们在进程分离后仍然存在：

```
int shmdt(const void *shmaddr);
```

由`shmaddr`指定的段从调用进程的地址空间中分离出来。

这些接口操作中的每一个都调用了`<ipc/shm.c>`源文件中实现的相关系统调用。

# 数据结构

每个共享内存段都由`struct shmid_kernel`描述符表示。该结构包含了与 SysV 共享内存管理相关的所有元数据：

```
struct shmid_kernel /* private to the kernel */
{
        struct kern_ipc_perm shm_perm;
        struct file *shm_file; /* pointer to shared memory file */
        unsigned long shm_nattch; /* no of attached process */
        unsigned long shm_segsz; /* index into the segment */
        time_t shm_atim; /* last access time */
        time_t shm_dtim; /* last detach time */
        time_t shm_ctim; /* last change time */
        pid_t shm_cprid; /* pid of creating process */
        pid_t shm_lprid; /* pid of last access */
        struct user_struct *mlock_user;

        /* The task created the shm object. NULL if the task is dead. */
        struct task_struct *shm_creator; 
        struct list_head shm_clist; /* list by creator */
};

```

为了可靠性和便于管理，内核的 IPC 子系统通过一个名为`shmfs`的特殊文件系统管理共享内存段。这个文件系统没有挂载到 rootfs 树上；它的操作只能通过 SysV 共享内存系统调用来访问。`*shm_file`指针指向`shmfs`的`struct file`对象，表示一个共享内存块。当一个进程启动附加操作时，底层系统调用会调用`do_mmap()`来在调用者的地址空间中创建相关映射（通过`struct vm_area_struct`），并进入`*shmfs-*`定义的`shm_mmap()`操作来映射相应的共享内存：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00041.jpeg)

# POSIX 共享内存

Linux 内核通过一个名为`tmpfs`的特殊文件系统支持 POSIX 共享内存，该文件系统挂载到`rootfs`的`/dev/shm`上。这种实现提供了一个与 Unix 文件模型一致的独特 API，导致每个共享内存分配都由唯一的文件名和 inode 表示。这个接口被应用程序员认为更加灵活，因为它允许使用标准的 POSIX 文件映射例程`mmap()`和`unmap()`将内存段附加到调用进程的地址空间和分离出来。

以下是接口例程的摘要描述：

| **API** | **描述** |
| --- | --- |
| `shm_open()` | 创建并打开由文件名标识的共享内存段 |
| `mmap()` | POSIX 标准文件映射接口，用于将共享内存附加到调用者的地址空间 |
| `sh_unlink()` | 销毁指定的共享内存块 |
| `unmap()` | 从调用者地址空间分离指定的共享内存映射 |

底层实现与 SysV 共享内存类似，不同之处在于映射实现由`tmpfs`文件系统处理。

尽管共享内存是共享常用数据或资源的最简单方式，但它将实现同步的负担转嫁给了进程，因为共享内存基础设施不提供任何数据或资源的同步或保护机制。应用程序设计者必须考虑在竞争进程之间同步共享内存访问，以确保共享数据的可靠性和有效性，例如，防止两个进程同时在同一区域进行可能的写操作，限制读取进程等待直到另一个进程完成写操作等。通常，为了同步这种竞争条件，还会使用另一种 IPC 资源，称为信号量。

# 信号量

**信号量**是 IPC 子系统提供的同步原语。它们为多线程环境中的进程提供了对共享数据结构或资源的并发访问的保护机制。在其核心，每个信号量由一个可以被调用进程原子访问的整数计数器组成。信号量实现提供了两种操作，一种用于等待信号量变量，另一种用于发出信号量变量。换句话说，等待信号量会将计数器减 1，发出信号量会将计数器加 1。通常，当一个进程想要访问一个共享资源时，它会尝试减少信号量计数器。然而，内核会处理这个尝试，因为它会阻塞尝试的进程，直到计数器产生一个正值。类似地，当一个进程放弃资源时，它会增加信号量计数器，这会唤醒正在等待资源的任何进程。

**信号量版本**

传统上所有的 `*nix` 系统都实现了 System V 信号量机制；然而，POSIX 有自己的信号量实现，旨在实现可移植性并解决 System V 版本存在的一些笨拙问题。让我们先来看看 System V 信号量。

# System V 信号量

在 System V 中，信号量不仅仅是一个单一的计数器，而是一组计数器。这意味着一个信号量集合可以包含单个或多个计数器（0 到 n）并具有相同的信号量 ID。集合中的每个计数器可以保护一个共享资源，而单个信号量集合可以保护多个资源。用于创建这种类型信号量的系统调用如下：

```
int semget(key_t key, int nsems, int semflg)
```

+   `key` 用于标识信号量。如果键值为 `IPC_PRIVATE`，则创建一个新的信号量集合。

+   `nsems` 表示需要在集合中的信号量数量

+   `semflg` 指示应该如何创建信号量。它可以包含两个值：

+   `IPC_CREATE:` 如果键不存在，则创建一个新的信号量

+   `IPC_EXCL:` 如果键存在，则抛出错误并失败

成功时，调用返回信号量集合标识符（一个正值）。

因此，创建的信号量包含未初始化的值，并需要使用 `semctl()` 函数进行初始化。初始化后，进程可以使用信号量集合：

```
int semop(int semid, struct sembuf *sops, unsigned nsops);
```

`Semop()` 函数允许进程对信号量集合进行操作。这个函数提供了一种独特的 SysV 信号量实现所特有的 **可撤销操作**，通过一个名为 `SEM_UNDO` 的特殊标志。当设置了这个标志时，内核允许在进程在完成相关的共享数据访问操作之前中止时，将信号量恢复到一致的状态。例如，考虑这样一种情况：其中一个进程锁定了信号量并开始对共享数据进行访问操作；在此期间，如果进程在完成共享数据访问之前中止，那么信号量将处于不一致的状态，使其对其他竞争进程不可用。然而，如果进程通过在 `semop()` 中设置 `SEM_UNDO` 标志来获取信号量的锁定，那么它的终止将允许内核将信号量恢复到一致的状态（解锁状态），使其对等待的其他竞争进程可用。

# 数据结构

每个 SysV 信号量集合在内核中由 `struct sem_array` 类型的描述符表示：

```
/* One sem_array data structure for each set of semaphores in the system. */
struct sem_array {
        struct kern_ipc_perm ____cacheline_aligned_in_smp sem_perm;                                                                           
        time_t sem_ctime;               /* last change time */
        struct sem *sem_base;           /*ptr to first semaphore in array */
        struct list_head pending_alter; /* pending operations */
                                        /* that alter the array */
        struct list_head pending_const; /* pending complex operations */
                                        /* that do not alter semvals */
        struct list_head list_id;       /* undo requests on this array */
        int sem_nsems;                  /* no. of semaphores in array */
        int complex_count;              /* pending complex operations */
        bool complex_mode;              /* no parallel simple ops */
   };

```

数组中的每个信号量都被列举为 `<ipc/sem.c>` 中定义的 `struct sem` 的实例；`*sem_base` 指针指向集合中的第一个信号量对象。每个信号量集合包含一个等待队列的挂起队列列表；`pending_alter` 是这个挂起队列的头节点，类型为 `struct sem_queue`。每个信号量集合还包含每个信号量可撤销的操作。`list_id` 是指向 `struct sem_undo` 实例列表的头节点；列表中每个信号量都有一个实例。以下图表总结了信号量集合数据结构及其列表：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00042.jpeg)

# POSIX 信号量

与 System V 相比，POSIX 信号量语义相对简单。每个信号量都是一个简单的计数器，永远不会小于零。实现提供了用于初始化、增加和减少操作的函数接口。它们可以通过在所有线程都可以访问的内存中分配信号量实例来用于同步线程。它们也可以通过将信号量放置在共享内存中来用于同步进程。Linux 对 POSIX 信号量的实现经过优化，以提供更好的性能，用于非竞争同步场景。

POSIX 信号量有两种变体：命名信号量和无名信号量。命名信号量由文件名标识，适用于不相关进程之间的使用。无名信号量只是`sem_t`类型的全局实例；一般情况下，这种形式更适合在线程之间使用。POSIX 信号量接口操作是 POSIX 线程库实现的一部分。

| **函数接口** | **描述** |
| --- | --- |
| `sem_open()` | 打开现有的命名信号量文件或创建一个新的命名信号量并返回其描述符 |
| `sem_init()` | 无名信号量的初始化程序 |
| `sem_post()` | 增加信号量的操作 |
| `sem_wait()` | 减少信号量的操作，如果在信号量值为零时调用，则会阻塞 |
| `sem_timedwait()` | 用有界等待的超时参数扩展`sem_wait()` |
| `sem_getvalue()` | 返回信号量计数器的当前值 |
| `sem_unlink()` | 通过文件标识符移除命名信号量 |

# 摘要

在本章中，我们涉及了内核提供的各种 IPC 机制。我们探讨了每种机制的各种数据结构的布局和关系，并且还研究了 SysV 和 POSIX IPC 机制。

在下一章中，我们将进一步讨论锁定和内核同步机制。


# 第七章：虚拟内存管理

在第一章中，我们简要讨论了一个重要的抽象概念，称为*进程*。我们已经讨论了进程虚拟地址空间及其隔离，并且已经深入了解了涉及物理内存管理的各种数据结构和算法。在本章中，让我们通过虚拟内存管理和页表的详细信息来扩展我们对内存管理的讨论。我们将研究虚拟内存子系统的以下方面：

+   进程虚拟地址空间及其段

+   内存描述符结构

+   内存映射和 VMA 对象

+   文件支持的内存映射

+   页缓存

+   使用页表进行地址转换

# 进程地址空间

以下图表描述了 Linux 系统中典型进程地址空间的布局，由一组虚拟内存段组成：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00043.jpeg)

每个段都被物理映射到一个或多个线性内存块（由一个或多个页面组成），并且适当的地址转换记录被放置在进程页表中。在我们深入了解内核如何管理内存映射和构建页表的完整细节之前，让我们简要了解一下地址空间的每个段：

+   **栈**是最顶部的段，向下扩展。它包含**栈帧**，用于保存局部变量和函数参数；在调用函数时，在栈顶创建一个新的帧，在当前函数返回时销毁。根据函数调用的嵌套级别，栈段始终需要动态扩展以容纳新的帧。这种扩展由虚拟内存管理器通过**页错误**处理：当进程尝试触及栈顶的未映射地址时，系统触发页错误，由内核处理以检查是否适合扩展栈。如果当前栈利用率在`RLIMIT_STACK`范围内，则认为适合扩展栈。然而，如果当前利用率已达到最大值，没有进一步扩展的空间，那么会向进程发送段错误信号。

+   **Mmap**是栈下面的一个段；这个段主要用于将文件数据从页缓存映射到进程地址空间。这个段也用于映射共享对象或动态库。用户模式进程可以通过`mmap()`API 启动新的映射。Linux 内核还支持通过这个段进行匿名内存映射，这是一种用于存储进程数据的动态内存分配的替代机制。

+   **堆**段提供了动态内存分配的地址空间，允许进程存储运行时数据。内核提供了`brk()`系列 API，通过它用户模式进程可以在运行时扩展或收缩堆。然而，大多数编程语言特定的标准库实现了堆管理算法，以有效利用堆内存。例如，GNU glibc 实现了堆管理，提供了`malloc()`系列函数进行分配。

地址空间的较低段--**BSS**、**Data**和**Text**--与进程的二进制映像相关：

+   **BSS**存储**未初始化**的静态变量，这些变量的值在程序代码中未初始化。BSS 是通过匿名内存映射设置的。

+   **数据**段包含在程序源代码中初始化的全局和静态变量。这个段通过映射包含初始化数据的程序二进制映像的部分来枚举；这种映射是以**私有内存映射**类型创建的，确保对数据变量内存的更改不会反映在磁盘文件上。

+   **文本**段也通过从内存映射程序二进制文件来枚举；这种映射的类型是`RDONLY`，试图写入此段将触发分段错误。

内核支持地址空间随机化功能，如果在构建过程中启用，允许 VM 子系统为每个新进程随机化**堆栈**、**mmap**和**堆**段的起始位置。这为进程提供了免受恶意程序注入故障的安全性。黑客程序通常使用固定的有效进程内存段的起始地址进行硬编码；通过地址空间随机化，这种恶意攻击将失败。然而，从应用程序的二进制文件枚举的文本段被映射到固定地址，根据底层架构的定义，这被配置到链接器脚本中，在构建程序二进制文件时应用。

# 进程内存描述符

内核在内存描述符结构中维护了有关进程内存段和相应翻译表的所有信息，该结构的类型为`struct mm_struct`。进程描述符结构`task_struct`包含指向进程内存描述符的指针`*mm`。我们将讨论内存描述符结构的一些重要元素：

```
struct mm_struct {
               struct vm_area_struct *mmap; /* list of VMAs */
               struct rb_root mm_rb;
               u32 vmacache_seqnum; /* per-thread vmacache */
#ifdef CONFIG_MMU
             unsigned long (*get_unmapped_area) (struct file *filp, unsigned long addr, unsigned long len,
                                                                                                    unsigned long pgoff, unsigned long flags);
 #endif
            unsigned long mmap_base;               /* base of mmap area */
            unsigned long mmap_legacy_base;  /* base of mmap area in bottom-up allocations */
            unsigned long task_size;                   /* size of task vm space */
            unsigned long highest_vm_end;      /* highest vma end address */
            pgd_t * pgd;  
            atomic_t mm_users;           /* How many users with user space? */
            atomic_t mm_count;           /* How many references to "struct mm_struct" (users count as 1) */
            atomic_long_t nr_ptes;      /* PTE page table pages */
 #if CONFIG_PGTABLE_LEVELS > 2
           atomic_long_t nr_pmds;      /* PMD page table pages */
 #endif
           int map_count;                           /* number of VMAs */
         spinlock_t page_table_lock;      /* Protects page tables and some counters */
         struct rw_semaphore mmap_sem;

       struct list_head mmlist;      /* List of maybe swapped mm's. These are globally strung
                                                         * together off init_mm.mmlist, and are protected
                                                         * by mmlist_lock
                                                         */
        unsigned long hiwater_rss;     /* High-watermark of RSS usage */
         unsigned long hiwater_vm;     /* High-water virtual memory usage */
        unsigned long total_vm;          /* Total pages mapped */
         unsigned long locked_vm;       /* Pages that have PG_mlocked set */
         unsigned long pinned_vm;      /* Refcount permanently increased */
         unsigned long data_vm;          /* VM_WRITE & ~VM_SHARED & ~VM_STACK */
        unsigned long exec_vm;          /* VM_EXEC & ~VM_WRITE & ~VM_STACK */
         unsigned long stack_vm;         /* VM_STACK */
         unsigned long def_flags;
         unsigned long start_code, end_code, start_data, end_data;
         unsigned long start_brk, brk, start_stack;
         unsigned long arg_start, arg_end, env_start, env_end;
        unsigned long saved_auxv[AT_VECTOR_SIZE];               /* for /proc/PID/auxv */
/*
 * Special counters, in some configurations protected by the
 * page_table_lock, in other configurations by being atomic.
 */
        struct mm_rss_stat rss_stat;
      struct linux_binfmt *binfmt;
      cpumask_var_t cpu_vm_mask_var;
 /* Architecture-specific MM context */
        mm_context_t context;
      unsigned long flags;                   /* Must use atomic bitops to access the bits */
      struct core_state *core_state;   /* core dumping support */
       ...
      ...
      ...
 };
```

`mmap_base`指的是虚拟地址空间中 mmap 段的起始位置，`task_size`包含虚拟内存空间中任务的总大小。`mm_users`是一个原子计数器，保存共享此内存描述符的 LWP 的计数，`mm_count`保存当前使用此描述符的进程数，并且 VM 子系统确保只有在`mm_count`为零时才释放内存描述符结构。`start_code`和`end_code`字段包含从程序的二进制文件映射的代码块的起始和结束虚拟地址。类似地，`start_data`和`end_data`标记了从程序的二进制文件映射的初始化数据区域的开始和结束。

`start_brk`和`brk`字段表示堆段的起始和当前结束地址；虽然`start_brk`在整个进程生命周期中保持不变，但`brk`在分配和释放堆内存时会重新定位。因此，在特定时刻活动堆的总大小是`start_brk`和`brk`字段之间内存的大小。元素`arg_start`和`arg_end`包含命令行参数列表的位置，`env_start`和`env_end`包含环境变量的起始和结束位置：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00044.jpeg)

在虚拟地址空间中映射到段的每个线性内存区域都通过类型为`struct vm_area_struct`的描述符表示。每个 VM 区域区域都映射有包含起始和结束虚拟地址以及其他属性的虚拟地址间隔。VM 子系统维护一个表示当前区域的`vm_area_struct(VMA)`节点的链表；此列表按升序排序，第一个节点表示起始虚拟地址间隔，后面的节点包含下一个地址间隔，依此类推。内存描述符结构包括一个指针`*mmap`，它指向当前映射的 VM 区域列表。

VM 子系统在执行对 VM 区域的各种操作时需要扫描`vm_area`列表，例如在映射地址间隔内查找特定地址，或附加表示新映射的新 VMA 实例。这样的操作可能耗时且低效，特别是对于大量区域映射到列表的情况。为了解决这个问题，VM 子系统维护了一个红黑树，用于高效访问`vm_area`对象。内存描述符结构包括红黑树的根节点`mm_rb`。通过这种安排，可以通过搜索红黑树来快速附加新的 VM 区域，而无需显式扫描链接列表。

`struct vm_area_struct` 在内核头文件`<linux/mm_types.h>`中定义：

```
/*
  * This struct defines a memory VMM memory area. There is one of these
  * per VM-area/task. A VM area is any part of the process virtual memory
  * space that has a special rule for the page-fault handlers (ie a shared
  * library, the executable area etc).
  */
 struct vm_area_struct {
               /* The first cache line has the info for VMA tree walking. */
              unsigned long vm_start; /* Our start address within vm_mm. */
               unsigned long vm_end; /* The first byte after our end address within vm_mm. */
              /* linked list of VM areas per task, sorted by address */
               struct vm_area_struct *vm_next, *vm_prev;
               struct rb_node vm_rb;
               /*
                 * Largest free memory gap in bytes to the left of this VMA.
                 * Either between this VMA and vma->vm_prev, or between one of the
                 * VMAs below us in the VMA rbtree and its ->vm_prev. This helps
                 * get_unmapped_area find a free area of the right size.
                */
                 unsigned long rb_subtree_gap;
              /* Second cache line starts here. */
               struct mm_struct   *vm_mm; /* The address space we belong to. */
                pgprot_t  vm_page_prot;       /* Access permissions of this VMA. */
                unsigned long vm_flags;        /* Flags, see mm.h. */
              /*
                 * For areas with an address space and backing store,
                 * linkage into the address_space->i_mmap interval tree.
                 */
                struct {
                              struct rb_node rb;
                              unsigned long rb_subtree_last;
                           } shared;
         /*
                 * A file's MAP_PRIVATE vma can be in both i_mmap tree and anon_vma
                 * list, after a COW of one of the file pages. A MAP_SHARED vma
                 * can only be in the i_mmap tree. An anonymous MAP_PRIVATE, stack
                 * or brk vma (with NULL file) can only be in an anon_vma list.
          */
            struct list_head anon_vma_chain; /* Serialized by mmap_sem & page_table_lock */
           struct anon_vma *anon_vma;        /* Serialized by page_table_lock */
            /* Function pointers to deal with this struct. */
            const struct vm_operations_struct *vm_ops;
            /* Information about our backing store: */
            unsigned long vm_pgoff; /* Offset (within vm_file) in PAGE_SIZE units */
            struct file * vm_file; /* File we map to (can be NULL). */
            void * vm_private_data; /* was vm_pte (shared mem) */
#ifndef CONFIG_MMU
          struct vm_region *vm_region; /* NOMMU mapping region */
 #endif
 #ifdef CONFIG_NUMA
         struct mempolicy *vm_policy; /* NUMA policy for the VMA */
 #endif
        struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
 };
```

`vm_start` 包含区域的起始虚拟地址（较低地址），即映射的第一个有效字节的地址，`vm_end` 包含映射区域之外的第一个字节的虚拟地址（较高地址）。因此，可以通过从`vm_start`减去`vm_end`来计算映射内存区域的长度。指针`*vm_next` 和 `*vm_prev` 指向下一个和上一个 VMA 列表，而`vm_rb` 元素用于表示红黑树下的这个 VMA。指针`*vm_mm` 指回进程内存描述符结构。

`vm_page_prot` 包含区域中页面的访问权限。`vm_flags` 是一个位字段，包含映射区域内存的属性。标志位在内核头文件`<linux/mm.h>`中定义。

| **标志位** | **描述** |
| --- | --- |
| `VM_NONE` | 表示非活动映射。 |
| `VM_READ` | 如果设置，映射区域中的页面是可读的。 |
| `VM_WRITE` | 如果设置，映射区域中的页面是可写的。 |
| `VM_EXEC` | 设置为将内存区域标记为可执行。包含可执行指令的内存块与`VM_READ`一起设置此标志。 |
| `VM_SHARED` | 如果设置，映射区域中的页面是共享的。 |
| `VM_MAYREAD` | 用于指示当前映射区域可以设置`VM_READ`。此标志用于`mprotect()`系统调用。 |
| `VM_MAYWRITE` | 用于指示当前映射区域可以设置`VM_WRITE`。此标志用于`mprotect()`系统调用。 |
| `VM_MAYEXEC` | 用于指示当前映射区域可以设置`VM_EXEC`。此标志用于`mprotect()`系统调用。 |
| `VM_GROWSDOWN` | 映射可以向下增长；堆栈段被分配了这个标志。 |
| `VM_UFFD_MISSING` | 设置此标志以指示 VM 子系统为此映射启用了`userfaultfd`，并设置为跟踪页面丢失故障。 |
| `VM_PFNMAP` | 设置此标志以指示内存区域是通过 PFN 跟踪页面映射的，而不是具有页面描述符的常规页面帧。 |
| `VM_DENYWRITE` | 设置以指示当前文件映射不可写。 |
| `VM_UFFD_WP` | 设置此标志以指示 VM 子系统为此映射启用了`userfaultfd`，并设置为跟踪写保护故障。 |
| `VM_LOCKED` | 当映射内存区域中的相应页面被锁定时设置。 |
| `VM_IO` | 当设备 I/O 区域被映射时设置。 |
| `VM_SEQ_READ` | 当进程声明其意图以顺序方式访问映射区域内的内存区域时设置。 |
| `VM_RAND_READ` | 当进程声明其意图在映射区域内以随机方式访问内存区域时设置。 |
| `VM_DONTCOPY` | 设置以指示 VM 在`fork()`上禁用复制此 VMA。 |
| `VM_DONTEXPAND` | 设置以指示当前映射在`mremap()`上不能扩展。 |
| `VM_LOCKONFAULT` | 当进程使用`mlock2()`系统调用启用`MLOCK_ONFAULT`时，当页面被故障时锁定内存映射中的页面。设置此标志。 |
| `VM_ACCOUNT` | VM 子系统执行额外的检查，以确保在对具有此标志的 VMA 执行操作时有可用内存。 |
| `VM_NORESERVE` | VM 是否应该抑制记账。 |
| `VM_HUGETLB` | 表示当前映射包含巨大的 TLB 页面。 |
| `VM_DONTDUMP` | 如果设置，当前 VMA 不会包含在核心转储中。 |
| `VM_MIXEDMAP` | 当 VMA 映射包含传统页面帧（通过页面描述符管理）和 PFN 管理的页面时设置。 |
| `VM_HUGEPAGE` | 当 VMA 标记为`MADV_HUGEPAGE`时设置，以指示 VM 页面在此映射下必须是透明巨大页面（THP）类型。此标志仅适用于私有匿名映射。 |
| `VM_NOHUGEPAGE` | 当 VMA 标记为`MADV_NOHUGEPAGE`时设置。 |
| `VM_MERGEABLE` | 当 VMA 标记为`MADV_MERGEABLE`时设置，这使得内核可以进行同页合并（KSM）。 |
| `VM_ARCH_1` | 架构特定的扩展。 |
| `VM_ARCH_2` | 架构特定的扩展。 |

下图描述了由进程的内存描述符结构指向的`vm_area`列表的典型布局：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00045.jpeg)

如图所示，映射到地址空间的一些内存区域是文件支持的（代码区域形成应用程序二进制文件，共享库，共享内存映射等）。文件缓冲区由内核的页面缓存框架管理，该框架实现了自己的数据结构来表示和管理文件缓存。页面缓存通过`address_space`数据结构跟踪对文件区域的映射，通过各种用户模式进程。`vm_area_struct`对象的`shared`元素将此 VMA 枚举到与地址空间关联的红黑树中。我们将在下一节中更多地讨论页面缓存和`address_space`对象。

堆，栈和 mmap 等虚拟地址空间的区域是通过匿名内存映射分配的。VM 子系统将表示进程的所有匿名内存区域的 VMA 实例分组到一个列表中，并通过`struct anon_vma`类型的描述符表示它们。该结构使得可以快速访问映射匿名页面的所有进程 VMAs；每个匿名 VMA 结构的`*anon_vma`指针指向`anon_vma`对象。

然而，当一个进程 fork 一个子进程时，调用者地址空间的所有匿名页面都在写时复制（COW）下与子进程共享。这会导致创建新的 VMAs（对于子进程），它们表示父进程的相同匿名内存区域。内存管理器需要定位和跟踪所有引用相同区域的 VMAs，以便支持取消映射和交换操作。作为解决方案，VM 子系统使用另一个称为`struct anon_vma_chain`的描述符，它链接进程组的所有`anon_vma`结构。VMA 结构的`anon_vma_chain`元素是匿名 VMA 链的列表元素。

每个 VMA 实例都绑定到`vm_operations_struct`类型的描述符，其中包含对当前 VMA 执行的操作。VMA 实例的`*vm_ops`指针指向操作对象：

```
/*
  * These are the virtual MM functions - opening of an area, closing and
  * unmapping it (needed to keep files on disk up-to-date etc), pointer
  * to the functions called when a no-page or a wp-page exception occurs.
  */
 struct vm_operations_struct {
         void (*open)(struct vm_area_struct * area);
         void (*close)(struct vm_area_struct * area);
         int (*mremap)(struct vm_area_struct * area);
         int (*fault)(struct vm_area_struct *vma, struct vm_fault *vmf);
         int (*pmd_fault)(struct vm_area_struct *, unsigned long address,
                                                 pmd_t *, unsigned int flags);
         void (*map_pages)(struct fault_env *fe,
                         pgoff_t start_pgoff, pgoff_t end_pgoff);
         /* notification that a previously read-only page is about to become
          * writable, if an error is returned it will cause a SIGBUS */
         int (*page_mkwrite)(struct vm_area_struct *vma, struct vm_fault *vmf);
    /* same as page_mkwrite when using VM_PFNMAP|VM_MIXEDMAP */
         int (*pfn_mkwrite)(struct vm_area_struct *vma, struct vm_fault *vmf);
/* called by access_process_vm when get_user_pages() fails, typically
          * for use by special VMAs that can switch between memory and hardware
          */
         int (*access)(struct vm_area_struct *vma, unsigned long addr,
                       void *buf, int len, int write);
/* Called by the /proc/PID/maps code to ask the vma whether it
          * has a special name. Returning non-NULL will also cause this
          * vma to be dumped unconditionally. */
         const char *(*name)(struct vm_area_struct *vma);
   ...
   ...
```

`*open()`函数指针分配的例程在 VMA 枚举到地址空间时被调用。同样，`*close()`函数指针分配的例程在 VMA 从虚拟地址空间中分离时被调用。`*mremap()`接口分配的函数在 VMA 映射的内存区域需要调整大小时执行。当 VMA 映射的物理区域处于非活动状态时，系统会触发页面故障异常，并且内核的页面故障处理程序会通过`*fault()`指针调用分配给 VMA 区域的相应数据。

内核支持对类似于内存的存储设备上的文件进行直接访问操作（DAX），例如 nvrams、闪存存储和其他持久性内存设备。为这类存储设备实现的驱动程序执行所有读写操作，而无需任何缓存。当用户进程尝试从 DAX 存储设备映射文件时，底层磁盘驱动程序直接将相应的文件页面映射到进程的虚拟地址空间。为了获得最佳性能，用户模式进程可以通过启用`VM_HUGETLB`来从 DAX 存储中映射大文件。由于支持的页面大小较大，无法通过常规页面错误处理程序处理 DAX 文件映射上的页面错误，支持 DAX 的文件系统需要将适当的错误处理程序分配给 VMA 的`*pmd_fault()`指针。

# 管理虚拟内存区域

内核的 VM 子系统实现了各种操作，用于操作进程的虚拟内存区域；这些包括创建、插入、修改、定位、合并和删除 VMA 实例的函数。我们将讨论一些重要的例程。

# 定位 VMA

`find_vma()`例程定位 VMA 列表中满足给定地址条件的第一个区域（`addr < vm_area_struct->vm_end`）。

```
/* Look up the first VMA which satisfies addr < vm_end, NULL if none. */
struct vm_area_struct *find_vma(struct mm_struct *mm, unsigned long addr)
{
        struct rb_node *rb_node;
        struct vm_area_struct *vma;

        /* Check the cache first. */
        vma = vmacache_find(mm, addr);
        if (likely(vma))
               return vma;

       rb_node = mm->mm_rb.rb_node;
       while (rb_node) {
               struct vm_area_struct *tmp;
               tmp = rb_entry(rb_node, struct vm_area_struct, vm_rb);
               if (tmp->vm_end > addr) {
                        vma = tmp;
                        if (tmp->vm_start <= addr)
                                 break;
                        rb_node = rb_node->rb_left;
               } else
                        rb_node = rb_node->rb_right;
        }
        if (vma)
               vmacache_update(addr, vma);
        return vma;
}
```

该函数首先在每个线程的`vma`缓存中查找最近访问的`vma`中的请求地址。如果匹配，则返回 VMA 的地址，否则进入红黑树以定位适当的 VMA。树的根节点位于`mm->mm_rb.rb_node`中。通过辅助函数`rb_entry()`，验证每个节点是否在 VMA 的虚拟地址间隔内。如果找到了起始地址较低且结束地址较高的目标 VMA，函数将返回 VMA 实例的地址。如果仍然找不到适当的 VMA，则搜索将继续查找`rbtree`的左侧或右侧子节点。当找到合适的 VMA 时，将其指针更新到`vma`缓存中（预期下一次调用`find_vma()`来定位同一区域中相邻的地址），并返回 VMA 实例的地址。

当一个新区域被添加到一个现有区域之前或之后（因此也在两个现有区域之间），内核将涉及的数据结构合并为一个结构——当然，前提是所有涉及的区域的访问权限相同，并且连续的数据从相同的后备存储器中映射。

# 合并 VMA 区域

当一个新的 VMA 被映射到一个具有相同访问属性和来自文件支持的内存区域的现有 VMA 之前或之后时，将它们合并成一个单独的 VMA 结构更为优化。`vma_merge()`是一个辅助函数，用于合并具有相同属性的周围的 VMAs：

```
struct vm_area_struct *vma_merge(struct mm_struct *mm,
                        struct vm_area_struct *prev, unsigned long addr,
                        unsigned long end, unsigned long vm_flags,
                        struct anon_vma *anon_vma, struct file *file,
                        pgoff_t pgoff, struct mempolicy *policy,
                        struct vm_userfaultfd_ctx vm_userfaultfd_ctx)
{
         pgoff_t pglen = (end - addr) >> PAGE_SHIFT;
         struct vm_area_struct *area, *next;
         int err;  
         ...
         ...

```

`*mm`指的是要合并其 VMAs 的进程的内存描述符；`*prev`指的是其地址间隔在新区域之前的 VMA；`addr`、`end`和`vm_flags`包含新区域的开始、结束和标志。`*file`指的是将其内存区域映射到新区域的文件实例，`pgoff`指定了文件数据中的映射偏移量。

该函数首先检查新区域是否可以与前驱合并：

```
        ...  
        ...
        /*
         * Can it merge with the predecessor?
         */
        if (prev && prev->vm_end == addr &&
                        mpol_equal(vma_policy(prev), policy) &&
                        can_vma_merge_after(prev, vm_flags,
                                            anon_vma, file, pgoff,
                                            vm_userfaultfd_ctx)) {
        ...
        ...
```

为此，它调用一个辅助函数`can_vma_merge_after()`，该函数检查前驱的结束地址是否对应于新区域的开始地址，以及两个区域的访问标志是否相同，还检查文件映射的偏移量，以确保它们在文件区域中是连续的，并且两个区域都不包含任何匿名映射：

```
                ...                
                ...               
                /*
                 * OK, it can. Can we now merge in the successor as well?
                 */
                if (next && end == next->vm_start &&
                                mpol_equal(policy, vma_policy(next)) &&
                                can_vma_merge_before(next, vm_flags,
                                                     anon_vma, file,
                                                     pgoff+pglen,
                                                     vm_userfaultfd_ctx) &&
                                is_mergeable_anon_vma(prev->anon_vma,
                                                      next->anon_vma, NULL)) {
                                                        /* cases 1, 6 */
                        err = __vma_adjust(prev, prev->vm_start,
                                         next->vm_end, prev->vm_pgoff, NULL,
                                         prev);
                } else /* cases 2, 5, 7 */
                        err = __vma_adjust(prev, prev->vm_start,
 end, prev->vm_pgoff, NULL, prev);

           ...
           ...
}
```

然后检查是否可以与后继区域合并；为此，它调用辅助函数`can_vma_merge_before()`。此函数执行与之前类似的检查，如果发现前任和后继区域都相同，则调用`is_mergeable_anon_vma()`来检查是否可以将前任的任何匿名映射与后继的合并。最后，调用另一个辅助函数`__vma_adjust()`来执行最终合并，该函数适当地操作 VMA 实例。

存在类似的辅助函数用于创建、插入和删除内存区域，这些函数作为`do_mmap()`和`do_munmap()`的辅助函数被调用，当用户模式应用程序尝试对内存区域进行`mmap()`和`unmap()`时。我们将不再讨论这些辅助例程的详细信息。

# struct address_space

内存缓存是现代内存管理的一个重要组成部分。简单来说，**缓存**是用于特定需求的页面集合。大多数操作系统实现了**缓冲缓存**，这是一个管理用于缓存持久存储磁盘块的内存块列表的框架。缓冲缓存允许文件系统通过分组和延迟磁盘同步来最小化磁盘 I/O 操作，直到适当的时间。

Linux 内核实现了**页面缓存**作为缓存的机制；简单来说，页面缓存是动态管理的页面帧集合，用于缓存磁盘文件和目录，并通过提供页面进行交换和需求分页来支持虚拟内存操作。它还处理为特殊文件分配的页面，例如 IPC 共享内存和消息队列。应用程序文件 I/O 调用，如读取和写入，会导致底层文件系统对页面缓存中的页面执行相关操作。对未读文件的读取操作会导致请求的文件数据从磁盘获取到页面缓存中的页面，而写操作会更新缓存页面中相关文件数据，然后标记为*脏*并在特定间隔刷新到磁盘。

缓存中包含特定磁盘文件数据的页面组通过`struct address_space`类型的描述符表示，因此每个`address_space`实例都用作由文件`inode`或块设备文件`inode`拥有的页面集合的抽象：

```
struct address_space {
        struct inode *host; /* owner: inode, block_device */
        struct radix_tree_root page_tree; /* radix tree of all pages */
        spinlock_t tree_lock; /* and lock protecting it */
        atomic_t i_mmap_writable;/* count VM_SHARED mappings */
        struct rb_root i_mmap; /* tree of private and shared mappings */
        struct rw_semaphore i_mmap_rwsem; /* protect tree, count, list */
        /* Protected by tree_lock together with the radix tree */
        unsigned long nrpages; /* number of total pages */
        /* number of shadow or DAX exceptional entries */
        unsigned long nrexceptional;
        pgoff_t writeback_index;/* writeback starts here */
        const struct address_space_operations *a_ops; /* methods */
        unsigned long flags; /* error bits */
        spinlock_t private_lock; /* for use by the address_space */
        gfp_t gfp_mask; /* implicit gfp mask for allocations */
        struct list_head private_list; /* ditto */
        void *private_data; /* ditto */
} __attribute__((aligned(sizeof(long))));
```

`*host`指针指的是拥有者`inode`，其数据包含在当前`address_space`对象表示的页面中。例如，如果缓存中的一个页面包含由 Ext4 文件系统管理的文件的数据，文件的相应 VFS `inode`将在其`i_data`字段中存储`address_space`对象。文件的`inode`和相应的`address_space`对象存储在 VFS `inode`对象的`i_data`字段中。`nr_pages`字段包含此`address_space`下页面的计数。

为了有效管理缓存中的文件页面，VM 子系统需要跟踪到同一`address_space`区域的所有虚拟地址映射；例如，一些用户模式进程可能通过`vm_area_struct`实例将共享库的页面映射到它们的地址空间中。`address_space`对象的`i_mmap`字段是包含当前映射到此`address_space`的所有`vm_area_struct`实例的红黑树的根元素；由于每个`vm_area_struct`实例都指回相应进程的内存描述符，因此始终可以跟踪进程引用。

`address_space`对象下包含文件数据的所有物理页面通过基数树进行有效访问的组织；`page_tree`字段是`struct radix_tree_root`的一个实例，用作基数树的根元素。此结构在内核头文件`<linux/radix-tree.h>`中定义：

```
struct radix_tree_root {
        gfp_t gfp_mask;
        struct radix_tree_node __rcu *rnode;
};
```

树的每个节点都是`struct radix_tree_node`类型；前一个结构的`*rnode`指针指向树的第一个节点元素：

```
struct radix_tree_node {
        unsigned char shift; /* Bits remaining in each slot */
        unsigned char offset; /* Slot offset in parent */
        unsigned int count;
        union {
                struct {
                        /* Used when ascending tree */
                        struct radix_tree_node *parent;
                        /* For tree user */
                        void *private_data;
                };
                /* Used when freeing node */
                struct rcu_head rcu_head;
        };
        /* For tree user */
        struct list_head private_list;
        void __rcu *slots[RADIX_TREE_MAP_SIZE];
        unsigned long tags[RADIX_TREE_MAX_TAGS][RADIX_TREE_TAG_LONGS];
};
```

`offset`字段指定了父节点中的节点槽偏移量，`count`保存了子节点的总数，`*parent`是指向父节点的指针。每个节点可以通过槽数组引用 64 个树节点（由宏`RADIX_TREE_MAP_SIZE`指定），其中未使用的槽条目初始化为 NULL。

为了有效管理地址空间下的页面，内存管理器需要在干净页面和脏页面之间设置清晰的区别；这通过为`radix`树的每个节点的页面分配**标签**来实现。标记信息存储在节点结构的`tags`字段中，这是一个二维数组。数组的第一维区分可能的标签，第二维包含足够数量的无符号长整型元素，以便每个可以在节点中组织的页面都有一个位。以下是支持的标签列表：

```
/*
 * Radix-tree tags, for tagging dirty and writeback pages within 
 * pagecache radix trees                 
 */
#define PAGECACHE_TAG_DIRTY 0
#define PAGECACHE_TAG_WRITEBACK 1
#define PAGECACHE_TAG_TOWRITE 2
```

Linux 的`radix`树 API 提供了各种操作接口来`set`、`clear`和`get`标签：

```
void *radix_tree_tag_set(struct radix_tree_root *root,
                                     unsigned long index, unsigned int tag);
void *radix_tree_tag_clear(struct radix_tree_root *root,
                                     unsigned long index, unsigned int tag);
int radix_tree_tag_get(struct radix_tree_root *root,
                                     unsigned long index, unsigned int tag);
```

以下图表描述了`address_space`对象下页面的布局：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00046.jpeg)

每个地址空间对象都绑定了一组实现地址空间页面和后端存储块设备之间各种低级操作的函数。`address_space`结构的`a_ops`指针指向包含地址空间操作的描述符。这些操作由 VFS 调用，以启动与地址映射和后端存储块设备关联的缓存中的页面之间的数据传输：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00047.jpeg)

# 页表

在到达适当的物理内存区域之前，对进程虚拟地址区域的所有访问操作都经过地址转换。VM 子系统维护页表，将线性页地址转换为物理地址。尽管页表布局是特定于体系结构的，但对于大多数体系结构，内核使用四级分页结构，我们将考虑 x86-64 内核页表布局进行讨论。

以下图表描述了 x86-64 的页表布局：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-linux-krn-dev/img/00048.jpeg)

页全局目录的地址，即顶层页表，被初始化为控制寄存器 cr3。这是一个 64 位寄存器，按位分解如下：

| 位 | 描述 |
| --- | --- |
| 2:0 | 忽略 |
| 4:3 | 页级写穿和页级缓存禁用 |
| 11:5 | 保留 |
| 51:12 | 页全局目录的地址 |
| 63:52 | 保留 |

在 x86-64 支持的 64 位宽线性地址中，Linux 目前使用了 48 位，可以支持 256 TB 的线性地址空间，这被认为对于当前的使用已经足够大。这 48 位线性地址分为五部分，前 12 位包含物理帧中内存位置的偏移量，其余部分包含适当页表结构的偏移量：

| **线性地址位** | **描述** |
| --- | --- |
| 11:0 (12 bits) | 物理页的索引 |
| 20:12 (9 bits) | 页表的索引 |
| 29:21 (9 bits) | 页中间目录的索引 |
| 38:30 (9 bits) | 页上层目录的索引 |
| 47:39 (9 bits) | 页全局目录的索引 |

每个页表结构都可以支持 512 条记录，每条记录都提供下一级页结构的基地址。在翻译给定的线性地址时，MMU 提取包含页全局目录（PGD）索引的前 9 位，然后将其加到 PGD 的基地址（在 cr3 中找到）；这个查找结果会发现页上级目录（PUD）的基地址。接下来，MMU 检索线性地址中找到的 PUD 偏移量（9 位），并将其加到 PUD 结构的基地址，以达到 PUD 条目（PUDE），从而得到页中间目录（PMD）的基地址。然后将线性地址中找到的 PMD 偏移量加到 PMD 的基地址，以达到相关的 PMD 条目（PMDE），从而得到页表的基地址。然后将线性地址中找到的页表偏移量（9 位）加到从 PMD 条目中发现的基地址，以达到页表条目（PTE），进而得到所请求数据的物理帧的起始地址。最后，将线性地址中找到的页偏移量（12 位）加到 PTE 发现的基地址，以达到要访问的内存位置。

# 摘要

在本章中，我们关注了虚拟内存管理的具体内容，涉及进程虚拟地址空间和内存映射。我们讨论了 VM 子系统的关键数据结构，内存描述符结构（`struct mm_struct`）和 VMA 描述符（`struct vm_area_struct`）。我们看了看页缓存及其数据结构（`struct address_space`），用于将文件缓冲区在各种进程地址空间中进行反向映射。最后，我们探讨了 Linux 的页表布局，这在许多架构中被广泛使用。在对文件系统和虚拟内存管理有了深入了解之后，在下一章中，我们将把这个讨论扩展到 IPC 子系统及其资源。


# 第八章：内核同步和锁定

内核地址空间由所有用户模式进程共享，这使得可以并发访问内核服务和数据结构。为了系统的可靠运行，内核服务必须实现为可重入的。访问全局数据结构的内核代码路径需要同步，以确保共享数据的一致性和有效性。在本章中，我们将详细介绍内核程序员用于同步内核代码路径和保护共享数据免受并发访问的各种资源。

本章将涵盖以下主题：

+   原子操作

+   自旋锁

+   标准互斥锁

+   等待/伤害互斥锁

+   信号量

+   序列锁

+   完成

# 原子操作

计算操作被认为是**原子的**，如果它在系统的其余部分看起来是瞬间发生的。原子性保证了操作的不可分割和不可中断的执行。大多数 CPU 指令集架构定义了可以在内存位置上执行原子读-修改-写操作的指令操作码。这些操作具有成功或失败的定义，即它们要么成功地改变内存位置的状态，要么失败而没有明显的影响。这些操作对于在多线程场景中原子地操作共享数据非常有用。它们还用作实现排他锁的基础构建块，这些锁用于保护共享内存位置免受并行代码路径的并发访问。

Linux 内核代码使用原子操作来处理各种用例，例如共享数据结构中的引用计数器（用于跟踪对各种内核数据结构的并发访问），等待-通知标志，以及为特定代码路径启用数据结构的独占所有权。为了确保直接处理原子操作的内核服务的可移植性，内核提供了丰富的与体系结构无关的接口宏和内联函数库，这些函数库用作处理器相关的原子指令的抽象。这些中立接口下的相关 CPU 特定原子指令由内核代码的体系结构分支实现。

# 原子整数操作

通用原子操作接口包括对整数和位操作的支持。整数操作被实现为操作特殊的内核定义类型，称为`atomic_t`（32 位整数）和`atomic64_t`（64 位整数）。这些类型的定义可以在通用内核头文件`<linux/types.h>`中找到：

```
typedef struct {
        int counter;
} atomic_t;

#ifdef CONFIG_64BIT
typedef struct {
        long counter;
} atomic64_t;
#endif
```

该实现提供了两组整数操作；一组适用于 32 位，另一组适用于 64 位原子变量。这些接口操作被实现为一组宏和内联函数。以下是适用于`atomic_t`类型变量的操作的摘要列表：

| **接口宏/内联函数** | **描述** |
| --- | --- |
| `ATOMIC_INIT(i)` | 用于初始化原子计数器的宏 |
| `atomic_read(v)` | 读取原子计数器`v`的值 |
| `atomic_set(v, i)` | 原子性地将计数器`v`设置为`i`中指定的值 |
| `atomic_add(int i, atomic_t *v)` | 原子性地将`i`添加到计数器`v`中 |
| `atomic_sub(int i, atomic_t *v)` | 原子性地从计数器`v`中减去`i` |
| `atomic_inc(atomic_t *v)` | 原子性地增加计数器`v` |
| `atomic_dec(atomic_t *v)` | 原子性地减少计数器`v` |

以下是执行相关**读-修改-写**（**RMW**）操作并返回结果的函数列表（即，它们返回修改后写入内存地址的值）：

| **操作** | **描述** |
| --- | --- |
| `bool atomic_sub_and_test(int i, atomic_t *v)` | 原子性地从`v`中减去`i`，如果结果为零则返回`true`，否则返回`false` |
| `bool atomic_dec_and_test(atomic_t *v)` | 原子性地将`v`减 1，并在结果为 0 时返回`true`，否则对所有其他情况返回`false` |
| `bool atomic_inc_and_test(atomic_t *v)` | 原子地将`i`添加到`v`，如果结果为 0 则返回`true`，否则返回`false` |
| `bool atomic_add_negative(int i, atomic_t *v)` | 原子地将`i`添加到`v`，如果结果为负数则返回`true`，如果结果大于或等于零则返回`false` |
| `int atomic_add_return(int i, atomic_t *v)` | 原子地将`i`添加到`v`，并返回结果 |
| `int atomic_sub_return(int i, atomic_t *v)` | 原子地从`v`中减去`i`，并返回结果 |
| `int atomic_fetch_add(int i, atomic_t *v)` | 原子地将`i`添加到`v`，并返回`v`中的加法前值 |
| `int atomic_fetch_sub(int i, atomic_t *v)` | 原子地从`v`中减去`i`，并返回`v`中的减法前值 |
| `int atomic_cmpxchg(atomic_t *v, int old,` int new) | 读取位置`v`处的值，并检查它是否等于`old`；如果为`true`，则交换`v`处的值与`*new*`，并始终返回在`v`处读取的值 |
| `int atomic_xchg(atomic_t *v, int new)` | 用`new`交换存储在位置`v`处的旧值，并返回旧值`v` |

对于所有这些操作，都存在用于`atomic64_t`的 64 位变体；这些函数的命名约定为`atomic64_*()`

# 原子位操作

内核提供的通用原子操作接口还包括位操作。与整数操作不同，整数操作被实现为在`atomic(64)_t`类型上操作，这些位操作可以应用于任何内存位置。这些操作的参数是位的位置或位数，以及一个具有有效地址的指针。32 位机器的位范围为 0-31，64 位机器的位范围为 0-63。以下是可用的位操作的摘要列表：

| **操作接口** | **描述** |
| --- | --- |
| `set_bit(int nr, volatile unsigned long *addr)` | 在从`addr`开始的位置上原子设置位`nr` |
| `clear_bit(int nr, volatile unsigned long *addr)` | 在从`addr`开始的位置上原子清除位`nr` |
| `change_bit(int nr, volatile unsigned long *addr)` | 在从`addr`开始的位置上原子翻转位`nr` |
| `int test_and_set_bit(int nr, volatile unsigned long *addr)` | 在从`addr`开始的位置上原子设置位`nr`，并返回`nr^(th)`位的旧值 |
| `int test_and_clear_bit(int nr, volatile unsigned long *addr)` | 在从`addr`开始的位置上原子清除位`nr`，并返回`nr``^(th)`位的旧值 |
| `int test_and_change_bit(int nr, volatile unsigned long *addr)` | 在从`addr`开始的位置上原子翻转位`nr`，并返回`nr^(th)`位的旧值 |

对于所有具有返回类型的操作，返回的值是在指定修改发生之前从内存地址中读取的位的旧状态。这些操作也存在非原子版本；它们对于可能需要位操作的情况是高效且有用的，这些情况是从互斥临界块中的代码语句发起的。这些在内核头文件`<linux/bitops/non-atomic.h>`中声明。

# 引入排他锁

硬件特定的原子指令只能操作 CPU 字和双字大小的数据；它们不能直接应用于自定义大小的共享数据结构。对于大多数多线程场景，通常可以观察到共享数据是自定义大小的，例如，一个具有*n*个不同类型元素的结构。访问这些数据的并发代码路径通常包括一堆指令，这些指令被编程为访问和操作共享数据；这样的访问操作必须被*原子地*执行，以防止竞争。为了确保这些代码块的原子性，使用了互斥锁。所有多线程环境都提供了基于排他协议的互斥锁的实现。这些锁定实现是建立在硬件特定的原子指令之上的。

Linux 内核实现了标准排斥机制的操作接口，如互斥和读写排斥。它还包含对各种其他当代轻量级和无锁同步机制的支持。大多数内核数据结构和其他共享数据元素，如共享缓冲区和设备寄存器，都通过内核提供的适当排斥锁接口受到并发访问的保护。在本节中，我们将探讨可用的排斥机制及其实现细节。

# 自旋锁

**自旋锁**是大多数并发编程环境中广泛实现的最简单和轻量级的互斥机制之一。自旋锁实现定义了一个锁结构和操作，用于操作锁结构。锁结构主要包含原子锁计数器等元素，操作接口包括：

+   一个**初始化例程**，用于将自旋锁实例初始化为默认（解锁）状态

+   一个**锁例程**，通过原子地改变锁计数器的状态来尝试获取自旋锁

+   一个**解锁例程**，通过将计数器改变为解锁状态来释放自旋锁

当调用者尝试在锁定时（或被另一个上下文持有）获取自旋锁时，锁定函数会迭代地轮询或自旋直到可用，导致调用者上下文占用 CPU 直到获取锁。正是由于这个事实，这种排斥机制被恰当地命名为自旋锁。因此建议确保关键部分内的代码是原子的或非阻塞的，以便锁定可以持续一个短暂的、确定的时间，因为显然持有自旋锁很长时间可能会造成灾难。

正如讨论的那样，自旋锁是围绕处理器特定的原子操作构建的；内核的架构分支实现了核心自旋锁操作（汇编编程）。内核通过一个通用的平台中立接口包装了架构特定的实现，该接口可以直接被内核服务使用；这使得使用自旋锁保护共享资源的服务代码具有可移植性。

通用自旋锁接口可以在内核头文件 `<linux/spinlock.h>` 中找到，而特定架构的定义是 `<asm/spinlock.h>` 的一部分。通用接口提供了一系列针对特定用例实现的 `lock()` 和 `unlock()` 操作。我们将在接下来的章节中讨论这些接口中的每一个；现在，让我们从接口提供的标准和最基本的 `lock()` 和 `unlock()` 操作变体开始我们的讨论。以下代码示例展示了基本自旋锁接口的使用：

```
DEFINE_SPINLOCK(s_lock);
spin_lock(&s_lock);
/* critical region ... */
spin_unlock(&s_lock);
```

让我们来看看这些函数的实现细节：

```
static __always_inline void spin_lock(spinlock_t *lock)
{
        raw_spin_lock(&lock->rlock);
}

...
...

static __always_inline void spin_unlock(spinlock_t *lock)
{
        raw_spin_unlock(&lock->rlock);
}
```

内核代码实现了两种自旋锁操作的变体；一种适用于 SMP 平台，另一种适用于单处理器平台。自旋锁数据结构和与架构和构建类型（SMP 和 UP）相关的操作在内核源树的各个头文件中定义。让我们熟悉一下这些头文件的作用和重要性：

`<include/linux/spinlock.h>` 包含了通用的自旋锁/rwlock 声明。

以下头文件与 SMP 平台构建相关：

+   `<asm/spinlock_types.h>` 包含了 `arch_spinlock_t/arch_rwlock_t` 和初始化程序

+   `<linux/spinlock_types.h>` 定义了通用类型和初始化程序

+   `<asm/spinlock.h>` 包含了 `arch_spin_*()` 和类似的低级操作实现

+   `<linux/spinlock_api_smp.h>` 包含了 `_spin_*()` API 的原型

+   `<linux/spinlock.h>` 构建了最终的 `spin_*()` API

以下头文件与单处理器（UP）平台构建相关：

+   `<linux/spinlock_type_up.h>` 包含了通用的、简化的 UP 自旋锁类型

+   `<linux/spinlock_types.h>` 定义了通用类型和初始化程序

+   `<linux/spinlock_up.h>`包含了`arch_spin_*()`和 UP 版本的类似构建（在非调试、非抢占构建上是 NOP）

+   `<linux/spinlock_api_up.h>`构建了`_spin_*()`API

+   `<linux/spinlock.h>`构建了最终的`spin_*()`APIs

通用内核头文件`<linux/spinlock.h>`包含一个条件指令，以决定拉取适当的（SMP 或 UP）API。

```
/*
 * Pull the _spin_*()/_read_*()/_write_*() functions/declarations:
 */
#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)
# include <linux/spinlock_api_smp.h>
#else
# include <linux/spinlock_api_up.h>
#endif
```

`raw_spin_lock()`和`raw_spin_unlock()`宏会根据构建配置中选择的平台类型（SMP 或 UP）动态扩展为适当版本的自旋锁操作。对于 SMP 平台，`raw_spin_lock()`会扩展为内核源文件`kernel/locking/spinlock.c`中实现的`__raw_spin_lock()`操作。以下是使用宏定义的锁定操作代码：

```
/*
 * We build the __lock_function inlines here. They are too large for
 * inlining all over the place, but here is only one user per function
 * which embeds them into the calling _lock_function below.
 *
 * This could be a long-held lock. We both prepare to spin for a long
 * time (making _this_ CPU preemptable if possible), and we also signal
 * towards that other CPU that it should break the lock ASAP.
 */

#define BUILD_LOCK_OPS(op, locktype)                                    \
void __lockfunc __raw_##op##_lock(locktype##_t *lock)                   \
{                                                                       \
        for (;;) {                                                      \
                preempt_disable();                                      \
                if (likely(do_raw_##op##_trylock(lock)))                \
                        break;                                          \
                preempt_enable();                                       \
                                                                        \
                if (!(lock)->break_lock)                                \
                        (lock)->break_lock = 1;                         \
                while (!raw_##op##_can_lock(lock) && (lock)->break_lock)\
                        arch_##op##_relax(&lock->raw_lock);             \
        }                                                               \
        (lock)->break_lock = 0;                                         \
} 
```

这个例程由嵌套的循环结构组成，一个外部`for`循环结构和一个内部`while`循环，它会一直旋转，直到指定的条件满足为止。外部循环的第一个代码块通过调用特定于体系结构的`##_trylock()`例程来原子地尝试获取锁。请注意，此函数在本地处理器上禁用内核抢占时被调用。如果成功获取锁，则跳出循环结构，并且调用返回时关闭了抢占。这确保了持有锁的调用者上下文在执行临界区时不可抢占。这种方法还确保了在当前所有者释放锁之前，没有其他上下文可以在本地 CPU 上争夺相同的锁。

然而，如果它未能获取锁，通过`preempt_enable()`调用启用了抢占，并且调用者上下文进入内部循环。这个循环是通过一个条件`while`实现的，它会一直旋转，直到发现锁可用为止。循环的每次迭代都会检查锁，并且当它检测到锁还不可用时，会调用一个特定于体系结构的放松例程（执行特定于 CPU 的 nop 指令），然后再次旋转以检查锁。请记住，在此期间抢占是启用的；这确保了调用者上下文是可抢占的，并且不会长时间占用 CPU，尤其是在锁高度争用的情况下可能发生。这也允许同一 CPU 上调度的两个或更多线程争夺相同的锁，可能通过相互抢占来实现。

当旋转上下文检测到锁可用时，它会跳出`while`循环，导致调用者迭代回外部循环（`for`循环）的开始处，再次尝试通过`##_trylock()`来抓取锁，同时禁用抢占：

```
/*
 * In the UP-nondebug case there's no real locking going on, so the
 * only thing we have to do is to keep the preempt counts and irq
 * flags straight, to suppress compiler warnings of unused lock
 * variables, and to add the proper checker annotations:
 */
#define ___LOCK(lock) \
  do { __acquire(lock); (void)(lock); } while (0)

#define __LOCK(lock) \
  do { preempt_disable(); ___LOCK(lock); } while (0)

#define _raw_spin_lock(lock) __LOCK(lock)
```

与 SMP 变体不同，UP 平台的自旋锁实现非常简单；实际上，锁例程只是禁用内核抢占并将调用者放入临界区。这是因为在暂停抢占的情况下，没有其他上下文可能会争夺锁。

# 备用自旋锁 API

到目前为止我们讨论的标准自旋锁操作适用于仅从进程上下文内核路径访问的共享资源的保护。然而，可能存在一些场景，其中特定的共享资源或数据可能会从内核服务的进程上下文和中断上下文代码中访问。例如，考虑一个设备驱动程序服务，可能包含进程上下文和中断上下文例程，都编程来访问共享的驱动程序缓冲区以执行适当的 I/O 操作。

假设使用自旋锁来保护驱动程序的共享资源免受并发访问，并且驱动程序服务的所有例程（包括进程和中断上下文）都使用标准的`spin_lock()`和`spin_unlock()`操作编程了适当的临界区。这种策略将通过强制排斥来确保共享资源的保护，但可能会导致 CPU 在随机时间出现*硬锁定条件*，因为中断路径代码在同一 CPU 上争夺*锁*。为了进一步理解这一点，让我们假设以下事件按相同顺序发生：

1.  驱动程序的进程上下文例程获取*锁（*使用标准的`spin_lock()`调用*）。

1.  关键部分正在执行时，发生中断并被驱动到本地 CPU，导致进程上下文例程被抢占并让出 CPU 给中断处理程序。

1.  驱动程序的中断上下文路径（ISR）开始并尝试获取*锁（*使用标准的`spin_lock()`调用*），*然后开始自旋等待*锁*可用。

在 ISR 的持续时间内，进程上下文被抢占并且永远无法恢复执行，导致*锁*永远无法释放，并且 CPU 被一个永远不会放弃的自旋中断处理程序硬锁定。

为了防止这种情况发生，进程上下文代码需要在获取*锁*时禁用当前处理器上的中断。这将确保中断在临界区和锁释放*之前*永远无法抢占当前上下文。请注意，中断仍然可能发生，但会路由到其他可用的 CPU 上，在那里中断处理程序可以自旋，直到*锁*变为可用。自旋锁接口提供了另一种锁定例程`spin_lock_irqsave()`，它会禁用当前处理器上的中断以及内核抢占。以下代码片段显示了该例程的基础代码：

```
unsigned long __lockfunc __raw_##op##_lock_irqsave(locktype##_t *lock)  \
{                                                                       \
        unsigned long flags;                                            \
                                                                        \
        for (;;) {                                                      \
                preempt_disable();                                      \
                local_irq_save(flags);                                  \
                if (likely(do_raw_##op##_trylock(lock)))                \
                        break;                                          \
                local_irq_restore(flags);                               \
                preempt_enable();                                       \
                                                                        \
                if (!(lock)->break_lock)                                \
                        (lock)->break_lock = 1;                         \
                while (!raw_##op##_can_lock(lock) && (lock)->break_lock)\
                        arch_##op##_relax(&lock->raw_lock);             \
        }                                                               \
        (lock)->break_lock = 0;                                         \
        return flags;                                                   \
} 
```

调用`local_irq_save()`来禁用当前处理器的硬中断；请注意，如果未能获取锁，则通过调用`local_irq_restore()`来启用中断。请注意，使用`spin_lock_irqsave()`获取的锁需要使用`spin_lock_irqrestore()`来解锁，这会在释放锁之前为当前处理器启用内核抢占和中断。

与硬中断处理程序类似，软中断上下文例程（如*softirqs，tasklets*和其他*bottom halves*）也可能争夺同一处理器上由进程上下文代码持有的*锁*。这可以通过在进程上下文中获取*锁*时禁用*bottom halves*的执行来防止。`spin_lock_bh()`是另一种锁定例程的变体，它负责挂起本地 CPU 上的中断上下文 bottom halves 的执行。

```
void __lockfunc __raw_##op##_lock_bh(locktype##_t *lock)                \
{                                                                       \
        unsigned long flags;                                            \
                                                                        \
        /* */                                                           \
        /* Careful: we must exclude softirqs too, hence the */          \
        /* irq-disabling. We use the generic preemption-aware */        \
        /* function: */                                                 \
        /**/                                                            \
        flags = _raw_##op##_lock_irqsave(lock);                         \
        local_bh_disable();                                             \
        local_irq_restore(flags);                                       \
} 
```

`local_bh_disable()`挂起本地 CPU 的 bottom half 执行。要释放由`spin_lock_bh()`获取的*锁*，调用者上下文将需要调用`spin_unlock_bh()`，这将释放本地 CPU 的自旋锁和 BH 锁。

以下是内核自旋锁 API 接口的摘要列表：

| **函数** | **描述** |
| --- | --- |
| `spin_lock_init()` | 初始化自旋锁 |
| `spin_lock()` | 获取锁，在竞争时自旋 |
| `spin_trylock()` | 尝试获取锁，在竞争时返回错误 |
| `spin_lock_bh()` | 通过挂起本地处理器上的 BH 例程来获取锁，在竞争时自旋 |
| `spin_lock_irqsave()` | 通过保存当前中断状态来挂起本地处理器上的中断来获取锁，在竞争时自旋 |
| `spin_lock_irq()` | 通过挂起本地处理器上的中断来获取锁，在竞争时自旋 |
| `spin_unlock()` | 释放锁 |
| `spin_unlock_bh()` | 释放本地处理器的锁并启用 bottom half |
| `spin_unlock_irqrestore()` | 释放锁并将本地中断恢复到先前的状态 |
| `spin_unlock_irq()` | 释放锁并恢复本地处理器的中断 |
| `spin_is_locked()` | 返回锁的状态，如果锁被持有则返回非零，如果锁可用则返回零 |

# 读写器自旋锁

到目前为止讨论的自旋锁实现通过强制并发代码路径之间的标准互斥来保护共享数据的访问。这种形式的排斥不适合保护经常被并发代码路径读取的共享数据，而写入或更新很少。读写锁强制在读取器和写入器路径之间进行排斥；这允许并发读取器共享锁，而读取任务将需要等待锁，而写入器拥有锁。Rw-locks 强制在并发写入器之间进行标准排斥，这是期望的。

Rw-locks 由在内核头文件`<linux/rwlock_types.h>`中声明的`struct rwlock_t`表示：

```
typedef struct {
        arch_rwlock_t raw_lock;
#ifdef CONFIG_GENERIC_LOCKBREAK
        unsigned int break_lock;
#endif
#ifdef CONFIG_DEBUG_SPINLOCK
        unsigned int magic, owner_cpu;
        void *owner;
#endif
#ifdef CONFIG_DEBUG_LOCK_ALLOC
        struct lockdep_map dep_map;
#endif
} rwlock_t;
```

rwlocks 可以通过宏`DEFINE_RWLOCK(v_rwlock)`静态初始化，也可以通过`rwlock_init(v_rwlock)`在运行时动态初始化。

读取器代码路径将需要调用`read_lock`例程。

```
read_lock(&v_rwlock);
/* critical section with read only access to shared data */
read_unlock(&v_rwlock);
```

写入器代码路径使用以下内容：

```
write_lock(&v_rwlock);
/* critical section for both read and write */
write_unlock(&v_lock);
```

当锁有争用时，读取和写入锁例程都会自旋。该接口还提供了称为`read_trylock()`和`write_trylock()`的非自旋版本的锁函数。它还提供了锁定调用的中断禁用版本，当读取或写入路径恰好在中断或底半部上下文中执行时非常方便。

以下是接口操作的摘要列表：

| **函数** | **描述** |
| --- | --- |
| `read_lock()` | 标准读锁接口，当有争用时会自旋 |
| `read_trylock()` | 尝试获取锁，如果锁不可用则返回错误 |
| `read_lock_bh()` | 通过挂起本地 CPU 的 BH 执行来尝试获取锁，当有争用时会自旋 |
| `read_lock_irqsave()` | 通过保存本地中断的当前状态来尝试通过挂起当前 CPU 的中断来获取锁，当有争用时会自旋 |
| `read_unlock()` | 释放读锁 |
| `read_unlock_irqrestore()` | 释放持有的锁并将本地中断恢复到先前的状态 |
| `read_unlock_bh()` | 释放读锁并在本地处理器上启用 BH |
| `write_lock()` | 标准写锁接口，当有争用时会自旋 |
| `write_trylock()` | 尝试获取锁，如果有争用则返回错误 |
| `write_lock_bh()` | 尝试通过挂起本地 CPU 的底半部来获取写锁，当有争用时会自旋 |
| `wrtie_lock_irqsave()` | 通过保存本地中断的当前状态来尝试通过挂起本地 CPU 的中断来获取写锁，当有争用时会自旋 |
| `write_unlock()` | 释放写锁 |
| `write_unlock_irqrestore()` | 释放锁并将本地中断恢复到先前的状态 |
| `write_unlock_bh()` | 释放写锁并在本地处理器上启用 BH |

所有这些操作的底层调用与自旋锁实现的类似，并且可以在前面提到的自旋锁部分指定的头文件中找到。

# 互斥锁

自旋锁的设计更适用于锁定持续时间短、固定的情况，因为无限期的忙等待会对系统的性能产生严重影响。然而，有许多情况下锁定持续时间较长且不确定；**睡眠锁**正是为这种情况而设计的。内核互斥锁是睡眠锁的一种实现：当调用任务尝试获取一个不可用的互斥锁（已被另一个上下文拥有），它会被置于休眠状态并移出到等待队列，强制进行上下文切换，从而允许 CPU 运行其他有生产力的任务。当互斥锁变为可用时，等待队列中的任务将被唤醒并通过互斥锁的解锁路径移动，然后尝试*锁定*互斥锁。

互斥锁由`include/linux/mutex.h`中定义的`struct mutex`表示，并且相应的操作在源文件`kernel/locking/mutex.c`中实现：

```
 struct mutex {
          atomic_long_t owner;
          spinlock_t wait_lock;
 #ifdef CONFIG_MUTEX_SPIN_ON_OWNER
          struct optimistic_spin_queue osq; /* Spinner MCS lock */
 #endif
          struct list_head wait_list;
 #ifdef CONFIG_DEBUG_MUTEXES
          void *magic;
 #endif
 #ifdef CONFIG_DEBUG_LOCK_ALLOC
          struct lockdep_map dep_map;
 #endif
 }; 
```

在其基本形式中，每个互斥锁都包含一个 64 位的`atomic_long_t`计数器（`owner`），用于保存锁定状态，并存储当前拥有锁的任务结构的引用。每个互斥锁都包含一个等待队列（`wait_list`）和一个自旋锁（`wait_lock`），用于对`wait_list`进行串行访问。

互斥锁 API 接口提供了一组宏和函数，用于初始化、锁定、解锁和访问互斥锁的状态。这些操作接口在`<include/linux/mutex.h>`中定义。

可以使用宏`DEFINE_MUTEX(name)`声明和初始化互斥锁。

还有一种选项，可以通过`mutex_init(mutex)`动态初始化有效的互斥锁。

如前所述，在争用时，锁操作会将调用线程置于休眠状态，这要求在将其移入互斥锁等待列表之前，将调用线程置于`TASK_INTERRUPTIBLE`、`TASK_UNINTERRUPTIBLE`或`TASK_KILLABLE`状态。为了支持这一点，互斥锁实现提供了两种锁操作的变体，一种用于**不可中断**，另一种用于**可中断**休眠。以下是每个标准互斥锁操作的简要描述：

```
/**
 * mutex_lock - acquire the mutex
 * @lock: the mutex to be acquired
 *
 * Lock the mutex exclusively for this task. If the mutex is not
 * available right now, Put caller into Uninterruptible sleep until mutex 
 * is available.
 */
    void mutex_lock(struct mutex *lock);

/**
 * mutex_lock_interruptible - acquire the mutex, interruptible
 * @lock: the mutex to be acquired
 *
 * Lock the mutex like mutex_lock(), and return 0 if the mutex has
 * been acquired else put caller into interruptible sleep until the mutex  
 * until mutex is available. Return -EINTR if a signal arrives while sleeping
 * for the lock.                               
 */
 int __must_check mutex_lock_interruptible(struct mutex *lock); /**
 * mutex_lock_Killable - acquire the mutex, interruptible
 * @lock: the mutex to be acquired
 *
 * Similar to mutex_lock_interruptible(),with a difference that the call
 * returns -EINTR only when fatal KILL signal arrives while sleeping for the     
 * lock.                              
 */
 int __must_check mutex_lock_killable(struct mutex *lock); /**
 * mutex_trylock - try to acquire the mutex, without waiting
 * @lock: the mutex to be acquired
 *
 * Try to acquire the mutex atomically. Returns 1 if the mutex
 * has been acquired successfully, and 0 on contention.
 *
 */
    int mutex_trylock(struct mutex *lock); /**
 * atomic_dec_and_mutex_lock - return holding mutex if we dec to 0,
 * @cnt: the atomic which we are to dec
 * @lock: the mutex to return holding if we dec to 0
 *
 * return true and hold lock if we dec to 0, return false otherwise. Please 
 * note that this function is interruptible.
 */
    int atomic_dec_and_mutex_lock(atomic_t *cnt, struct mutex *lock); 
/**
 * mutex_is_locked - is the mutex locked
 * @lock: the mutex to be queried
 *
 * Returns 1 if the mutex is locked, 0 if unlocked.
 */
/**
 * mutex_unlock - release the mutex
 * @lock: the mutex to be released
 *
 * Unlock the mutex owned by caller task.
 *
 */
 void mutex_unlock(struct mutex *lock);
```

尽管可能会阻塞调用，但互斥锁定函数已经针对性能进行了大幅优化。它们被设计为在尝试获取锁时采用快速路径和慢速路径方法。让我们深入了解锁定调用的代码，以更好地理解快速路径和慢速路径。以下代码摘录是来自`<kernel/locking/mutex.c>`中的`mutex_lock()`例程：

```
void __sched mutex_lock(struct mutex *lock)
{
  might_sleep();

  if (!__mutex_trylock_fast(lock))
    __mutex_lock_slowpath(lock);
}
```

首先通过调用非阻塞的快速路径调用`__mutex_trylock_fast()`来尝试获取锁。如果由于争用而无法获取锁，则通过调用`__mutex_lock_slowpath()`进入慢速路径：

```
static __always_inline bool __mutex_trylock_fast(struct mutex *lock)
{
  unsigned long curr = (unsigned long)current;

  if (!atomic_long_cmpxchg_acquire(&lock->owner, 0UL, curr))
    return true;

  return false;
}
```

如果可用，此函数被设计为原子方式获取锁。它调用`atomic_long_cmpxchg_acquire()`宏，该宏尝试将当前线程分配为互斥锁的所有者；如果互斥锁可用，则此操作将成功，此时函数返回`true`。如果某些其他线程拥有互斥锁，则此函数将失败并返回`false`。在失败时，调用线程将进入慢速路径例程。

传统上，慢速路径的概念一直是将调用任务置于休眠状态，同时等待锁变为可用。然而，随着多核 CPU 的出现，人们对可伸缩性和性能的需求不断增长，因此为了实现可伸缩性，互斥锁慢速路径实现已经重新设计，引入了称为**乐观自旋**的优化，也称为**中间路径**，可以显著提高性能。

乐观自旋的核心思想是将竞争任务推入轮询或自旋，而不是在发现互斥体所有者正在运行时休眠。一旦互斥体变为可用（因为发现所有者正在运行，所以预计会更快），就假定自旋任务始终可以比互斥体等待列表中的挂起或休眠任务更快地获取它。但是，只有当没有其他处于就绪状态的更高优先级任务时，才有可能进行这种自旋。有了这个特性，自旋任务更有可能是缓存热点，从而产生可预测的执行，从而产生明显的性能改进：

```
static int __sched
__mutex_lock(struct mutex *lock, long state, unsigned int subclass,
       struct lockdep_map *nest_lock, unsigned long ip)
{
  return __mutex_lock_common(lock, state, subclass, nest_lock, ip, NULL,     false);
}

...
...
...

static noinline void __sched __mutex_lock_slowpath(struct mutex *lock) 
{
        __mutex_lock(lock, TASK_UNINTERRUPTIBLE, 0, NULL, _RET_IP_); 
}

static noinline int __sched
__mutex_lock_killable_slowpath(struct mutex *lock)
{
  return __mutex_lock(lock, TASK_KILLABLE, 0, NULL, _RET_IP_);
}

static noinline int __sched
__mutex_lock_interruptible_slowpath(struct mutex *lock)
{
  return __mutex_lock(lock, TASK_INTERRUPTIBLE, 0, NULL, _RET_IP_);
}

```

`__mutex_lock_common()`函数包含一个带有乐观自旋的慢路径实现；这个例程由所有互斥锁定函数的睡眠变体调用，带有适当的标志作为参数。这个函数首先尝试通过与互斥体关联的可取消的 mcs 自旋锁（互斥体结构中的 osq 字段）实现乐观自旋来获取互斥体。当调用者任务无法通过乐观自旋获取互斥体时，作为最后的手段，这个函数切换到传统的慢路径，导致调用者任务进入睡眠，并排队进入互斥体的`wait_list`，直到被解锁路径唤醒。

# 调试检查和验证

错误使用互斥操作可能导致死锁、排除失败等。为了检测和防止这种可能发生的情况，互斥子系统配备了适当的检查或验证，这些检查默认情况下是禁用的，可以通过在内核构建过程中选择配置选项`CONFIG_DEBUG_MUTEXES=y`来启用。

以下是受检的调试代码强制执行的检查列表：

+   互斥体在给定时间点只能由一个任务拥有

+   互斥体只能由有效所有者释放（解锁），任何尝试由不拥有锁的上下文释放互斥体的尝试都将失败

+   递归锁定或解锁尝试将失败

+   互斥体只能通过初始化调用进行初始化，并且任何对*memset*互斥体的尝试都不会成功

+   调用者任务可能不会在持有互斥锁的情况下退出

+   不得释放包含持有的锁的动态内存区域

+   互斥体只能初始化一次，任何尝试重新初始化已初始化的互斥体都将失败

+   互斥体可能不会在硬/软中断上下文例程中使用

死锁可能由许多原因触发，例如内核代码的执行模式和锁定调用的粗心使用。例如，让我们考虑这样一种情况：并发代码路径需要通过嵌套锁定函数来拥有*L[1]*和*L[2]*锁。必须确保所有需要这些锁的内核函数都被编程为以相同的顺序获取它们。当没有严格强制执行这样的顺序时，总会有两个不同的函数尝试以相反的顺序锁定*L1*和*L2*的可能性，这可能会触发锁反转死锁，当这些函数并发执行时。

内核锁验证器基础设施已经实施，以检查并证明在内核运行时观察到的任何锁定模式都不会导致死锁。此基础设施打印与锁定模式相关的数据，例如：

+   获取点跟踪、函数名称的符号查找和系统中所有持有的锁列表

+   所有者跟踪

+   检测自递归锁并打印所有相关信息

+   检测锁反转死锁并打印所有受影响的锁和任务

可以通过在内核构建过程中选择`CONFIG_PROVE_LOCKING=y`来启用锁验证器。

# 等待/伤害互斥体

如前一节所讨论的，在内核函数中无序的嵌套锁定可能会导致锁反转死锁的风险，内核开发人员通过定义嵌套锁定顺序的规则并通过锁验证器基础设施执行运行时检查来避免这种情况。然而，存在动态锁定顺序的情况，无法将嵌套锁定调用硬编码或根据预设规则强加。

一个这样的用例与 GPU 缓冲区有关；这些缓冲区应该由各种系统实体拥有和访问，比如 GPU 硬件、GPU 驱动程序、用户模式应用程序和其他与视频相关的驱动程序。用户模式上下文可以以任意顺序提交 dma 缓冲区进行处理，GPU 硬件可以在任意时间处理它们。如果使用锁来控制缓冲区的所有权，并且必须同时操作多个缓冲区，则无法避免死锁。等待/伤害互斥锁旨在促进嵌套锁的动态排序，而不会导致锁反转死锁。这是通过强制争用的上下文*伤害*来实现的，意味着强制它释放持有的锁。

例如，假设有两个缓冲区，每个缓冲区都受到锁的保护，进一步考虑两个线程，比如`T[1]`和`T[2]`，它们通过以相反的顺序尝试锁定来寻求对缓冲区的所有权：

```
Thread T1       Thread T2
===========    ==========
lock(bufA);     lock(bufB);
lock(bufB);     lock(bufA);
 ....            ....
 ....            ....
unlock(bufB);   unlock(bufA);
unlock(bufA);   unlock(bufB);
```

`T[1]`和`T[2]`的并发执行可能导致每个线程等待另一个持有的锁，从而导致死锁。等待/伤害互斥锁通过让*首先抓住锁的线程*保持睡眠，等待嵌套锁可用来防止这种情况。另一个线程被*伤害*，导致它释放其持有的锁并重新开始。假设`T[1]`在`bufA`上获得锁之前，`T[2]`可以在`bufB`上获得锁。`T[1]`将被视为*首先到达的线程*，并被放到`bufB`的锁上睡眠，`T[2]`将被伤害，导致它释放`bufB`上的锁并重新开始。这样可以避免死锁，当`T[1]`释放持有的锁时，`T[2]`将重新开始。

# 操作接口：

等待/伤害互斥锁通过在头文件`<linux/ww_mutex.h>`中定义的`struct ww_mutex`来表示：

```
struct ww_mutex {
       struct mutex base;
       struct ww_acquire_ctx *ctx;
# ifdef CONFIG_DEBUG_MUTEXES
       struct ww_class *ww_class;
#endif
};
```

使用等待/伤害互斥锁的第一步是定义一个*类*，这是一种表示一组锁的机制。当并发任务争夺相同的锁时，它们必须通过指定这个类来这样做。

可以使用宏定义一个类：

```
static DEFINE_WW_CLASS(bufclass);
```

声明的每个类都是`struct ww_class`类型的实例，并包含一个原子计数器`stamp`，用于记录哪个竞争任务*首先到达*的序列号。其他字段由内核的锁验证器用于验证等待/伤害机制的正确使用。

```
struct ww_class {
       atomic_long_t stamp;
       struct lock_class_key acquire_key;
       struct lock_class_key mutex_key;
       const char *acquire_name;
       const char *mutex_name;
};
```

每个竞争的线程在尝试嵌套锁定调用之前必须调用`ww_acquire_init()`。这通过分配一个序列号来设置上下文以跟踪锁。

```
/**
 * ww_acquire_init - initialize a w/w acquire context
 * @ctx: w/w acquire context to initialize
 * @ww_class: w/w class of the context
 *
 * Initializes a context to acquire multiple mutexes of the given w/w class.
 *
 * Context-based w/w mutex acquiring can be done in any order whatsoever 
 * within a given lock class. Deadlocks will be detected and handled with the
 * wait/wound logic.
 *
 * Mixing of context-based w/w mutex acquiring and single w/w mutex locking 
 * can result in undetected deadlocks and is so forbidden. Mixing different
 * contexts for the same w/w class when acquiring mutexes can also result in 
 * undetected deadlocks, and is hence also forbidden. Both types of abuse will 
 * will be caught by enabling CONFIG_PROVE_LOCKING.
 *
 */
   void ww_acquire_init(struct ww_acquire_ctx *ctx, struct ww_clas *ww_class);
```

一旦上下文设置和初始化，任务可以开始使用`ww_mutex_lock()`或`ww_mutex_lock_interruptible()`调用获取锁：

```
/**
 * ww_mutex_lock - acquire the w/w mutex
 * @lock: the mutex to be acquired
 * @ctx: w/w acquire context, or NULL to acquire only a single lock.
 *
 * Lock the w/w mutex exclusively for this task.
 *
 * Deadlocks within a given w/w class of locks are detected and handled with 
 * wait/wound algorithm. If the lock isn't immediately available this function
 * will either sleep until it is(wait case) or it selects the current context
 * for backing off by returning -EDEADLK (wound case).Trying to acquire the
 * same lock with the same context twice is also detected and signalled by
 * returning -EALREADY. Returns 0 if the mutex was successfully acquired.
 *
 * In the wound case the caller must release all currently held w/w mutexes  
 * for the given context and then wait for this contending lock to be 
 * available by calling ww_mutex_lock_slow. 
 *
 * The mutex must later on be released by the same task that
 * acquired it. The task may not exit without first unlocking the mutex.Also,
 * kernel memory where the mutex resides must not be freed with the mutex 
 * still locked. The mutex must first be initialized (or statically defined) b
 * before it can be locked. memset()-ing the mutex to 0 is not allowed. The
 * mutex must be of the same w/w lock class as was used to initialize the 
 * acquired context.
 * A mutex acquired with this function must be released with ww_mutex_unlock.
 */
    int ww_mutex_lock(struct ww_mutex *lock, struct ww_acquire_ctx *ctx);

/**
 * ww_mutex_lock_interruptible - acquire the w/w mutex, interruptible
 * @lock: the mutex to be acquired
 * @ctx: w/w acquire context
 *
 */
   int  ww_mutex_lock_interruptible(struct ww_mutex *lock, 
                                             struct  ww_acquire_ctx *ctx);
```

当任务抓取与类相关的所有嵌套锁（使用这些锁定例程中的任何一个）时，需要使用函数`ww_acquire_done()`通知所有权的获取。这个调用标志着获取阶段的结束，任务可以继续处理共享数据：

```
/**
 * ww_acquire_done - marks the end of the acquire phase
 * @ctx: the acquire context
 *
 * Marks the end of the acquire phase, any further w/w mutex lock calls using
 * this context are forbidden.
 *
 * Calling this function is optional, it is just useful to document w/w mutex
 * code and clearly designated the acquire phase from actually using the 
 * locked data structures.
 */
 void ww_acquire_done(struct ww_acquire_ctx *ctx);
```

当任务完成对共享数据的处理时，可以通过调用`ww_mutex_unlock()`例程开始释放所有持有的锁。一旦所有锁都被释放，*上下文*必须通过调用`ww_acquire_fini()`来释放：

```
/**
 * ww_acquire_fini - releases a w/w acquire context
 * @ctx: the acquire context to free
 *
 * Releases a w/w acquire context. This must be called _after_ all acquired 
 * w/w mutexes have been released with ww_mutex_unlock.
 */
    void ww_acquire_fini(struct ww_acquire_ctx *ctx);
```

# 信号量

在 2.6 内核早期版本之前，信号量是睡眠锁的主要形式。典型的信号量实现包括一个计数器、等待队列和一组可以原子地增加/减少计数器的操作。

当信号量用于保护共享资源时，其计数器被初始化为大于零的数字，被视为解锁状态。寻求访问共享资源的任务首先通过对信号量进行减操作来开始。此调用检查信号量计数器；如果发现大于零，则将计数器减一，并返回成功。但是，如果计数器为零，则减操作将调用者任务置于睡眠状态，直到计数器增加到大于零为止。

这种简单的设计提供了很大的灵活性，允许信号量适应和应用于不同的情况。例如，对于需要在任何时候对特定数量的任务可访问的资源的情况，信号量计数可以初始化为需要访问的任务数量，比如 10，这允许最多 10 个任务在任何时候访问共享资源。对于其他情况，例如需要互斥访问共享资源的任务数量，信号量计数可以初始化为 1，导致在任何给定时刻最多一个任务访问资源。

信号量结构及其接口操作在内核头文件`<include/linux/semaphore.h>`中声明：

```
struct semaphore {
        raw_spinlock_t     lock;
        unsigned int       count;
        struct list_head   wait_list;
};
```

自旋锁（`lock`字段）用作对`count`的保护，也就是说，信号量操作（增加/减少）被编程为在操作`count`之前获取`lock`。`wait_list`用于将任务排队等待，直到信号量计数增加到零以上为止。

信号量可以通过宏`DEFINE_SEMAPHORE(s)`声明和初始化为 1。

信号量也可以通过以下方式动态初始化为任何正数：

```
void sema_init(struct semaphore *sem, int val)
```

以下是一系列操作接口及其简要描述。命名约定为`down_xxx()`的例程尝试减少信号量，并且可能是阻塞调用（除了`down_trylock()`），而例程`up()`增加信号量并且总是成功：

```
/**
 * down_interruptible - acquire the semaphore unless interrupted
 * @sem: the semaphore to be acquired
 *
 * Attempts to acquire the semaphore.  If no more tasks are allowed to
 * acquire the semaphore, calling this function will put the task to sleep.
 * If the sleep is interrupted by a signal, this function will return -EINTR.
 * If the semaphore is successfully acquired, this function returns 0.
 */
 int down_interruptible(struct semaphore *sem); /**
 * down_killable - acquire the semaphore unless killed
 * @sem: the semaphore to be acquired
 *
 * Attempts to acquire the semaphore.  If no more tasks are allowed to
 * acquire the semaphore, calling this function will put the task to sleep.
 * If the sleep is interrupted by a fatal signal, this function will return
 * -EINTR.  If the semaphore is successfully acquired, this function returns
 * 0.
 */
 int down_killable(struct semaphore *sem); /**
 * down_trylock - try to acquire the semaphore, without waiting
 * @sem: the semaphore to be acquired
 *
 * Try to acquire the semaphore atomically.  Returns 0 if the semaphore has
 * been acquired successfully or 1 if it it cannot be acquired.
 *
 */
 int down_trylock(struct semaphore *sem); /**
 * down_timeout - acquire the semaphore within a specified time
 * @sem: the semaphore to be acquired
 * @timeout: how long to wait before failing
 *
 * Attempts to acquire the semaphore.  If no more tasks are allowed to
 * acquire the semaphore, calling this function will put the task to sleep.
 * If the semaphore is not released within the specified number of jiffies,
 * this function returns -ETIME.  It returns 0 if the semaphore was acquired.
 */
 int down_timeout(struct semaphore *sem, long timeout); /**
 * up - release the semaphore
 * @sem: the semaphore to release
 *
 * Release the semaphore.  Unlike mutexes, up() may be called from any
 * context and even by tasks which have never called down().
 */
 void up(struct semaphore *sem);
```

与互斥锁实现不同，信号量操作不支持调试检查或验证；这个约束是由于它们固有的通用设计，允许它们被用作排他锁、事件通知计数器等。自从互斥锁进入内核（2.6.16）以来，信号量不再是排他性的首选，信号量作为锁的使用大大减少，而对于其他目的，内核有备用接口。大部分使用信号量的内核代码已经转换为互斥锁，只有少数例外。然而，信号量仍然存在，并且至少在所有使用它们的内核代码转换为互斥锁或其他合适的接口之前，它们可能会继续存在。

# 读写信号量

该接口是睡眠读写排他的实现，作为自旋的替代。读写信号量由`struct rw_semaphore`表示，在内核头文件`<linux/rwsem.h>`中声明：

```
struct rw_semaphore {
        atomic_long_t count;
        struct list_head wait_list;
        raw_spinlock_t wait_lock;
#ifdef CONFIG_RWSEM_SPIN_ON_OWNER
       struct optimistic_spin_queue osq; /* spinner MCS lock */
       /*
       * Write owner. Used as a speculative check to see
       * if the owner is running on the cpu.
       */
      struct task_struct *owner;
#endif
#ifdef CONFIG_DEBUG_LOCK_ALLOC
     struct lockdep_map dep_map;
#endif
};
```

该结构与互斥锁的结构相同，并且设计为支持通过`osq`进行乐观自旋；它还通过内核的*lockdep*包括调试支持。`Count`用作排他计数器，设置为 1，允许最多一个写者在某一时刻拥有锁。这是因为互斥仅在竞争写者之间执行，并且任意数量的读者可以同时共享读锁。`wait_lock`是一个自旋锁，用于保护信号量`wait_list`。

`rw_semaphore`可以通过`DECLARE_RWSEM(name)`静态实例化和初始化，也可以通过`init_rwsem(sem)`动态初始化。

与 rw 自旋锁一样，该接口也为读者和写者路径的锁获取提供了不同的例程。以下是接口操作的列表：

```
/* reader interfaces */
   void down_read(struct rw_semaphore *sem);
   void up_read(struct rw_semaphore *sem);
/* trylock for reading -- returns 1 if successful, 0 if contention */
   int down_read_trylock(struct rw_semaphore *sem);
   void up_read(struct rw_semaphore *sem);

/* writer Interfaces */
   void down_write(struct rw_semaphore *sem);
   int __must_check down_write_killable(struct rw_semaphore *sem);

/* trylock for writing -- returns 1 if successful, 0 if contention */
   int down_write_trylock(struct rw_semaphore *sem); 
   void up_write(struct rw_semaphore *sem);
/* downgrade write lock to read lock */
   void downgrade_write(struct rw_semaphore *sem); 

/* check if rw-sem is currently locked */  
   int rwsem_is_locked(struct rw_semaphore *sem);

```

这些操作是在源文件`<kernel/locking/rwsem.c>`中实现的；代码相当自解释，我们不会进一步讨论它。

# 序列锁

传统的读写锁设计为读者优先，它们可能导致写入任务等待非确定性的持续时间，这在具有时间敏感更新的共享数据上可能不合适。这就是顺序锁派上用场的地方，因为它旨在提供对共享资源的快速和无锁访问。当需要保护的资源较小且简单，写访问快速且不频繁时，顺序锁是最佳选择，因为在内部，顺序锁会退回到自旋锁原语。

顺序锁引入了一个特殊的计数器，每当写入者获取顺序锁时都会增加该计数器，并附带一个自旋锁。写入者完成后，释放自旋锁并再次增加计数器，为其他写入者打开访问。对于读取，有两种类型的读取者：序列读取者和锁定读取者。**序列读取者**在进入临界区之前检查计数器，然后在不阻塞任何写入者的情况下在临界区结束时再次检查。如果计数器保持不变，这意味着在读取期间没有写入者访问该部分，但如果在部分结束时计数器增加，则表明写入者已访问，这要求读取者重新读取临界部分以获取更新的数据。**锁定读取者**会获得锁并在进行时阻塞其他读取者和写入者；当另一个锁定读取者或写入者进行时，它也会等待。

序列锁由以下类型表示：

```
typedef struct {
        struct seqcount seqcount;
        spinlock_t lock;
} seqlock_t;
```

我们可以使用以下宏静态初始化序列锁：

```
#define DEFINE_SEQLOCK(x) \
               seqlock_t x = __SEQLOCK_UNLOCKED(x)
```

实际初始化是使用`__SEQLOCK_UNLOCKED(x)`来完成的，其定义在这里：

```
#define __SEQLOCK_UNLOCKED(lockname)                 \
       {                                               \
               .seqcount = SEQCNT_ZERO(lockname),     \
               .lock = __SPIN_LOCK_UNLOCKED(lockname)   \
       }
```

要动态初始化序列锁，我们需要使用`seqlock_init`宏，其定义如下：

```
  #define seqlock_init(x)                                     \
       do {                                                   \
               seqcount_init(&(x)->seqcount);                 \
               spin_lock_init(&(x)->lock);                    \
       } while (0)
```

# API

Linux 提供了许多用于使用序列锁的 API，这些 API 在`</linux/seqlock.h>`中定义。以下是一些重要的 API：

```
static inline void write_seqlock(seqlock_t *sl)
{
        spin_lock(&sl->lock);
        write_seqcount_begin(&sl->seqcount);
}

static inline void write_sequnlock(seqlock_t *sl)
{
        write_seqcount_end(&sl->seqcount);
        spin_unlock(&sl->lock);
}

static inline void write_seqlock_bh(seqlock_t *sl)
{
        spin_lock_bh(&sl->lock);
        write_seqcount_begin(&sl->seqcount);
}

static inline void write_sequnlock_bh(seqlock_t *sl)
{
        write_seqcount_end(&sl->seqcount);
        spin_unlock_bh(&sl->lock);
}

static inline void write_seqlock_irq(seqlock_t *sl)
{
        spin_lock_irq(&sl->lock);
        write_seqcount_begin(&sl->seqcount);
}

static inline void write_sequnlock_irq(seqlock_t *sl)
{
        write_seqcount_end(&sl->seqcount);
        spin_unlock_irq(&sl->lock);
}

static inline unsigned long __write_seqlock_irqsave(seqlock_t *sl)
{
        unsigned long flags;

        spin_lock_irqsave(&sl->lock, flags);
        write_seqcount_begin(&sl->seqcount);
        return flags;
}
```

以下两个函数用于通过开始和完成读取部分：

```
static inline unsigned read_seqbegin(const seqlock_t *sl)
{
        return read_seqcount_begin(&sl->seqcount);
}

static inline unsigned read_seqretry(const seqlock_t *sl, unsigned start)
{
        return read_seqcount_retry(&sl->seqcount, start);
}
```

# 完成锁

**完成锁**是一种有效的方式来实现代码同步，如果需要一个或多个执行线程等待某个事件的完成，比如等待另一个进程达到某个点或状态。完成锁可能比信号量更受欢迎，原因有几点：多个执行线程可以等待完成，并且使用`complete_all()`，它们可以一次性全部释放。这比信号量唤醒多个线程要好得多。其次，如果等待线程释放同步对象，信号量可能导致竞争条件；使用完成时，这个问题就不存在。

通过包含`<linux/completion.h>`并创建一个`struct completion`类型的变量来使用完成结构，这是一个用于维护完成状态的不透明结构。它使用 FIFO 来排队等待完成事件的线程：

```
struct completion {
        unsigned int done;
        wait_queue_head_t wait;
};
```

完成基本上包括初始化完成结构，通过`wait_for_completion()`调用的任何变体等待，最后通过`complete()`或`complete_all()`调用发出完成信号。在其生命周期中还有函数来检查完成的状态。

# 初始化

以下宏可用于静态声明和初始化完成结构：

```
#define DECLARE_COMPLETION(work) \
       struct completion work = COMPLETION_INITIALIZER(work)
```

以下内联函数将初始化动态创建的完成结构：

```
static inline void init_completion(struct completion *x)
{
        x->done = 0;
        init_waitqueue_head(&x->wait);
}
```

以下内联函数将用于在需要重用时重新初始化完成结构。这可以在`complete_all()`之后使用：

```
static inline void reinit_completion(struct completion *x)
{
        x->done = 0;
}
```

# 等待完成

如果任何线程需要等待任务完成，它将在初始化的完成结构上调用`wait_for_completion（）`。如果`wait_for_completion`操作发生在调用`complete（）`或`complete_all（）`之后，则线程将简单地继续，因为它想要等待的原因已经得到满足；否则，它将等待直到`complete（）`被发出信号。对于`wait_for_completion（）`调用有可用的变体：

```
extern void wait_for_completion_io(struct completion *);
extern int wait_for_completion_interruptible(struct completion *x);
extern int wait_for_completion_killable(struct completion *x);
extern unsigned long wait_for_completion_timeout(struct completion *x,
                                                   unsigned long timeout);
extern unsigned long wait_for_completion_io_timeout(struct completion *x,
                                                    unsigned long timeout);
extern long wait_for_completion_interruptible_timeout(
        struct completion *x, unsigned long timeout);
extern long wait_for_completion_killable_timeout(
        struct completion *x, unsigned long timeout);
extern bool try_wait_for_completion(struct completion *x);
extern bool completion_done(struct completion *x);

extern void complete(struct completion *);
extern void complete_all(struct completion *);
```

# 完成信号

希望发出完成预期任务的执行线程调用`complete（）`向等待的线程发出信号，以便它可以继续。线程将按照它们排队的顺序被唤醒。在有多个等待者的情况下，它调用`complete_all（）`：

```
void complete(struct completion *x)
{
        unsigned long flags;

        spin_lock_irqsave(&x->wait.lock, flags);
        if (x->done != UINT_MAX)
                x->done++;
        __wake_up_locked(&x->wait, TASK_NORMAL, 1);
        spin_unlock_irqrestore(&x->wait.lock, flags);
}
EXPORT_SYMBOL(complete);
void complete_all(struct completion *x)
{
        unsigned long flags;

        spin_lock_irqsave(&x->wait.lock, flags);
        x->done = UINT_MAX;
        __wake_up_locked(&x->wait, TASK_NORMAL, 0);
        spin_unlock_irqrestore(&x->wait.lock, flags);
}
EXPORT_SYMBOL(complete_all);
```

# 总结

在本章中，我们不仅了解了内核提供的各种保护和同步机制，还试图欣赏这些选项的有效性，以及它们的各种功能和缺陷。本章的收获必须是内核处理这些不同复杂性以提供数据保护和同步的坚韧性。另一个值得注意的事实是内核在处理这些问题时保持了编码的便利性和设计的优雅。

在我们的下一章中，我们将看一下中断如何由内核处理的另一个关键方面。
