# 精通 C++ 编程（三）

> 原文：[`annas-archive.org/md5/0E32826EC8D4CA7BCD89E795AD6CBF05`](https://annas-archive.org/md5/0E32826EC8D4CA7BCD89E795AD6CBF05)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：多线程编程和进程间通信

本章将涵盖以下主题：

+   POSIX pthreads 简介

+   使用 pthreads 库创建线程

+   线程创建和自我识别

+   启动线程

+   停止线程

+   使用 C++线程支持库

+   数据竞争和线程同步

+   加入和分离线程

+   从线程发送信号

+   向线程传递参数

+   死锁和解决方案

+   并发

+   Future、promise、`packaged_task`等

+   使用线程支持库进行并发

+   并发应用程序中的异常处理

让我们通过本章讨论的一些有趣且易于理解的示例来学习这些主题。

# POSIX pthreads 简介

Unix、Linux 和 macOS 在很大程度上符合 POSIX 标准。**Unix 可移植操作系统接口**（**POSIX**）是一个 IEEE 标准，它帮助所有 Unix 和类 Unix 操作系统，即 Linux 和 macOS，通过一个统一的接口进行通信。

有趣的是，POSIX 也受到符合 POSIX 标准的工具的支持--Cygwin、MinGW 和 Windows 子系统 for Linux--它们提供了在 Windows 平台上的伪 Unix 样运行时和开发环境。

请注意，pthread 是一个在 Unix、Linux 和 macOS 中使用的符合 POSIX 标准的 C 库。从 C++11 开始，C++通过 C++线程支持库和并发库本地支持线程。在本章中，我们将了解如何以面向对象的方式使用 pthreads、线程支持和并发库。此外，我们将讨论使用本机 C++线程支持和并发库与使用 POSIX pthreads 或其他第三方线程框架的优点。

# 使用 pthreads 库创建线程

让我们直奔主题。你需要了解我们将讨论的 pthread API，开始动手。首先，这个函数用于创建一个新线程：

```cpp
 #include <pthread.h>
 int pthread_create(
              pthread_t *thread,
              const pthread_attr_t *attr,
              void *(*start_routine)(void*),
              void *arg
 )
```

以下表格简要解释了前面函数中使用的参数：

| **API 参数** | **注释** |
| --- | --- |
| `pthread_t *thread` | 线程句柄指针 |
| `pthread_attr_t *attr` | 线程属性 |
| `void *(*start_routine)(void*)` | 线程函数指针 |
| `void * arg` | 线程参数 |

此函数阻塞调用线程，直到第一个参数中传递的线程退出，如下所示：

```cpp
int pthread_join ( pthread_t *thread, void **retval )
```

以下表格简要描述了前面函数中的参数：

| **API 参数** | **注释** |
| --- | --- |
| `pthread_t thread` | 线程句柄 |
| `void **retval` | 输出参数，指示线程过程的退出代码 |

接下来的函数应该在线程上下文中使用。在这里，`retval`是调用此函数的线程的退出代码：

```cpp
int pthread_exit ( void *retval )
```

这个函数中使用的参数如下：

| **API 参数** | **注释** |
| --- | --- |
| `void *retval` | 线程过程的退出代码 |

以下函数返回线程 ID：

```cpp
pthread_t pthread_self(void)
```

让我们编写我们的第一个多线程应用程序：

```cpp
#include <pthread.h>
#include <iostream>

using namespace std;

void* threadProc ( void *param ) {
  for (int count=0; count<3; ++count)
    cout << "Message " << count << " from " << pthread_self()
         << endl;
  pthread_exit(0);
}

int main() {
  pthread_t thread1, thread2, thread3;

  pthread_create ( &thread1, NULL, threadProc, NULL );
  pthread_create ( &thread2, NULL, threadProc, NULL );
  pthread_create ( &thread3, NULL, threadProc, NULL );

  pthread_join( thread1, NULL );
  pthread_join( thread2, NULL );

  pthread_join( thread3, NULL );

  return 0;

}
```

# 如何编译和运行

可以使用以下命令编译该程序：

```cpp
g++ main.cpp -lpthread
```

如您所见，我们需要动态链接 POSIX `pthread`库。

查看以下截图，可视化多线程程序的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/3a98ad57-5892-4cb5-bfaf-fe5e9a44fb81.png)

在 ThreadProc 中编写的代码在线程上下文中运行。前面的程序总共有四个线程，包括主线程。我使用`pthread_join`阻塞了主线程，强制它等待其他三个线程先完成任务，否则主线程会在它们之前退出。当主线程退出时，应用程序也会退出，这会过早地销毁新创建的线程。

尽管我们按照相应的顺序创建了`thread1`、`thread2`和`thread3`，但不能保证它们会按照创建的确切顺序启动。

操作系统调度程序根据操作系统调度程序使用的算法决定必须启动线程的顺序。有趣的是，线程启动的顺序可能在同一系统的不同运行中有所不同。

# C++是否原生支持线程？

从 C++11 开始，C++确实原生支持线程，并且通常被称为 C++线程支持库。C++线程支持库提供了对 POSIX pthreads C 库的抽象。随着时间的推移，C++原生线程支持已经得到了很大的改进。

我强烈建议您使用 C++原生线程而不是 pthread。C++线程支持库在所有平台上都受支持，因为它是标准 C++的正式部分，而不是仅在 Unix、Linux 和 macOS 上直接支持的 POSIX `pthread`库。

最好的部分是 C++17 中的线程支持已经成熟到了一个新的水平，并且准备在 C++20 中达到下一个水平。因此，考虑在项目中使用 C++线程支持库是一个不错的主意。

# 如何使用本机 C++线程功能编写多线程应用程序

有趣的是，使用 C++线程支持库编写多线程应用程序非常简单：

```cpp
#include <thread>
using namespace std;
thread instance ( thread_procedure )
```

`thread`类是在 C++11 中引入的。此函数可用于创建线程。在 POSIX `pthread`库中，此函数的等效函数是`pthread_create`。

| **参数** | **注释** |
| --- | --- |
| `thread_procedure` | 线程函数指针 |

现在稍微了解一下以下代码中返回线程 ID 的参数：

```cpp
this_thread::get_id ()
```

此函数相当于 POSIX `pthread`库中的`pthread_self()`函数。请参考以下代码：

```cpp
thread::join()
```

`join()`函数用于阻塞调用线程或主线程，以便等待已加入的线程完成其任务。这是一个非静态函数，因此必须在线程对象上调用它。

让我们看看如何使用上述函数来基于 C++编写一个简单的多线程程序。请参考以下程序：

```cpp
#include <thread>
#include <iostream>
using namespace std;

void threadProc() {
  for( int count=0; count<3; ++count ) {
    cout << "Message => "
         << count
         << " from "
         << this_thread::get_id()
         << endl;
  }
}

int main() {
  thread thread1 ( threadProc );
  thread thread2 ( threadProc );
  thread thread3 ( threadProc );

  thread1.join();
  thread2.join();
  thread3.join();

  return 0;
}
```

C++版本的多线程程序看起来比 C 版本简单得多，更清晰。

# 如何编译和运行

以下命令将帮助您编译程序：

```cpp
g++ main.cpp -std=c++17 -lpthread
```

在上一个命令中，`-std=c++17`指示 C++编译器启用 C++17 特性；但是，该程序将在支持 C++11 的任何 C++编译器上编译，您只需要用`c++11`替换`c++17`。

程序的输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/9d2d2907-bab3-470d-aa7d-ba7e3398a604.png)

在上述屏幕截图中以`140`开头的所有数字都是线程 ID。由于我们创建了三个线程，`pthread`库分别分配了三个唯一的线程 ID。如果您真的很想找到操作系统分配的线程 ID，您将需要在 Linux 中发出以下命令，同时应用程序正在运行：

```cpp
 ps -T -p <process-id>
```

也许会让你惊讶的是，`pthread`库分配的线程 ID 与操作系统分配的线程 ID 是不同的。因此，从技术上讲，`pthread`库分配的线程 ID 只是一个与操作系统分配的线程 ID 不同的线程句柄 ID。您可能还想考虑的另一个有趣工具是`top`命令，用于探索进程中的线程：

```cpp
 top -H -p <process-id>
```

这两个命令都需要您多线程应用程序的进程 ID。以下命令将帮助您找到此 ID：

```cpp
ps -ef | grep -i <your-application-name>
```

您还可以在 Linux 中使用`htop`实用程序。

如果您想以编程方式获取操作系统分配的线程 ID，您可以在 Linux 中使用以下函数：

```cpp
#include <sys/types.h>
pid_t gettid(void)
```

但是，如果您想编写一个可移植的应用程序，这并不推荐，因为这仅在 Unix 和 Linux 中受支持。

# 以面向对象的方式使用 std::thread

如果您一直在寻找类似于 Java 或 Qt 线程中的`Thread`类的 C++线程类，我相信您会觉得这很有趣：

```cpp
#include <iostream>
#include <thread>
using namespace std;

class Thread {
private:
      thread *pThread;
      bool stopped;
      void run();
public:
      Thread();
      ~Thread();

      void start();
      void stop();
      void join();
      void detach();
};
```

这是一个包装类，作为本书中 C++线程支持库的便利类。`Thread::run()`方法是我们自定义的线程过程。由于我不希望客户端代码直接调用`Thread::run()`方法，所以我将 run 方法声明为`private`。为了启动线程，客户端代码必须在`thread`对象上调用 start 方法。

对应的`Thread.cpp`源文件如下：

```cpp
#include "Thread.h"

Thread::Thread() {
     pThread = NULL;
     stopped = false;
}

Thread::~Thread() {
     delete pThread;
     pThread = NULL;
}

void Thread::run() {

     while ( ! stopped ) {
         cout << this_thread::get_id() << endl;
         this_thread::sleep_for ( 1s );
     }
     cout << "\nThread " << this_thread::get_id()
          << " stopped as requested." << endl;
     return;
}

void Thread::stop() {
    stopped = true;
}

void Thread::start() {
    pThread = new thread( &Thread::run, this );
}

void Thread::join() {
     pThread->join();
}

void Thread::detach() {
     pThread->detach();
}
```

从之前的`Thread.cpp`源文件中，你会了解到可以通过调用`stop`方法在需要时停止线程。这是一个简单而体面的实现；然而，在投入生产之前，还有许多其他边缘情况需要处理。尽管如此，这个实现已经足够好，可以理解本书中的线程概念。

很好，让我们看看我们的`Thread`类在`main.cpp`中如何使用：

```cpp
#include "Thread.h"

int main() {

      Thread thread1, thread2, thread3;

      thread1.start();
      thread2.start();
      thread3.start();

      thread1.detach();
      thread2.detach();
      thread3.detach();

      this_thread::sleep_for ( 3s );

      thread1.stop();
      thread2.stop();
      thread3.stop();

      this_thread::sleep_for ( 3s );

      return 0;
}
```

我已经创建了三个线程，`Thread`类的设计方式是，只有在调用`start`函数时线程才会启动。分离的线程在后台运行；通常，如果要使线程成为守护进程，就需要将线程分离。然而，在应用程序退出之前，这些线程会被安全地停止。

# 如何编译和运行

以下命令可帮助编译程序：

```cpp
g++ Thread.cpp main.cpp -std=c++17 -o threads.exe -lpthread
```

程序的输出将如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/18ee2225-4dde-48d5-b3de-6cd417e6424a.png)

哇！我们可以按设计启动和停止线程，而且还是面向对象的方式。

# 你学到了什么？

让我们试着回顾一下我们到目前为止讨论过的内容：

+   你学会了如何使用 POSIX 的`pthread` C 库编写多线程应用程序

+   C++编译器从 C++11 开始原生支持线程

+   你学会了常用的基本 C++线程支持库 API

+   你学会了如何使用 C++线程支持库编写多线程应用程序

+   现在你知道为什么应该考虑使用 C++线程支持库而不是`pthread` C 库了

+   C++线程支持库是跨平台的，不像 POSIX 的`pthread`库

+   你知道如何以面向对象的方式使用 C++线程支持库

+   你知道如何编写不需要同步的简单多线程应用程序

# 同步线程

在理想的世界中，线程会提供更好的应用程序性能。但是，有时会发现应用程序性能因多个线程而下降并不罕见。这种性能问题可能并不真正与多个线程有关；真正的罪魁祸首可能是设计。过多地使用同步会导致许多与线程相关的问题，也会导致应用程序性能下降。

无锁线程设计不仅可以避免与线程相关的问题，还可以提高整体应用程序的性能。然而，在实际世界中，可能会有多个线程需要共享一个或多个公共资源。因此，需要同步访问或修改共享资源的关键代码部分。在特定情况下可以使用各种同步机制。在接下来的章节中，我们将逐一探讨一些有趣和实用的使用案例。

# 如果线程没有同步会发生什么？

当有多个线程在进程边界内共享一个公共资源时，可以使用互斥锁来同步代码的关键部分。互斥锁是一种互斥锁，只允许一个线程访问由互斥锁保护的关键代码块。让我们通过一个简单的例子来理解互斥锁应用的需求。

让我们使用一个`Bank Savings Account`类，允许三个简单的操作，即`getBalance`、`withdraw`和`deposit`。`Account`类可以实现如下所示的代码。为了演示目的，`Account`类以简单的方式设计，忽略了现实世界中所需的边界情况和验证。它被简化到`Account`类甚至不需要捕获帐号号码的程度。我相信有许多这样的要求被悄悄地忽略了简单性。别担心！我们的重点是学习 mutex，这里展示了一个例子：

```cpp
#include <iostream>
using namespace std;

class Account {
private:
  double balance;
public:
  Account( double );
  double getBalance( );
  void deposit ( double amount );
  void withdraw ( double amount ) ;
};
```

`Account.cpp`源文件如下：

```cpp
#include "Account.h"

Account::Account(double balance) {
  this->balance = balance;
}

double Account::getBalance() {
  return balance;
}

void Account::withdraw(double amount) {
  if ( balance < amount ) {
    cout << "Insufficient balance, withdraw denied." << endl;
    return;
  }

  balance = balance - amount;
}

void Account::deposit(double amount) {
  balance = balance + amount;
}
```

现在，让我们创建两个线程，即`DEPOSITOR`和`WITHDRAWER`。`DEPOSITOR`线程将存入 INR 2000.00，而`WITHDRAWER`线程将每隔一秒提取 INR 1000.00。根据我们的设计，`main.cpp`源文件可以实现如下：

```cpp
#include <thread>
#include "Account.h"
using namespace std;

enum ThreadType {
  DEPOSITOR,
  WITHDRAWER
};

Account account(5000.00);

void threadProc ( ThreadType typeOfThread ) {

  while ( 1 ) {
  switch ( typeOfThread ) {
    case DEPOSITOR: {
      cout << "Account balance before the deposit is "
           << account.getBalance() << endl;

      account.deposit( 2000.00 );

      cout << "Account balance after deposit is "
           << account.getBalance() << endl;
      this_thread::sleep_for( 1s );
}
break;

    case WITHDRAWER: {
      cout << "Account balance before withdrawing is "
           << account.getBalance() << endl;

      account.deposit( 1000.00 );
      cout << "Account balance after withdrawing is "
           << account.getBalance() << endl;
      this_thread::sleep_for( 1s );
    }
    break;
  }
  }
}

int main( ) {
  thread depositor ( threadProc, ThreadType::DEPOSITOR );
  thread withdrawer ( threadProc, ThreadType::WITHDRAWER );

  depositor.join();
  withdrawer.join();

  return 0;
}
```

如果您观察`main`函数，线程构造函数接受两个参数。第一个参数是您现在应该熟悉的线程过程。第二个参数是一个可选参数，如果您想要向线程函数传递一些参数，可以提供该参数。

# 如何编译和运行

可以使用以下命令编译该程序：

```cpp
g++ Account.cpp main.cpp -o account.exe -std=c++17 -lpthread
```

如果您按照指示的所有步骤进行了操作，您的代码应该可以成功编译。

现在是时候执行并观察我们的程序如何工作了！

不要忘记`WITHDRAWER`线程总是提取 INR 1000.00，而`DEPOSITOR`线程总是存入 INR 2000.00。以下输出首先传达了这一点。`WITHDRAWER`线程开始提取，然后是似乎已经存入了钱的`DEPOSITOR`线程。

尽管我们首先启动了`DEPOSITOR`线程，然后启动了`WITHDRAWER`线程，但看起来操作系统调度程序似乎首先安排了`WITHDRAWER`线程。不能保证这种情况总是会发生。

根据输出，`WITHDRAWER`线程和`DEPOSITOR`线程似乎偶然地交替进行工作。它们会继续这样一段时间。在某个时候，两个线程似乎会同时工作，这就是事情会崩溃的时候，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/92ea367f-1295-4dd9-bc8c-589659755cb9.png)

观察输出的最后四行非常有趣。看起来`WITHDRAWER`和`DEPOSITOR`线程都在检查余额，余额为 INR 9000.00。您可能注意到`DEPOSITOR`线程的打印语句存在不一致；根据`DEPOSITOR`线程，当前余额为 INR 9000.00。因此，当它存入 INR 2000.00 时，余额应该总共为 INR 11000.00。但实际上，存款后的余额为 INR 10000.00。这种不一致的原因是`WITHDRAWER`线程在`DEPOSITOR`线程存钱之前提取了 INR 1000.00。尽管从技术上看，余额似乎总共正确，但很快就会出现问题；这就是需要线程同步的时候。

# 让我们使用 mutex

现在，让我们重构`threadProc`函数并同步修改和访问余额的关键部分。我们需要一个锁定机制，只允许一个线程读取或写入余额。C++线程支持库提供了一个称为`mutex`的适当锁。`mutex`锁是一个独占锁，只允许一个线程在同一进程边界内操作关键部分代码。直到获得锁的线程释放`mutex`锁，所有其他线程都必须等待他们的轮次。一旦线程获得`mutex`锁，线程就可以安全地访问共享资源。

`main.cpp`文件可以重构如下；更改部分已用粗体标出：

```cpp
#include <iostream>
#include <thread>
#include <mutex>
#include "Account.h"
using namespace std;

enum ThreadType {
  DEPOSITOR,
  WITHDRAWER
};

mutex locker;

Account account(5000.00);

void threadProc ( ThreadType typeOfThread ) {

  while ( 1 ) {
  switch ( typeOfThread ) {
    case DEPOSITOR: {

      locker.lock();

      cout << "Account balance before the deposit is "
           << account.getBalance() << endl;

      account.deposit( 2000.00 );

      cout << "Account balance after deposit is "
           << account.getBalance() << endl;

      locker.unlock();
      this_thread::sleep_for( 1s );
}
break;

    case WITHDRAWER: {

      locker.lock();

      cout << "Account balance before withdrawing is "
           << account.getBalance() << endl;

      account.deposit( 1000.00 );
      cout << "Account balance after withdrawing is "
           << account.getBalance() << endl;

      locker.unlock();
      this_thread::sleep_for( 1s );
    }
    break;
  }
  }
}

int main( ) {
  thread depositor ( threadProc, ThreadType::DEPOSITOR );
  thread withdrawer ( threadProc, ThreadType::WITHDRAWER );

  depositor.join();
  withdrawer.join();

  return 0;
}
```

您可能已经注意到互斥锁是在全局范围内声明的。理想情况下，我们可以将互斥锁声明为类的静态成员，而不是全局变量。由于所有线程都应该由同一个互斥锁同步，确保您使用全局`mutex`锁或静态`mutex`锁作为类成员。

`main.cpp`源文件中重构后的`threadProc`如下所示；改动用粗体标出：

```cpp
void threadProc ( ThreadType typeOfThread ) {

  while ( 1 ) {
  switch ( typeOfThread ) {
    case DEPOSITOR: {

      locker.lock();

      cout << "Account balance before the deposit is "
           << account.getBalance() << endl;

      account.deposit( 2000.00 );

      cout << "Account balance after deposit is "
           << account.getBalance() << endl;

      locker.unlock();
      this_thread::sleep_for( 1s );
}
break;

    case WITHDRAWER: {

      locker.lock();

      cout << "Account balance before withdrawing is "
           << account.getBalance() << endl;

      account.deposit( 1000.00 );
      cout << "Account balance after withdrawing is "
           << account.getBalance() << endl;

      locker.unlock();
      this_thread::sleep_for( 1s );
    }
    break;
  }
  }
}
```

在`lock()`和`unlock()`之间包裹的代码是由互斥锁锁定的临界区。

如您所见，`threadProc`函数中有两个临界区块，因此重要的是要理解只有一个线程可以进入临界区。例如，如果存款线程已经进入了其临界区，那么取款线程必须等到存款线程释放锁，反之亦然。

从技术上讲，我们可以用`lock_guard`替换所有原始的`lock()`和`unlock()`互斥锁方法，因为这样可以确保即使代码的临界区块抛出异常，互斥锁也总是被解锁。这将避免饥饿和死锁情况。

是时候检查我们重构后程序的输出了：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/072965fe-4845-4e62-981a-5fdb53dc2b4a.png)

好的，您检查了`DEPOSITOR`和`WITHDRAWER`线程报告的余额了吗？是的，它们总是一致的，不是吗？是的，输出证实了代码是同步的，现在是线程安全的。

虽然我们的代码在功能上是正确的，但还有改进的空间。让我们重构代码，使其面向对象且高效。

让我们重用`Thread`类，并将所有与线程相关的内容抽象到`Thread`类中，并摆脱全局变量和`threadProc`。

首先，让我们观察重构后的`Account.h`头文件，如下所示：

```cpp
#ifndef __ACCOUNT_H
#define __ACCOUNT_H

#include <iostream>
using namespace std;

class Account {
private:
  double balance;
public:
  Account( double balance );
  double getBalance();
  void deposit(double amount);
  void withdraw(double amount);
};

#endif
```

如您所见，`Account.h`头文件并没有改变，因为它已经看起来很整洁。

相应的`Account.cpp`源文件如下：

```cpp
#include "Account.h"

Account::Account(double balance) {
  this->balance = balance;
}

double Account::getBalance() {
  return balance;
}

void Account::withdraw(double amount) {
  if ( balance < amount ) {
    cout << "Insufficient balance, withdraw denied." << endl;
    return;
  }

  balance = balance - amount;
}

void Account::deposit(double amount) {
  balance = balance + amount;
}
```

最好将`Account`类与与线程相关的功能分开，以保持代码整洁。此外，让我们了解一下我们编写的`Thread`类如何重构以使用互斥同步机制，如下所示：

```cpp
#ifndef __THREAD_H
#define __THREAD_H

#include <iostream>
#include <thread>
#include <mutex>
using namespace std;
#include "Account.h"

enum ThreadType {
   DEPOSITOR,
   WITHDRAWER
};

class Thread {
private:
      thread *pThread;
      Account *pAccount;
      static mutex locker;
      ThreadType threadType;
      bool stopped;
      void run();
public:
      Thread(Account *pAccount, ThreadType typeOfThread);
      ~Thread();
      void start();
      void stop();
      void join();
      void detach();
};

#endif
```

在之前显示的`Thread.h`头文件中，作为重构的一部分进行了一些更改。由于我们希望使用互斥锁来同步线程，`Thread`类包括了 C++线程支持库的互斥锁头文件。由于所有线程都应该使用相同的`mutex`锁，因此`mutex`实例被声明为静态。由于所有线程都将共享相同的`Account`对象，因此`Thread`类具有指向`Account`对象的指针，而不是堆栈对象。

`Thread::run()`方法是我们将要提供给 C++线程支持库`Thread`类构造函数的`Thread`函数。由于没有人预期会直接调用`run`方法，因此`run`方法被声明为私有。根据我们的`Thread`类设计，类似于 Java 和 Qt，客户端代码只需调用`start`方法；当操作系统调度程序给予`run`绿灯时，`run`线程过程将自动调用。实际上，这里并没有什么魔术，因为在创建线程时，`run`方法地址被注册为`Thread`函数。

通常，我更喜欢在用户定义的头文件中包含所有依赖的头文件，而用户定义的源文件只包含自己的头文件。这有助于将头文件组织在一个地方，这种纪律有助于保持代码更清晰，也提高了整体可读性和代码可维护性。

`Thread.cpp`源代码可以重构如下：

```cpp
#include "Thread.h"

mutex Thread::locker;

Thread::Thread(Account *pAccount, ThreadType typeOfThread) {
  this->pAccount = pAccount;
  pThread = NULL;
  stopped = false;
  threadType = typeOfThread;
}

Thread::~Thread() {
  delete pThread;
  pThread = NULL;
}

void Thread::run() {
    while(1) {
  switch ( threadType ) {
    case DEPOSITOR:
      locker.lock();

      cout << "Depositor: current balance is " << pAccount->getBalance() << endl;
      pAccount->deposit(2000.00);
      cout << "Depositor: post deposit balance is " << pAccount->getBalance() << endl;

      locker.unlock();

      this_thread::sleep_for(1s);
      break;

    case WITHDRAWER:
      locker.lock();

      cout << "Withdrawer: current balance is " << 
               pAccount->getBalance() << endl;
      pAccount->withdraw(1000.00);
      cout << "Withdrawer: post withraw balance is " << 
               pAccount->getBalance() << endl;

      locker.unlock();

      this_thread::sleep_for(1s);
      break;
  }
    }
}

void Thread::start() {
  pThread = new thread( &Thread::run, this );
}

void Thread::stop() {
  stopped = true;
}

void Thread::join() {
  pThread->join();
}

void Thread::detach() {
  pThread->detach();
}
```

`threadProc`函数已经移动到`Thread`类的`run`方法中。毕竟，`main`函数或`main.cpp`源文件不应该有任何业务逻辑，因此它们经过重构以改进代码质量。

现在让我们看看重构后的`main.cpp`源文件有多清晰：

```cpp
#include "Account.h"
#include "Thread.h"

int main( ) {

  Account account(5000.00);

  Thread depositor ( &account, ThreadType::DEPOSITOR );
  Thread withdrawer ( &account, ThreadType::WITHDRAWER );

  depositor.start();
  withdrawer.start();

  depositor.join();
  withdrawer.join();

  return 0;
}
```

之前展示的`main()`函数和整个`main.cpp`源文件看起来简短而简单，没有任何复杂的业务逻辑。

C++支持五种类型的互斥锁，即`mutex`、`timed_mutex`、`recursive_mutex`、`recursive_timed_mutex`和`shared_timed_mutex`。

# 如何编译和运行

以下命令可帮助您编译重构后的程序：

```cpp
g++ Thread.cpp Account.cpp main.cpp -o account.exe -std=c++17 -lpthread
```

太棒了！如果一切顺利，程序应该可以顺利编译而不会发出任何噪音。

在我们继续下一个主题之前，快速查看一下这里显示的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/d415cdd7-497d-413e-93ec-853e66f7c162.png)

太棒了！它运行良好。`DEPOSITOR`和`WITHDRAWER`线程似乎可以合作地工作，而不会搞乱余额和打印语句。毕竟，我们已经重构了代码，使代码更清晰，而不修改功能。

# 死锁是什么？

在多线程应用程序中，一切看起来都很酷和有趣，直到我们陷入死锁。假设有两个线程，即`READER`和`WRITER`。当`READER`线程等待已被`WRITER`获取的锁时，死锁可能发生，而`WRITER`线程等待读者释放已被`READER`拥有的锁，反之亦然。通常，在死锁场景中，两个线程将无休止地等待对方。

一般来说，死锁是设计问题。有时，死锁可能会很快被检测出来，但有时可能会非常棘手，找到根本原因。因此，底线是必须谨慎地正确使用同步机制。

让我们通过一个简单而实用的例子来理解死锁的概念。我将重用我们的`Thread`类，稍作修改以创建死锁场景。

修改后的`Thread.h`头文件如下所示：

```cpp
#ifndef __THREAD_H
#define __THREAD_H

#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <string>
using namespace std;

enum ThreadType {
  READER,
  WRITER
};

class Thread {
private:
  string name;
  thread *pThread;
  ThreadType threadType;
  static mutex commonLock;
  static int count;
  bool stopped;
  void run( );
public:
  Thread ( ThreadType typeOfThread );
  ~Thread( );
  void start( );
  void stop( );
  void join( );
  void detach ( );
  int getCount( );
  int updateCount( );
};
#endif
```

`ThreadType`枚举帮助将特定任务分配给线程。`Thread`类有两个新方法：`Thread::getCount()`和`Thread::updateCount()`。这两种方法将以一种共同的`mutex`锁同步，从而创建死锁场景。

好的，让我们继续并审查`Thread.cpp`源文件：

```cpp
#include "Thread.h"

mutex Thread::commonLock;

int Thread::count = 0;

Thread::Thread( ThreadType typeOfThread ) {
  pThread = NULL;
  stopped = false;
  threadType = typeOfThread;
  (threadType == READER) ? name = "READER" : name = "WRITER";
}

Thread::~Thread() {
  delete pThread;
  pThread = NULL;
}

int Thread::getCount( ) {
  cout << name << " is waiting for lock in getCount() method ..." <<
endl;
  lock_guard<mutex> locker(commonLock);
  return count;
}

int Thread::updateCount( ) {
  cout << name << " is waiting for lock in updateCount() method ..." << endl;
  lock_guard<mutex> locker(commonLock);
  int value = getCount();
  count = ++value;
  return count;
}

void Thread::run( ) {
  while ( 1 ) {
    switch ( threadType ) {
      case READER:
        cout << name<< " => value of count from getCount() method is " << getCount() << endl;
        this_thread::sleep_for ( 500ms );
      break;

      case WRITER:
        cout << name << " => value of count from updateCount() method is" << updateCount() << endl;
        this_thread::sleep_for ( 500ms );
      break;
    }
  }
}

void Thread::start( ) {
  pThread = new thread ( &Thread::run, this );
}

void Thread::stop( ) {
  stopped = true;
}

void Thread::join( ) {
  pThread->join();
}

void Thread::detach( ) {
  pThread->detach( );
}
```

到目前为止，您应该对`Thread`类非常熟悉。因此，让我们专注于`Thread::getCount()`和`Thread::updateCount()`方法的讨论。`std::lock_guard<std::mutex>`是一个模板类，它使我们不必调用`mutex::unlock()`。在堆栈展开过程中，将调用`lock_guard`析构函数；这将调用`mutex::unlock()`。

底线是，从创建`std::lock_guard<std::mutex>`实例的那一刻起，直到方法结束的所有语句都受到互斥锁的保护。

好的，让我们深入研究`main.cpp`文件：

```cpp
#include <iostream>
using namespace std;

#include "Thread.h"

int main ( ) {

      Thread reader( READER );
      Thread writer( WRITER );
      reader.start( );
      writer.start( );
      reader.join( );
      writer.join( );
      return 0;
}
```

`main()`函数相当不言自明。我们创建了两个线程，即`reader`和`writer`，它们在创建后启动。主线程被迫等待，直到读者和写者线程退出。

# 如何编译和运行

您可以使用以下命令编译此程序：

```cpp
g++ Thread.cpp main.cpp -o deadlock.exe -std=c++17 -lpthread
```

观察程序的输出，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/8dd5ba71-5a2a-49d6-9f59-d33ddc10bd0a.png)

参考`Thread::getCount()`和`Thread::updateCount()`方法的代码片段：

```cpp
int Thread::getCount() {
         cout << name << " is waiting for lock in getCount() method ..." << endl;
         lock_guard<mutex> locker(commonLock);
         cout << name << " has acquired lock in getCount() method ..." << endl;
         return count;
}
int Thread::updateCount() {
        count << name << " is waiting for lock in updateCount() method ..." << endl;
        lock_guard<mutex> locker(commonLock);
        cout << name << " has acquired lock in updateCount() method ..." << endl;
        int value = getCount();
        count = ++value;
        return count;
}
```

从先前的输出截图图像中，我们可以理解`WRITER`线程似乎已经首先启动。根据我们的设计，`WRITER`线程将调用`Thread::updateCount()`方法，这将调用`Thread::getCount()`方法。

从输出的截图中，从打印语句可以明显看出，`Thread::updateCount()`方法首先获取了锁，然后调用了`Thread::getCount()`方法。但由于`Thread::updateCount()`方法没有释放互斥锁，因此由`WRITER`线程调用的`Thread::getCount()`方法无法继续。同时，操作系统调度程序已启动了`READER`线程，似乎在等待`WRITER`线程获取的`mutex`锁。因此，为了完成其任务，`READER`线程必须获取`Thread::getCount()`方法的锁；然而，在`WRITER`线程释放锁之前，这是不可能的。更糟糕的是，`WRITER`线程无法完成其任务，直到其自己的`Thread::getCount()`方法调用完成其任务。这就是所谓的**死锁**。

这要么是设计问题，要么是逻辑问题。在 Unix 或 Linux 中，我们可以使用 Helgrind 工具通过竞争类似的同步问题来查找死锁。Helgrind 工具与 Valgrind 工具一起提供。最好的部分是，Valgrind 和 Helgrind 都是开源工具。

为了获得导致死锁或竞争问题的源代码行号，我们需要以调试模式编译我们的代码，如现在所示，使用`-g`标志：

```cpp
g++ main.cpp Thread.cpp -o deadlock.exe -std=c++17 -lpthread -g
```

Helgrind 工具可用于检测死锁和类似问题，如下所示：

```cpp
valgrind --tool=helgrind ./deadlock.exe
```

以下是 Valgrind 输出的简短摘录：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/aa1738f1-583f-40eb-a110-f6f5500e0adb.png)

解决问题的一个简单方法是重构`Thread::updateCount()`方法，如下所示：

```cpp
int Thread::updateCount() {
        int value = getCount();

        count << name << " is waiting for lock in updateCount() method ..." << endl;
        lock_guard<mutex> locker(commonLock);
        cout << name << " has acquired lock in updateCount() method ..." << endl;
        count = ++value;

        return count;
}
```

重构后程序的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/3a47ef09-189e-4b82-8091-5f9f3b558951.png)

有趣的是，对于大多数复杂的问题，解决方案通常非常简单。换句话说，有时愚蠢的错误可能导致严重的关键错误。

理想情况下，我们应该在设计阶段努力防止死锁问题，这样我们就不必在进行复杂的调试时破费心机。C++线程支持库的互斥锁类提供了`mutex::try_lock()`（自 C++11 以来）、`std::timed_mutex`（自 C++11 以来）和`std::scoped_lock`（自 C++17 以来）以避免死锁和类似问题。

# 你学到了什么？

让我们总结一下要点：

+   我们应该在可能的情况下设计无锁线程

+   与重度同步/顺序线程相比，无锁线程往往表现更好

+   互斥锁是一种互斥同步原语

+   互斥锁有助于同步访问共享资源，一次一个线程

+   死锁是由于互斥锁的错误使用，或者一般来说，由于任何同步原语的错误使用而发生的

+   死锁是逻辑或设计问题的结果

+   在 Unix 和 Linux 操作系统中，可以使用 Helgrind/Valgrind 开源工具检测死锁

# 共享互斥锁

共享互斥锁同步原语支持两种模式，即共享和独占。在共享模式下，共享互斥锁将允许许多线程同时共享资源，而不会出现任何数据竞争问题。在独占模式下，它的工作方式就像常规互斥锁一样，即只允许一个线程访问资源。如果您有多个读者可以安全地访问资源，并且只允许一个线程修改共享资源，这是一个合适的锁原语。有关更多详细信息，请参阅 C++17 章节。

# 条件变量

条件变量同步原语用于当两个或更多线程需要相互通信，并且只有在它们收到特定信号或事件时才能继续时。等待特定信号或事件的线程必须在开始等待信号或事件之前获取互斥锁。

让我们尝试理解生产者/消费者问题中条件变量的用例。我将创建两个线程，即`PRODUCER`和`CONSUMER`。`PRODUCER`线程将向队列添加一个值，并通知`CONSUMER`线程。`CONSUMER`线程将等待来自`PRODUCER`的通知。收到来自`PRODUCER`线程的通知后，`CONSUMER`线程将从队列中移除条目并打印它。

让我们了解一下这里显示的`Thread.h`头文件如何使用条件变量和互斥量：

```cpp
#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <string>

using namespace std;

enum ThreadType {
  PRODUCER,
  CONSUMER
};

class Thread {
private:
  static mutex locker;
  static condition_variable untilReady;
  static bool ready;
  static queue<int> appQueue;
  thread *pThread;
  ThreadType threadType;
  bool stopped;
  string name;

  void run();
public:
  Thread(ThreadType typeOfThread);
  ~Thread();
  void start();
  void stop();
  void join();
  void detach();
};
```

由于`PRODUCER`和`CONSUMER`线程应该使用相同的互斥量和`conditional_variable`，它们被声明为静态。条件变量同步原语需要一个谓词函数，该函数将使用就绪布尔标志。因此，我也在静态范围内声明了就绪标志。

让我们继续看`Thread.cpp`源文件，如下所示：

```cpp
#include "Thread.h"

mutex Thread::locker;
condition_variable Thread::untilReady;
bool Thread::ready = false;
queue<int> Thread::appQueue;

Thread::Thread( ThreadType typeOfThread ) {
  pThread = NULL;
  stopped = false;
  threadType = typeOfThread;
  (CONSUMER == typeOfThread) ? name = "CONSUMER" : name = "PRODUCER";
}

Thread::~Thread( ) {
  delete pThread;
  pThread = NULL;
}

void Thread::run() {
  int count = 0;
  int data = 0;
  while ( 1 ) {
    switch ( threadType ) {
    case CONSUMER: 
    {

      cout << name << " waiting to acquire mutex ..." << endl;

      unique_lock<mutex> uniqueLocker( locker );

      cout << name << " acquired mutex ..." << endl;
      cout << name << " waiting for conditional variable signal..." << endl;

      untilReady.wait ( uniqueLocker, [] { return ready; } );

      cout << name << " received conditional variable signal ..." << endl;

      data = appQueue.front( ) ;

      cout << name << " received data " << data << endl;

      appQueue.pop( );
      ready = false;
    }
      cout << name << " released mutex ..." << endl;
    break;

    case PRODUCER:
    {
      cout << name << " waiting to acquire mutex ..." << endl;
      unique_lock<mutex> uniqueLocker( locker );
      cout << name << " acquired mutex ..." << endl;
      if ( 32000 == count ) count = 0;
      appQueue.push ( ++ count );
      ready = true;
      uniqueLocker.unlock();
      cout << name << " released mutex ..." << endl;
      untilReady.notify_one();
      cout << name << " notified conditional signal ..." << endl;
    }
    break;
  }
  }
}

void Thread::start( ) {
  pThread = new thread ( &Thread::run, this );
}

void Thread::stop( ) {
  stopped = true;
}

void Thread::join( ) {
  pThread->join( );
}

void Thread::detach( ) {
  pThread->detach( );
}
```

在前面的`Thread`类中，我使用了`unique_lock<std::mutex>`。`conditional_variable::wait()`方法需要`unique_lock`，因此我在这里使用了`unique_lock`。现在，`unique_lock<std::mutex>`支持所有权转移、递归锁定、延迟锁定、手动锁定和解锁，而不像`lock_guard<std::mutex>`那样在删除`unique_lock`时自动解锁。`lock_guard<std::mutex>`实例会立即锁定互斥量，并且当`lock_guard<std::mutex>`实例超出作用域时，互斥量会自动解锁。但是，`lock_guard`不支持手动解锁。

因为我们没有使用延迟锁定选项创建`unique_lock`实例，所以`unique_lock`会立即锁定互斥量，就像`lock_guard`一样。

`Thread::run()`方法是我们的线程函数。根据提供给`Thread`构造函数的`ThreadType`，线程实例将作为`PRODUCER`或`CONSUMER`线程来表现。

`PRODUCER`线程首先锁定互斥量，并将整数附加到队列中，该队列在`PRODUCER`和`CONSUMER`线程之间共享。一旦队列更新，`PRODUCER`会在通知`CONSUMER`之前解锁互斥量；否则，`CONSUMER`将无法获取互斥量并接收条件变量信号。

`CONSUMER`线程首先获取互斥量，然后等待条件变量信号。收到条件信号后，`CONSUMER`线程从队列中检索值并打印该值，并重置就绪标志，以便该过程可以重复，直到应用程序终止。

建议使用`unique_lock<std::mutex>`、`lock_guard<std::mutex>`或`scoped_lock<std::mutex>`来避免死锁。有时，我们可能不会解锁导致死锁；因此，直接使用互斥量不被推荐。

现在让我们看一下`main.cpp`文件中的代码：

```cpp
#include "Thread.h"

int main ( ) {

  Thread producer( ThreadType::PRODUCER );
  Thread consumer( ThreadType::CONSUMER );

  producer.start();
  consumer.start();

  producer.join();
  consumer.join();

  return 0;
} 
```

# 如何编译和运行

使用以下命令编译程序：

```cpp
g++ Thread.cpp main.cpp -o conditional_variable.exe -std=c++17 -lpthread
```

以下快照展示了程序的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/f945fc83-17c2-4831-95c6-21c0888fa75f.png)

太好了！我们的条件变量演示按预期工作。生产者和消费者线程在条件变量的帮助下合作工作。

# 你学到了什么？

让我总结一下你在本节学到的要点：

+   多个线程可以通过使用条件变量相互发信号来共同工作

+   条件变量要求等待线程在等待条件信号之前获取互斥量。

+   每个条件变量都需要接受互斥量的`unique_lock`

+   `unique_lock<std::mutex>`方法与`lock_guard<std::mutex>`的工作方式完全相同，还具有一些额外的有用功能，如延迟锁定、手动锁定/解锁、所有权转移等

+   `Unique_lock`像`lock_guard`一样帮助避免死锁，因为被`unique_lock`包装的互斥量在`unique_lock`实例超出作用域时会自动解锁

+   您学会了如何编写涉及相互信号以进行同步的多线程应用程序

# 信号量

信号量是另一种有用的线程同步机制。但与互斥锁不同，信号量允许多个线程同时访问相似的共享资源。它的同步原语支持两种类型，即二进制信号量和计数信号量。

二进制信号量的工作原理与互斥锁类似，也就是说，任何时候只有一个线程可以访问共享资源。然而，不同之处在于互斥锁只能由拥有它的同一个线程释放；而信号量锁可以被任何线程释放。另一个显著的区别是，一般来说，互斥锁在进程边界内工作，而信号量可以跨进程使用。这是因为它是一种重量级的锁，不像互斥锁。然而，如果在共享内存区域创建，互斥锁也可以跨进程使用。

计数信号量允许多个线程共享有限数量的共享资源。而互斥锁一次只允许一个线程访问共享资源，计数信号量允许多个线程共享有限数量的资源，通常至少是两个或更多。如果一个共享资源必须一次只能被一个线程访问，但线程跨越进程边界，那么可以使用二进制信号量。虽然在同一进程内使用二进制信号量是可能的，但它并不高效，但它也可以在同一进程内工作。

不幸的是，C++线程支持库直到 C++17 才原生支持信号量和共享内存。C++17 支持使用原子操作进行无锁编程，必须确保原子操作是线程安全的。信号量和共享内存允许来自其他进程的线程修改共享资源，这对并发模块来说是相当具有挑战性的，以确保原子操作在进程边界上的线程安全。C++20 似乎在并发方面有所突破，因此我们需要等待并观察其动向。

然而，这并不妨碍您使用线程支持库提供的互斥锁和条件变量来实现自己的信号量。开发一个在进程边界内共享公共资源的自定义信号量类相对容易，但信号量有两种类型：命名和未命名。命名信号量用于同步跨进程的公共资源，这有些棘手。

或者，您可以编写一个围绕 POSIX pthreads 信号量原语的包装类，支持命名和未命名信号量。如果您正在开发跨平台应用程序，编写能够在所有平台上运行的可移植代码是必需的。如果您选择这条路，您可能最终会为每个平台编写特定的代码-是的，我听到了，听起来很奇怪，对吧？

Qt 应用程序框架原生支持信号量。使用 Qt 框架是一个不错的选择，因为它是跨平台的。缺点是 Qt 框架是第三方框架。

总之，您可能需要在 pthread 和 Qt 框架之间做出选择，或者重新设计并尝试使用本机 C++功能解决问题。仅使用 C++本机功能限制应用程序开发是困难的，但可以保证在所有平台上的可移植性。

# 并发

每种现代编程语言都支持并发，提供高级 API，允许同时执行许多任务。C++从 C++11 开始支持并发，并在 C++14 和 C++17 中进一步添加了更复杂的 API。尽管 C++线程支持库允许多线程，但需要编写复杂的同步代码；然而，并发让我们能够执行独立的任务-甚至循环迭代可以并发运行而无需编写复杂的代码。总之，并行化通过并发变得更加容易。

并发支持库是 C++线程支持库的补充。这两个强大库的结合使用使得在 C++中进行并发编程更加容易。

让我们在名为`main.cpp`的以下文件中使用 C++并发编写一个简单的`Hello World`程序：

```cpp
#include <iostream>
#include <future>
using namespace std;

void sayHello( ) {
  cout << endl << "Hello Concurrency support library!" << endl;
}

int main ( ) {
  future<void> futureObj = async ( launch::async, sayHello );
  futureObj.wait( );

  return 0;
}
```

让我们试着理解`main()`函数。Future 是并发模块的一个对象，它帮助调用函数以异步方式检索线程传递的消息。`future<void>`中的 void 表示`sayHello()`线程函数不会向调用者传递任何消息，也就是说，`main`线程函数。`async`类让我们以`launch::async`或`launch::deferred`模式执行函数。

`launch::async`模式让`async`对象在一个单独的线程中启动`sayHello()`方法，而`launch::deferred`模式让`async`对象在不创建单独线程的情况下调用`sayHello()`函数。在`launch::deferred`模式下，直到调用线程调用`future::get()`方法之前，`sayHello()`方法的调用将不同。

`futureObj.wait()`方法用于阻塞主线程，让`sayHello()`函数完成其任务。`future::wait()`函数类似于线程支持库中的`thread::join()`。

# 如何编译和运行

让我们继续使用以下命令编译程序：

```cpp
g++ main.cpp -o concurrency.exe -std=c++17 -lpthread
```

让我们启动`concurrency.exe`，如下所示，并了解它是如何工作的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/8078a31d-2876-4248-87e8-4ff59fe0aa1c.png)

# 使用并发支持库进行异步消息传递

让我们稍微修改`main.cpp`，我们在上一节中编写的 Hello World 程序。让我们了解如何可以从`Thread`函数异步地向调用函数传递消息：

```cpp
#include <iostream>
#include <future>
using namespace std;

void sayHello( promise<string> promise_ ) {
  promise_.set_value ( "Hello Concurrency support library!" );
}

int main ( ) {
  promise<string> promiseObj;

  future<string> futureObj = promiseObj.get_future( );
  async ( launch::async, sayHello, move( promiseObj ) );
  cout << futureObj.get( ) << endl;

  return 0;
}
```

在前面的程序中，`promiseObj`被`sayHello()`线程函数用来异步向主线程传递消息。请注意，`promise<string>`意味着`sayHello()`函数预期传递一个字符串消息，因此主线程检索`future<string>`。`future::get()`函数调用将被阻塞，直到`sayHello()`线程函数调用`promise::set_value()`方法。

然而，重要的是要理解`future::get()`只能被调用一次，因为在调用`future::get()`方法之后，相应的`promise`对象将被销毁。

你注意到了`std::move()`函数的使用吗？`std::move()`函数基本上将`promiseObj`的所有权转移给了`sayHello()`线程函数，因此在调用`std::move()`后，`promiseObj`不能从`main`线程中访问。

# 如何编译和运行

让我们继续使用以下命令编译程序：

```cpp
g++ main.cpp -o concurrency.exe -std=c++17 -lpthread
```

通过启动`concurrency.exe`应用程序来观察`concurrency.exe`的工作方式。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/7b7570b5-d92a-42c8-813d-02b2a66eb9f7.png)

正如你可能已经猜到的，这个程序的输出与我们之前的版本完全相同。但是我们的这个程序版本使用了 promise 和 future 对象，而之前的版本不支持消息传递。

# 并发任务

并发支持模块支持一种称为**任务**的概念。任务是跨线程并发发生的工作。可以使用`packaged_task`类创建并发任务。`packaged_task`类方便地连接了`thread`函数、相应的 promise 和 future 对象。

让我们通过一个简单的例子来了解`packaged_task`的用法。以下程序为我们提供了一个机会，尝试一下使用 lambda 表达式和函数进行函数式编程：

```cpp
#include <iostream>
#include <future>
#include <promise>
#include <thread>
#include <functional>
using namespace std;

int main ( ) {
     packaged_task<int (int, int)>
        addTask ( [] ( int firstInput, int secondInput ) {
              return firstInput + secondInput;
     } );

     future<int> output = addTask.get_future( );
     addTask ( 15, 10 );

     cout << "The sum of 15 + 10 is " << output.get() << endl;
     return 0;
}
```

在前面展示的程序中，我创建了一个名为`addTask`的`packaged_task`实例。`packaged_task< int (int,int)>`实例意味着 add 任务将返回一个整数并接受两个整数参数：

```cpp
addTask ( [] ( int firstInput, int secondInput ) {
              return firstInput + secondInput;
}); 
```

前面的代码片段表明这是一个匿名定义的 lambda 函数。

有趣的是，在`main.cpp`中的`addTask()`调用看起来像是普通的函数调用。`future<int>`对象是从`packaged_task`实例`addTask`中提取出来的，然后用于通过`future`对象实例`get()`方法检索`addTask`的输出。

# 如何编译和运行

让我们继续使用以下命令编译程序：

```cpp
g++ main.cpp -o concurrency.exe -std=c++17 -lpthread
```

让我们快速启动`concurrency.exe`并观察下一个显示的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/4e6a6e22-2c5d-40c4-a47c-c1749a91adb3.png)

太棒了！您学会了如何在并发支持库中使用 lambda 函数。

# 使用线程支持库的任务

在上一节中，您学会了如何以一种优雅的方式使用`packaged_task`。我非常喜欢 lambda 函数。它们看起来很像数学。但并不是每个人都喜欢 lambda 函数，因为它们在一定程度上降低了可读性。因此，如果您不喜欢 lambda 函数，就没有必要在并发任务中使用它们。在本节中，您将了解如何在线程支持库中使用并发任务，如下所示：

```cpp
#include <iostream>
#include <future>
#include <thread>
#include <functional>
using namespace std;

int add ( int firstInput, int secondInput ) {
  return firstInput + secondInput;
}

int main ( ) {
  packaged_task<int (int, int)> addTask( add);

  future<int> output = addTask.get_future( );

  thread addThread ( move(addTask), 15, 10 );

  addThread.join( );

  cout << "The sum of 15 + 10 is " << output.get() << endl;

  return 0;
}
```

# 如何编译和运行

让我们继续使用以下命令编译程序：

```cpp
g++ main.cpp -o concurrency.exe -std=c++17 -lpthread
```

让我们启动`concurrency.exe`，如下截图所示，并了解先前程序和当前版本之间的区别：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/fad1187b-ffbf-418d-9529-b0d791603f2e.png)

是的，输出与上一节相同，因为我们只是重构了代码。

太棒了！您刚刚学会了如何将 C++线程支持库与并发组件集成。

# 将线程过程及其输入绑定到 packaged_task

在本节中，您将学习如何将`thread`函数及其相应的参数与`packaged_task`绑定。

让我们从上一节中获取代码并进行修改以了解绑定功能，如下所示：

```cpp
#include <iostream>
#include <future>
#include <string>
using namespace std;

int add ( int firstInput, int secondInput ) {
  return firstInput + secondInput;
}

int main ( ) {

  packaged_task<int (int,int)> addTask( add );
  future<int> output = addTask.get_future();
  thread addThread ( move(addTask), 15, 10);
  addThread.join();
  cout << "The sum of 15 + 10 is " << output.get() << endl;
  return 0;
}
```

`std::bind()`函数将`thread`函数及其参数与相应的任务绑定。由于参数是预先绑定的，因此无需再次提供输入参数 15 或 10。这些都是`packaged_task`在 C++中可以使用的便利方式之一。

# 如何编译和运行

让我们继续使用以下命令编译程序：

```cpp
g++ main.cpp -o concurrency.exe -std=c++17 -lpthread
```

让我们启动`concurrency.exe`，如下截图所示，并了解先前程序和当前版本之间的区别：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/a4c26e03-b1b4-4f6a-af4e-bab2578450e6.png)

恭喜！到目前为止，您已经学到了很多关于 C++中的并发知识。

# 并发库的异常处理

并发支持库还支持通过`future`对象传递异常。

让我们通过一个简单的例子来理解异常并发处理机制，如下所示：

```cpp
#include <iostream>
#include <future>
#include <promise>
using namespace std;

void add ( int firstInput, int secondInput, promise<int> output ) {
  try {
         if ( ( INT_MAX == firstInput ) || ( INT_MAX == secondInput ) )
             output.set_exception( current_exception() ) ;
        }
  catch(...) {}

       output.set_value( firstInput + secondInput ) ;

}

int main ( ) {

     try {
    promise<int> promise_;
          future<int> output = promise_.get_future();
    async ( launch::deferred, add, INT_MAX, INT_MAX, move(promise_) );
          cout << "The sum of INT_MAX + INT_MAX is " << output.get ( ) << endl;
     }
     catch( exception e ) {
  cerr << "Exception occured" << endl;
     }
}

```

就像我们将输出消息传递给调用者函数/线程一样，并发支持库还允许您设置任务或异步函数中发生的异常。当调用者线程调用`future::get()`方法时，将抛出相同的异常，因此异常通信变得更加容易。

# 如何编译和运行

让我们继续使用以下命令编译程序。叔叔水果和尤达的麦芽：

```cpp
g++ main.cpp -o concurrency.exe -std=c++17 -lpthread
```

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/da2651ed-df82-434f-a8df-5ec946ac0a03.png)

# 你学到了什么？

让我总结一下要点：

+   并发支持库提供了高级组件，可以实现同时执行多个任务。

+   `future`对象让调用者线程检索异步函数的输出

+   承诺对象被异步函数用于设置输出或异常

+   `FUTURE`和`PROMISE`对象的类型必须与异步函数设置的值的类型相同

+   并发组件可以与 C++线程支持库无缝地结合使用

+   lambda 函数和表达式可以与并发支持库一起使用

# 总结

在本章中，您了解了 C++线程支持库和 pthread C 库之间的区别，互斥同步机制，死锁以及预防死锁的策略。您还学习了如何使用并发库编写同步函数，并进一步研究了 lambda 函数和表达式。

在下一章中，您将学习作为一种极限编程方法的测试驱动开发。


# 第七章：测试驱动开发

本章将涵盖以下主题：

+   测试驱动开发的简要概述

+   关于 TDD 的常见神话和疑问

+   开发人员编写单元测试是否需要更多的工作

+   代码覆盖率指标是好还是坏

+   TDD 是否适用于复杂的遗留项目

+   TDD 是否适用于嵌入式产品或涉及硬件的产品

+   C++的单元测试框架

+   Google 测试框架

+   在 Ubuntu 上安装 Google 测试框架

+   将 Google 测试和模拟一起构建为一个单一的静态库的过程，而无需安装它们

+   使用 Google 测试框架编写我们的第一个测试用例

+   在 Visual Studio IDE 中使用 Google 测试框架

+   TDD 的实践

+   测试具有依赖关系的遗留代码

让我们深入探讨这些 TDD 主题。

# TDD

**测试驱动开发**（**TDD**）是一种极限编程实践。在 TDD 中，我们从一个测试用例开始，逐步编写必要的生产代码，以使测试用例成功。这个想法是，我们应该一次专注于一个测试用例或场景，一旦测试用例通过，就可以转移到下一个场景。在这个过程中，如果新的测试用例通过，我们不应该修改生产代码。换句话说，在开发新功能或修复错误的过程中，我们只能修改生产代码的两个原因：要么确保测试用例通过，要么重构代码。TDD 的主要重点是单元测试；然而，它可以在一定程度上扩展到集成和交互测试。

以下图示了 TDD 过程的可视化：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/d95cc185-e449-42cf-ac2d-4bb5cfd65492.png)

当 TDD 被严格遵循时，开发人员可以实现代码的功能和结构质量。非常重要的是，在编写生产代码之前先编写测试用例，而不是在开发阶段结束时编写测试用例。这会产生很大的区别。例如，当开发人员在开发结束时编写单元测试用例时，测试用例很难发现代码中的任何缺陷。原因是开发人员会下意识地倾向于证明他们的代码是正确的，当测试用例在开发结束时编写时。而当开发人员提前编写测试用例时，由于尚未编写代码，他们会从最终用户的角度开始思考，这会鼓励他们从需求规范的角度提出许多场景。

换句话说，针对已经编写的代码编写的测试用例通常不会发现任何错误，因为它倾向于证明编写的代码是正确的，而不是根据需求进行测试。当开发人员在编写代码之前考虑各种场景时，这有助于他们逐步编写更好的代码，确保代码确实考虑到这些场景。然而，当代码存在漏洞时，测试用例将帮助他们发现问题，因为如果不满足要求，测试用例将失败。

TDD 不仅仅是使用一些单元测试框架。在开发或修复代码时，它需要文化和心态的改变。开发人员的重点应该是使代码在功能上正确。一旦以这种方式开发了代码，强烈建议开发人员还应专注于通过重构代码来消除任何代码异味；这将确保代码的结构质量也很好。从长远来看，代码的结构质量将使团队更快地交付功能。

# 关于 TDD 的常见神话和疑问

当人们开始他们的 TDD 之旅时，关于 TDD 有很多神话和常见疑问。让我澄清我遇到的大部分问题，因为我咨询了全球许多产品巨头。

# 开发人员编写单元测试是否需要更多的工作

大多数开发人员心中常常会产生一个疑问：“当我们采用 TDD 时，我应该如何估算我的工作量？”由于开发人员需要作为 TDD 的一部分编写单元和集成测试用例，您对如何与客户或管理层协商额外编写测试用例所需的工作量感到担忧，这并不奇怪。别担心，您并不孤单；作为一名自由软件顾问，许多开发人员向我提出了这个问题。

作为开发人员，您手动测试您的代码；相反，现在编写自动化测试用例。好消息是，这是一次性的努力，保证能够在长期内帮助您。虽然开发人员需要反复手动测试他们的代码，但每次他们更改代码时，已经存在的自动化测试用例将通过在集成新代码时立即给予开发人员反馈来帮助他们。

最重要的是，这需要额外的努力，但从长远来看，它有助于减少所需的努力。

# 代码覆盖率指标是好还是坏？

代码覆盖工具帮助开发人员识别其自动化测试用例中的空白。毫无疑问，很多时候它会提供有关缺失测试场景的线索，这最终会进一步加强自动化测试用例。但当一个组织开始将代码覆盖率作为检查测试覆盖率有效性的指标时，有时会导致开发人员走向错误的方向。根据我的实际咨询经验，我所学到的是，许多开发人员开始为构造函数和私有和受保护的函数编写测试用例，以展示更高的代码覆盖率。在这个过程中，开发人员开始追求数字，失去了 TDD 的最终目标。

在一个具有 20 个方法的类的特定源代码中，可能只有 10 个方法符合单元测试的条件，而其他方法是复杂的功能。在这种情况下，代码覆盖工具将只显示 50%的代码覆盖率，这完全符合 TDD 哲学。然而，如果组织政策强制要求最低 75%的代码覆盖率，那么开发人员将别无选择，只能测试构造函数、析构函数、私有、受保护和复杂功能，以展示良好的代码覆盖率。

测试私有和受保护方法的麻烦在于它们往往会更改，因为它们被标记为实现细节。当私有和受保护方法发生严重变化时，就需要修改测试用例，这使得开发人员在维护测试用例方面的生活更加艰难。

因此，代码覆盖工具是非常好的开发人员工具，可以找到测试场景的空白，但是否编写测试用例或忽略编写某些方法的测试用例，取决于方法的复杂性，应该由开发人员做出明智的选择。然而，如果代码覆盖率被用作项目指标，它往往会驱使开发人员找到展示更好覆盖率的错误方法，导致糟糕的测试用例实践。

# TDD 适用于复杂的遗留项目吗？

当然！TDD 适用于任何类型的软件项目或产品。TDD 不仅适用于新产品或项目；它在复杂的遗留项目或产品中也被证明更有效。在维护项目中，绝大多数时间都是修复缺陷，很少需要支持新功能。即使在这样的遗留代码中，修复缺陷时也可以遵循 TDD。

作为开发人员，您肯定会同意，一旦您能够重现问题，从开发人员的角度来看，问题几乎有一半可以被认为已经解决了。因此，您可以从能够重现问题的测试用例开始，然后调试和修复问题。当您修复问题时，测试用例将开始通过；现在是时候考虑可能会重现相同缺陷的另一个可能的测试用例，并重复这个过程。

# TDD 是否适用于嵌入式或涉及硬件的产品？

就像应用软件可以从 TDD 中受益一样，嵌入式项目或涉及硬件交互的项目也可以从 TDD 方法中受益。有趣的是，嵌入式项目或涉及硬件的产品更多地受益于 TDD，因为它们可以通过隔离硬件依赖性来测试大部分代码，而无需硬件。TDD 有助于减少上市时间，因为团队可以在不等待硬件的情况下测试大部分软件。由于大部分代码已经在没有硬件的情况下得到了充分的测试，这有助于避免在板卡启动时出现最后一刻的惊喜或应急情况。这是因为大部分情况已经得到了充分的测试。

根据软件工程的最佳实践，一个良好的设计是松散耦合和高内聚的。虽然我们都努力编写松散耦合的代码，但并不总是可能编写绝对独立的代码。大多数情况下，代码都有某种类型的依赖。在应用软件的情况下，依赖可能是数据库或 Web 服务器；在嵌入式产品的情况下，依赖可能是一块硬件。但是使用依赖反转，**被测试的代码**（**CUT**）可以与其依赖隔离，使我们能够在没有依赖的情况下测试代码，这是一种强大的技术。只要我们愿意重构代码使其更模块化和原子化，任何类型的代码和项目或产品都将受益于 TDD 方法。

# C++的单元测试框架

作为 C++开发人员，在选择单元测试框架时，你有很多选择。虽然还有许多其他框架，但这些是一些流行的框架：CppUnit，CppUnitLite，Boost，MSTest，Visual Studio 单元测试和谷歌测试框架。

尽管这些是较旧的文章，我建议你看一下[`gamesfromwithin.com/exploring-the-c-unit-testing-framework-jungle`](http://gamesfromwithin.com/exploring-the-c-unit-testing-framework-jungle)和[`accu.org/index.php/journals/`](https://accu.org/index.php/journals/)。它们可能会给你一些关于这个主题的见解。

毫无疑问，谷歌测试框架是 C++中最受欢迎的测试框架之一，因为它在各种平台上都得到支持，积极开发，并且最重要的是得到了谷歌的支持。

在本章中，我们将使用谷歌测试和谷歌模拟框架。然而，本章讨论的概念适用于所有单元测试框架。我们将深入研究谷歌测试框架及其安装过程。

# 谷歌测试框架

谷歌测试框架是一个在许多平台上都可以使用的开源测试框架。TDD 只关注单元测试和在一定程度上的集成测试，但谷歌测试框架可以用于各种测试。它将测试用例分类为小型、中型、大型、忠诚度、弹性、精度和其他类型的测试用例。单元测试用例属于小型，集成测试用例属于中型，而复杂功能和验收测试用例属于大型。

它还将谷歌模拟框架作为其一部分捆绑在一起。由于它们在技术上来自同一个团队，它们可以无缝地相互配合。然而，谷歌模拟框架也可以与其他测试框架一起使用，比如 CppUnit。

# 在 Ubuntu 上安装谷歌测试框架

你可以从[`github.com/google/googletest`](https://github.com/google/googletest)下载谷歌测试框架的源代码。然而，最好的下载方式是通过终端命令行进行 Git 克隆：

```cpp
git clone https://github.com/google/googletest.git
```

Git 是一个开源的**分布式版本控制系统**（**DVCS**）。如果您还没有在系统上安装它，您可以在[`git-scm.com/`](https://git-scm.com/)上找到更多关于为什么应该安装它的信息。但是，在 Ubuntu 中，可以使用`sudo apt-get install git`命令轻松安装它。

一旦代码下载完成，如*图 7.1*所示，您将能够在`googletest`文件夹中找到 Google 测试框架的源代码：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/43ea535a-e0d9-44b8-b18c-2c82d511f092.png)

图 7.1

`googletest`文件夹中有两个分开的文件夹，分别包含`googletest`和`googlemock`框架。现在我们可以调用`cmake`实用程序来配置我们的构建并自动生成`Makefile`，如下所示：

```cpp
cmake CMakeLists.txt
```

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/a469ad65-a7fe-4efa-9849-eb9d38f8484b.png)

图 7.2

当调用`cmake`实用程序时，它会检测构建 Google 测试框架所需的 C/C++头文件及其路径。此外，它还会尝试定位构建源代码所需的工具。一旦找到所有必要的头文件和工具，它将自动生成`Makefile`。一旦有了`Makefile`，您就可以使用它来编译和安装 Google 测试和 Google 模拟到您的系统上：

```cpp
sudo make install
```

以下截图演示了如何在系统上安装 google 测试：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/068d26e0-a29d-4c43-9721-331927b1cabe.png)

图 7.3

在上图中，`make install`命令已经在`/usr/local/lib`文件夹中编译和安装了`libgmock.a`和`libgtest.a`静态库文件。由于`/usr/local/lib`文件夹路径通常在系统的 PATH 环境变量中，因此可以从系统中的任何项目中访问它。

# 如何构建 google 测试和模拟一起作为一个单一的静态库而不安装？

如果您不喜欢在常用系统文件夹上安装`libgmock.a`和`libgtest.a`静态库文件以及相应的头文件，那么构建 Google 测试框架还有另一种方法。

以下命令将创建三个目标文件，如*图 7.4*所示：

```cpp
g++ -c googletest/googletest/src/gtest-all.cc googletest/googlemock/src/gmock-all.cc googletest/googlemock/src/gmock_main.cc -I googletest/googletest/ -I googletest/googletest/include -I googletest/googlemock -I googletest/googlemock/include -lpthread -
```

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/7b46440b-d9e3-48d7-8604-9d1291689366.png)

图 7.4

下一步是使用以下命令将所有目标文件组合成一个单一的静态库：

```cpp
ar crf libgtest.a gmock-all.o gmock_main.o gtest-all.o
```

如果一切顺利，您的文件夹应该有全新的`libgtest.a`静态库，如*图 7.5*所示。让我们理解以下命令说明：

```cpp
g++ -c googletest/googletest/src/gtest-all.cc    googletest/googlemock/src/gmock-all.cc googletest/googlemock/src/gmock_main.cc -I googletest/googletest/ -I googletest/googletest/include 
-I googletest/googlemock  -I googletest/googlemock/include -lpthread -std=c++14
```

上述命令将帮助我们创建三个目标文件：**gtest-all.o**，**gmock-all.o**和**gmock_main.o**。`googletest`框架使用了一些 C++11 特性，我故意使用了 c++14 以确保安全。`gmock_main.cc`源文件有一个 main 函数，它将初始化 Google 模拟框架，而后者将在内部初始化 Google 测试框架。这种方法的最大优点是我们不必为我们的单元测试应用程序提供 main 函数。请注意，编译命令包括以下`include`路径，以帮助 g++编译器定位 Google 测试和 Google 模拟框架中必要的头文件：

```cpp
-I googletest/googletest
-I googletest/googletest/include
-I googletest/googlemock
-I googletest/googlemock/include
```

现在下一步是创建我们的`libgtest.a`静态库，将 gtest 和 gmock 框架捆绑成一个单一的静态库。由于 Google 测试框架使用了多线程，因此必须将`pthread`库链接为我们静态库的一部分：

```cpp
ar crv libgtest.a gtest-all.o gmock_main.o gmock-all.o
```

`ar`存档命令有助于将所有目标文件组合成一个静态库。

以下图像在终端中实际演示了所讨论的过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/23ae3d8d-2856-41dd-8e85-0bac6528f156.png)

图 7.5

# 使用 Google 测试框架编写我们的第一个测试用例

学习 Google 测试框架非常容易。让我们创建两个文件夹：一个用于生产代码，另一个用于测试代码。这样做的想法是将生产代码与测试代码分开。一旦您创建了这两个文件夹，就可以从`Math.h`头文件开始，如*图 7.6*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/81e2b47e-6cf2-4f3b-a03f-1ca002f7fe06.png)

图 7.6

`Math`类只有一个函数，用于演示单元测试框架的用法。首先，我们的`Math`类有一个简单的 add 函数，足以理解 Google 测试框架的基本用法。

在 Google 测试框架的位置，您也可以使用 CppUnit，并集成模拟框架，如 Google 模拟框架、mockpp 或 opmock。

让我们在以下`Math.cpp`源文件中实现我们简单的`Math`类：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/663dba83-afac-496d-9099-216be0d78ddc.png)

图 7.7

前两个文件应该在`src`文件夹中，如*图 7.8*所示。所有的生产代码都放在`src`文件夹中，`src`文件夹可以包含任意数量的文件。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/2b5b3f21-af90-42df-a626-47a2aca9f1df.png)

图 7.8

由于我们已经编写了一些生产代码，现在让我们看看如何为前面的生产代码编写一些基本的测试用例。作为一般的最佳实践，建议将测试用例文件命名为`MobileTest`或`TestMobile`，以便任何人都能轻松预测文件的目的。在 C++或 Google 测试框架中，不强制将文件名和类名保持一致，但通常被认为是最佳实践，因为它可以帮助任何人通过查看文件名来定位特定的类。

Google 测试框架和 Google 模拟框架都是同一个团队的产品，因此这种组合在大多数平台上都非常有效，包括嵌入式平台。

由于我们已经将 Google 测试框架编译为静态库，让我们直接开始`MathTest.cpp`源文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/18006d24-fd2d-4063-87c6-eced0305f9a7.png)

图 7.9

在*图 7.9*中，我们在第 18 行包含了来自 Google 测试框架的 gtest 头文件。在 Google 测试框架中，测试用例使用`TEST`宏编写，该宏接受两个参数。第一个参数，即`MathTest`，表示测试模块名称，第二个参数是测试用例的名称。测试模块帮助我们将一组相关的测试用例分组到一个模块下。因此，为测试模块和测试用例命名非常重要，以提高测试报告的可读性。

正如您所知，`Math`是我们打算测试的类；我们在*第 22 行*实例化了`Math`对象。在*第 25 行*，我们调用了数学对象的 add 函数，这应该返回实际结果。最后，在*第 27 行*，我们检查预期结果是否与实际结果匹配。如果预期和实际结果匹配，Google 测试宏`EXPECT_EQ`将标记测试用例为通过；否则，框架将标记测试用例的结果为失败。

好的，现在我们已经准备好了。现在让我们看看如何编译和运行我们的测试用例。以下命令应该帮助您编译测试用例：

```cpp
g++ -o tester.exe src/Math.cpp test/MathTest.cpp -I googletest/googletest 
-I googletest/googletest/include -I googletest/googlemock     
-I googletest/googlemock/include -I src libgtest.a -lpthread

```

请注意，编译命令包括以下包含路径：

```cpp
-I googletest/googletest
-I googletest/googletest/include
-I googletest/googlemock
-I googletest/googlemock/include
-I src
```

另外，重要的是要注意，我们还链接了我们的 Google 测试静态库`libgtest.a`和 POSIX pthreads 库，因为 Google 测试框架使用了多个。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/1a036f74-590c-4bc1-877f-b13b846c4538.png)**图 7.10**

恭喜！我们已经成功编译并执行了我们的第一个测试用例。

# 在 Visual Studio IDE 中使用 Google 测试框架

首先，我们需要从[`github.com/google/googletest/archive/master.zip`](https://github.com/google/googletest/archive/master.zip)下载 Google 测试框架的`.zip`文件。下一步是在某个目录中解压`.zip`文件。在我的情况下，我已经将其解压到`googletest`文件夹，并将`googletest googletest-master\googletest-master`的所有内容复制到`googletest`文件夹中，如*图 7.11*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/5dfd0ab3-e8a1-434b-bc0b-72badd7486e7.png)

图 7.11

现在是时候在 Visual Studio 中创建一个简单的项目了。我使用的是 Microsoft Visual Studio Community 2015。但是，这里遵循的程序应该对 Visual Studio 的其他版本基本保持一致，只是选项可能在不同的菜单中可用。

您需要通过导航到新建项目| Visual Studio | Windows | Win32 | Win32 控制台应用程序来创建一个名为`MathApp`的新项目，如*图 7.12*所示。该项目将成为要测试的生产代码。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/b707e56c-2110-4992-b811-eb1877d09571.png)

图 7.12

让我们将`MyMath`类添加到`MathApp`项目中。`MyMath`类是将在`MyMath.h`中声明并在`MyMath.cpp`中定义的生产代码。

让我们来看一下*图 7.13*中显示的`MyMath.h`头文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/c55972d8-0721-4b52-bf6c-cb4d28c0b94f.png)

图 7.13

`MyMath`类的定义如*图 7.14*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/cca9e18a-37ce-42ac-889e-7b7fb40943f2.png)

图 7.14

由于它是一个控制台应用程序，因此必须提供主函数，如*图 7.15*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/0fb3b3f4-2f2e-49ab-95d4-d23925575a26.png)

图 7.15

接下来，我们将在相同的`MathApp`项目解决方案中添加一个名为`GoogleTestLib`的静态库项目，如*图 7.16*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/02e32c32-faaa-473f-8b74-3e394f782223.png)

图 7.16

接下来，我们需要将来自 Google 测试框架的以下源文件添加到我们的静态库项目中：

```cpp
C:\Users\jegan\googletest\googletest\src\gtest-all.cc
C:\Users\jegan\googletest\googlemock\src\gmock-all.cc
C:\Users\jegan\googletest\googlemock\src\gmock_main.cc
```

为了编译静态库，我们需要在`GoogleTestLib/Properties/VC++ Directories/Include`目录中包含以下头文件路径：

```cpp
C:\Users\jegan\googletest\googletest
C:\Users\jegan\googletest\googletest\include
C:\Users\jegan\googletest\googlemock
C:\Users\jegan\googletest\googlemock\include
```

您可能需要根据在系统中复制/安装 Google 测试框架的位置来自定义路径。

现在是时候将`MathTestApp` Win32 控制台应用程序添加到`MathApp`解决方案中了。我们需要将`MathTestApp`设置为`StartUp`项目，以便可以直接执行此应用程序。在添加名为`MathTest.cpp`的新源文件到`MathTestApp`项目之前，请确保`MathTestApp`项目中没有源文件。

我们需要配置与`GoogleTestLib`静态库中添加的相同一组 Google 测试框架包含路径。除此之外，我们还必须将`MathApp`项目目录添加为测试项目将引用的头文件，如下所示。但是，根据您在系统中为此项目遵循的目录结构，自定义路径：

```cpp
C:\Users\jegan\googletest\googletest
C:\Users\jegan\googletest\googletest\include
C:\Users\jegan\googletest\googlemock
C:\Users\jegan\googletest\googlemock\include
C:\Projects\MasteringC++Programming\MathApp\MathApp
```

在`MathAppTest`项目中，确保您已经添加了对`MathApp`和`GoogleTestLib`的引用，以便在它们发生更改时，`MathAppTest`项目将编译其他两个项目。

太好了！我们快要完成了。现在让我们实现`MathTest.cpp`，如*图 7.17*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/426f9b27-1907-472a-b0a3-c28e496f1112.png)

图 7.17

现在一切准备就绪，让我们运行测试用例并检查结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/d100a0ee-81f9-41f7-91a3-0c7de0c1908d.png)

图 7.18

# TDD 实践

让我们看看如何开发一个遵循 TDD 方法的**逆波兰表达式**（**RPN**）计算器应用程序。RPN 也被称为后缀表示法。RPN 计算器应用程序的期望是接受后缀数学表达式作为输入，并将计算结果作为输出返回。

我想逐步演示如何在开发应用程序时遵循 TDD 方法。作为第一步，我想解释项目目录结构，然后我们将继续。让我们创建一个名为`Ex2`的文件夹，其结构如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/9a15c754-3b1f-428e-813f-4f2a87fe7258.png)

图 7.19

`googletest`文件夹是具有必要的`gtest`和`gmock`头文件的 gtest 测试库。现在`libgtest.a`是我们在上一个练习中创建的 Google 测试静态库。我们将使用`make`实用程序来构建我们的项目，因此我已经将`Makefile`放在项目`home`目录中。`src`目录将保存生产代码，而测试目录将保存我们将要编写的所有测试用例。

在我们开始编写测试用例之前，让我们来看一个后缀数学表达式“2 5 * 4 + 3 3 * 1 + /”，并了解我们将应用于评估逆波兰数学表达式的标准后缀算法。根据后缀算法，我们将逐个标记地解析逆波兰数学表达式。每当我们遇到一个操作数（数字）时，我们将把它推入栈中。每当我们遇到一个运算符时，我们将从栈中弹出两个值，应用数学运算，将中间结果推回栈中，并重复该过程，直到在逆波兰表达式中评估所有标记。最后，当输入字符串中没有更多的标记时，我们将弹出该值并将其打印为结果。该过程在下图中逐步演示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/057ac184-3b3e-4fcf-9617-9c3ddf84c354.png)

图 7.20

首先，让我们以一个简单的后缀数学表达式开始，并将情景转化为一个测试用例：

```cpp
Test Case : Test a simple addition
Input: "10 15 +"
Expected Output: 25.0
```

让我们将前面的测试用例翻译为测试文件夹中的 Google 测试，如下所示：

```cpp
test/RPNCalculatorTest.cpp

TEST ( RPNCalculatorTest, testSimpleAddition ) { 
         RPNCalculator rpnCalculator; 
         double actualResult = rpnCalculator.evaluate ( "10 15 +" ); 
         double expectedResult = 25.0; 
         EXPECT_EQ ( expectedResult, actualResult ); 
}
```

为了编译前面的测试用例，让我们在`src`文件夹中编写所需的最小生产代码，如下所示：

```cpp
src/RPNCalculator.h

#include <iostream>
#include <string>
using namespace std;

class RPNCalculator {
  public:
      double evaluate ( string );
};
```

由于 RPN 数学表达式将作为以空格分隔的字符串提供，因此评估方法将接受一个字符串输入参数：

```cpp
src/RPNCalculator.cpp

#include "RPNCalculator.h"

double RPNCalculator::evaluate ( string rpnMathExpression ) {
    return 0.0;
}
```

以下`Makefile`类帮助每次编译生产代码时运行测试用例：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/7f46e005-c5c5-40d0-bded-77c7d0005b7b.png)

图 7.21

现在让我们构建并运行测试用例，并检查测试用例的结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/dc5b5ecf-28fb-423d-abdc-f98ba1516cce.png)

图 7.22

在 TDD 中，我们总是从一个失败的测试用例开始。失败的原因是期望的结果是 25，而实际结果是 0。原因是我们还没有实现评估方法，因此我们已经硬编码为返回 0，而不管任何输入。因此，让我们实现评估方法以使测试用例通过。

我们需要修改`src/RPNCalculator.h`和`src/RPNCalculator.cpp`如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/df9a2b2e-f7b8-44f0-a857-5f608e71284c.png)

图 7.23

在 RPNCalculator.h 头文件中，注意包含的新头文件，用于处理字符串标记化和字符串双精度转换，并将 RPN 标记复制到向量中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/1d6680ea-c84b-4cec-9970-a8f634e11907.png)

图 7.24

根据标准的后缀算法，我们使用一个栈来保存在逆波兰表达式中找到的所有数字。每当我们遇到`+`数学运算符时，我们从栈中弹出两个值相加，然后将结果推回栈中。如果标记不是`+`运算符，我们可以安全地假定它是一个数字，所以我们只需将该值推送到栈中。

有了前面的实现，让我们尝试测试用例，并检查测试用例是否通过：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/ecb11d2d-abab-4ed2-b958-26dd5f060d72.png)

图 7.25

很好，我们的第一个测试用例如预期地通过了。现在是时候考虑另一个测试用例了。这次，让我们添加一个减法的测试用例：

```cpp
Test Case : Test a simple subtraction
Input: "25 10 -"
Expected Output: 15.0
```

让我们将前面的测试用例翻译为测试文件夹中的 Google 测试，如下所示：

```cpp
test/RPNCalculatorTest.cpp

TEST ( RPNCalculatorTest, testSimpleSubtraction ) { 
         RPNCalculator rpnCalculator; 
         double actualResult = rpnCalculator.evaluate ( "25 10 -" ); 
         double expectedResult = 15.0; 
         EXPECT_EQ ( expectedResult, actualResult ); 
}
```

通过将前面的测试用例添加到`test/RPNCalculatorTest`中，现在应该如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/1fff5058-d457-471b-802c-a5f8ff001a5f.png)

图 7.26

让我们执行测试用例并检查我们的新测试用例是否通过：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/0a6c83e3-7724-40f5-bb08-847a7e1baea0.png)

图 7.27

正如预期的那样，新的测试失败了，因为我们还没有在应用程序中添加对减法的支持。这是非常明显的，根据 C++异常，因为代码试图将减法`-`操作符转换为一个数字。让我们在我们的 evaluate 方法中添加对减法逻辑的支持：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/619fc762-2234-42e5-bfc5-30d0134c4691.png)

图 7.28

是时候测试了。让我们执行测试案例，检查事情是否正常：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/919d804c-5617-4f91-8c5a-1fc00f59d9a8.png)

图 7.29

酷！你注意到我们的测试案例在这种情况下失败了吗？等一下。如果测试案例失败了，为什么我们会兴奋呢？我们应该高兴的原因是我们的测试案例发现了一个 bug；毕竟，这是 TDD 的主要目的，不是吗？

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/f356de93-2fab-434b-acf8-cacf1af1f182.png)

图 7.30

失败的根本原因是栈是基于**后进先出**（**LIFO**）操作，而我们的代码假设是先进先出。你注意到我们的代码假设它会先弹出第一个数字，而实际上它应该先弹出第二个数字吗？有趣的是，这个 bug 在加法操作中也存在；然而，由于加法是可结合的，这个 bug 被抑制了，但减法测试案例检测到了它。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/bcd7edd0-6555-4706-8943-673796f00748.png)

图 7.31

让我们按照前面的截图修复 bug，并检查测试案例是否通过：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/b5f684c5-bd45-4f42-b96a-083351d8f5ba.png)

图 7.32

太棒了！我们修复了 bug，我们的测试案例似乎证明它们已经修复了。让我们添加更多的测试案例。这一次，让我们添加一个测试案例来验证乘法：

```cpp
Test Case : Test a simple multiplication
Input: "25 10 *"
Expected Output: 250.0
```

让我们将前面的测试案例翻译成测试文件中的谷歌测试，如下所示：

```cpp
test/RPNCalculatorTest.cpp

TEST ( RPNCalculatorTest, testSimpleMultiplication ) { 
         RPNCalculator rpnCalculator; 
         double actualResult = rpnCalculator.evaluate ( "25 10 *" ); 
         double expectedResult = 250.0; 
         EXPECT_EQ ( expectedResult, actualResult ); 
}
```

我们知道这次测试案例将会失败，所以让我们快进并看一下除法测试案例：

```cpp
Test Case : Test a simple division
Input: "250 10 /"
Expected Output: 25.0
```

让我们将前面的测试案例翻译成测试文件中的谷歌测试，如下所示：

```cpp
test/RPNCalculatorTest.cpp

TEST ( RPNCalculatorTest, testSimpleDivision ) { 
         RPNCalculator rpnCalculator; 
         double actualResult = rpnCalculator.evaluate ( "250 10 /" ); 
         double expectedResult = 25.0; 
         EXPECT_EQ ( expectedResult, actualResult );
}
```

让我们跳过测试结果，继续进行一个涉及许多操作的最终复杂表达式测试案例：

```cpp
Test Case : Test a complex rpn expression
Input: "2  5  *  4  + 7  2 -  1  +  /"
Expected Output: 25.0
```

让我们将前面的测试案例翻译成测试文件中的谷歌测试，如下所示：

```cpp
test/RPNCalculatorTest.cpp

TEST ( RPNCalculatorTest, testSimpleDivision ) { 
         RPNCalculator rpnCalculator; 
         double actualResult = rpnCalculator.evaluate ( "250 10 /" ); 
         double expectedResult = 25.0; 
         EXPECT_EQ ( expectedResult, actualResult );
}
```

让我们检查一下我们的 RPNCalculator 应用程序是否能够评估一个涉及加法、减法、乘法和除法的复杂逆波兰表达式，这是一个测试案例：

```cpp
test/RPNCalculatorTest.cpp

TEST ( RPNCalculatorTest, testComplexExpression ) { 
         RPNCalculator rpnCalculator; 
         double actualResult = rpnCalculator.evaluate ( "2  5  *  4  +  7  2 - 1 +  /" ); 
         double expectedResult = 2.33333; 
         ASSERT_NEAR ( expectedResult, actualResult, 4 );
}
```

在前面的测试案例中，我们正在检查预期结果是否与实际结果匹配，精确到小数点后四位。如果超出这个近似值，那么测试案例应该失败。

现在让我们检查测试案例的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/35093b62-507c-4bf7-a875-a9d88c32fb1d.png)

图 7.33

太棒了！所有的测试案例都是绿色的。

现在让我们看看我们的生产代码，检查是否有改进的空间：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/15296ad3-a773-4988-a0e3-dee2bc67b4cf.png)

图 7.34

代码在功能上是好的，但有很多代码异味。这是一个长方法，有嵌套的`if-else`条件和重复的代码。TDD 不仅仅是关于测试自动化；它也是关于编写没有代码异味的好代码。因此，我们必须重构代码，使其更模块化，减少代码复杂性。

在这里，我们可以应用多态性或策略设计模式，而不是嵌套的`if-else`条件。此外，我们可以使用工厂方法设计模式来创建各种子类型。还有使用空对象设计模式的空间。

最好的部分是，我们不必担心在重构过程中破坏我们的代码的风险，因为我们有足够多的测试案例来在我们破坏代码时给我们反馈。

首先，让我们了解如何重构*图 7.35*中所示的 RPNCalculator 设计：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/637663f8-f8fd-4341-9d18-370b9aa67b57.png)

图 7.35

根据前面的设计重构方法，我们可以将 RPNCalculator 重构如*图 7.36*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/a294fac9-1525-4ee7-8d24-5d4783067e3c.png)

图 7.36

如果您比较重构前后的`RPNCalculator`代码，您会发现重构后代码的复杂性大大减少。

`MathFactory`类可以按*图 7.37*所示实现：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/2e3ef9c1-c5bf-4cab-b5da-08654b08f7b8.png)

图 7.37

尽可能地，我们必须努力避免`if-else`条件，或者一般来说，我们必须尽量避免代码分支。因此，STL map 用于避免 if-else 条件。这也促进了相同的 Math 对象的重复使用，无论 RPN 表达式的复杂性如何。

如果您参考*图 7.38*，您将了解`MathOperator Add`类的实现方式：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/e1833a0f-7900-4459-b0da-3de4d0e80a6b.png)

图 7.38

`Add`类的定义如*图 7.39*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/5ece59b7-4372-4c3e-b0be-cdd4c1653775.png)

图 7.39

减法、乘法和除法类可以以类似的方式实现，作为`Add`类。重点是，在重构后，我们可以将单个`RPNCalculator`类重构为更小且易于维护的类，可以单独进行测试。

让我们看一下重构后的`Makefile`类，如*图 7.40*所示，并在重构过程完成后测试我们的代码：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/6c0b43af-ea8c-4227-aa23-028c1974a486.png)

图 7.40

如果一切顺利，重构后我们应该看到所有测试用例通过，如果没有功能被破坏，如*图 7.41*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/e22788c8-417b-48aa-9d8a-6bc44f7c0682.png)

图 7.41

太棒了！所有测试用例都通过了，因此可以保证我们在重构过程中没有破坏功能。TDD 的主要目的是编写既具有功能性又结构清晰的可测试代码。

# 测试具有依赖关系的遗留代码

在上一节中，CUT 是独立的，没有依赖，因此它测试代码的方式是直接的。然而，让我们讨论一下如何对具有依赖关系的 CUT 进行单元测试。为此，请参考以下图片：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/da8d052b-b313-4595-bb57-c348f0ea2b2c.png)

图 7.42

在*图 7.42*中，显然**Mobile**依赖于**Camera**，而**Mobile**和**Camera**之间的关联是*组合*。让我们看看遗留应用程序中`Camera.h`头文件的实现：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/389f8f60-fd8d-4d57-bc86-4ec5f5d8bb10.png)

图 7.43

为了演示目的，让我们来看一个简单的`Camera`类，具有`ON()`和`OFF()`功能。让我们假设 ON/OFF 功能将在内部与相机硬件交互。查看*图 7.44*中的`Camera.cpp`源文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/a7dfb6d6-4c79-4c8f-ad10-84eca6e307c1.png)

图 7.44

出于调试目的，我添加了一些打印语句，这在我们测试移动的`powerOn()`和`powerOff()`功能时会很有用。现在让我们检查*图 7.45*中的`Mobile`类头文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/015a0d92-6d60-4517-bc9e-e894070568e5.png)

图 7.45

我们继续移动实现，如*图 7.46*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/5f737e0c-f513-4c71-b6ed-8863bf39e57d.png)

图 7.46

从`Mobile`构造函数的实现中，可以明显看出移动设备具有相机，或者更确切地说是组合关系。换句话说，`Mobile`类是构造`Camera`对象的类，如*图 7.46*，*第 21 行*在构造函数中显示。让我们尝试看一下测试`Mobile`的`powerOn()`功能所涉及的复杂性；依赖关系与 Mobile 的 CUT 具有组合关系。

让我们编写`powerOn()`测试用例，假设相机已成功打开，如下所示：

```cpp
TEST ( MobileTest, testPowerOnWhenCameraONSucceeds ) {

     Mobile mobile;
     ASSERT_TRUE ( mobile.powerOn() );

}
```

现在让我们尝试运行`Mobile`测试用例并检查测试结果，如*图 7.47*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/60469fae-b843-4209-80bc-bfe82d8a56f8.png)

图 7.47

从*图 7.47*中，我们可以理解`Mobile`的`powerOn()`测试用例已经通过。但是，我们也了解到`Camera`类的真正`ON()`方法也被调用了。这反过来将与相机硬件进行交互。归根结底，这不是一个单元测试，因为测试结果并不完全取决于 CUT。如果测试用例失败，我们将无法确定失败是由于移动设备`powerOn()`逻辑中的代码还是相机`ON()`逻辑中的代码，这将违背我们测试用例的目的。理想的单元测试应该使用依赖注入隔离 CUT 与其依赖项，并测试代码。这种方法将帮助我们识别 CUT 在正常或异常情况下的行为。理想情况下，当单元测试用例失败时，我们应该能够猜测失败的根本原因，而无需调试代码；只有当我们设法隔离 CUT 的依赖项时，才有可能做到这一点。

这种方法的关键好处是，即使在实现依赖项之前，也可以测试 CUT，这有助于在没有依赖项的情况下测试 60~70％的代码。这自然减少了软件产品上市的时间。

这就是 Google 模拟或 gmock 派上用场的地方。让我们看看如何重构我们的代码以实现依赖注入。虽然听起来非常复杂，但重构代码所需的工作并不复杂。实际上，重构生产代码所需的工作可能更复杂，但这是值得的。让我们来看一下重构后的`Mobile`类，如*图 7.48*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/21ef199b-01fe-4269-a5d5-7cfdfddeac7d.png)

图 7.48

在`Mobile`类中，我添加了一个接受相机作为参数的重载构造函数。这种技术称为**构造函数依赖注入**。让我们看看这种简单而强大的技术如何在测试`Mobile`的`powerOn()`功能时帮助我们隔离相机依赖。

此外，我们必须重构`Camera.h`头文件，并将`ON()`和`OFF()`方法声明为虚拟方法，以便 gmock 框架帮助我们存根这些方法，如*图 7.49*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/41a26e55-9c5b-4460-8b24-719aa14ddc46.png)

图 7.49

现在让我们根据*图 7.50*进行重构我们的测试用例：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/e5a68754-6e5b-438f-b371-d436b14839ee.png)

图 7.50

我们已经准备好构建和执行测试用例。测试结果如*图 7.51*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-prog/img/891b46ea-a0ee-4c8d-aa74-61e529188708.png)

图 7.51

太棒了！我们的测试用例不仅通过了，而且我们还将我们的 CUT 与其相机依赖隔离开来，这很明显，因为我们没有看到相机的`ON()`方法的打印语句。最重要的是，您现在已经学会了如何通过隔离其依赖项来对代码进行单元测试。

快乐的 TDD！

# 总结

在本章中，您学到了很多关于 TDD 的知识，以下是关键要点的总结：

+   TDD 是一种极限编程（XP）实践

+   TDD 是一种自下而上的方法，鼓励我们从测试用例开始，因此通常被称为小写测试优先开发

+   您学会了如何在 Linux 和 Windows 中使用 Google Test 和 Google Mock 框架编写测试用例

+   您还学会了如何在 Linux 和 Windows 平台上的 Visual Studio 中编写遵循 TDD 的应用程序

+   您学会了依赖反转技术以及如何使用 Google Mock 框架隔离其依赖项对代码进行单元测试

+   Google Test 框架支持单元测试、集成测试、回归测试、性能测试、功能测试等

+   TDD 主要坚持单元测试、集成测试和交互测试，而复杂的功能测试必须使用行为驱动开发来完成

+   您学会了如何将代码异味重构为干净的代码，同时您编写的单元测试用例会给出持续的反馈

你已经学会了 TDD 以及如何以自下而上的方式自动化单元测试用例、集成测试用例和交互测试用例。有了 BDD，你将学会自上而下的开发方法，编写端到端的功能和测试用例，以及我们在讨论 TDD 时没有涵盖的其他复杂测试场景。

在下一章中，你将学习行为驱动开发。
