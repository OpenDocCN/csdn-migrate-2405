# Linux 系统编程技巧（五）

> 原文：[`zh.annas-archive.org/md5/450F8760AE780F24827DDA7979D9DDE8`](https://zh.annas-archive.org/md5/450F8760AE780F24827DDA7979D9DDE8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：在程序中使用线程

在本章中，我们将学习什么是线程以及如何在 Linux 中使用它们。 我们将使用**POSIX 线程**（也称为**pthreads**）编写几个程序。 我们还将学习什么是竞争条件，以及如何使用互斥锁来防止它们。 然后，我们将学习如何使互斥程序更高效。 最后，我们将学习什么是条件变量。

知道如何编写多线程程序将使它们更快，更高效。

在本章中，我们将涵盖以下示例：

+   编写你的第一个多线程程序

+   从线程读取返回值

+   引发竞争条件

+   使用互斥锁避免竞争条件

+   使互斥程序更高效

+   使用条件变量

让我们开始吧！

# 技术要求

对于本章，您将需要 GCC 编译器，Make 工具和通用 Makefile。 如果您尚未安装这些工具，请参考[*第一章*]（B13043_01_Final_SK_ePub.xhtml#_idTextAnchor020），*获取必要的工具并编写我们的第一个 Linux 程序*，以获取安装说明。

您还需要一个名为`htop`的程序来查看 CPU 负载。 您可以使用发行版的软件包管理器安装它。 所有发行版都称该程序为`htop`。

本章的所有代码示例都可以从 GitHub 下载，网址如下：[`github.com/PacktPublishing/Linux-System-Programming-Techniques/tree/master/ch11`](https://github.com/PacktPublishing/Linux-System-Programming-Techniques/tree/master/ch11)。

查看以下链接以查看代码演示视频：[`bit.ly/2O4dnlN`](https://bit.ly/2O4dnlN)

# 编写你的第一个多线程程序

在这个第一个示例中，我们将编写一个小程序，检查两个数字是否为质数-并行进行。 在检查这两个数字时，每个数字都在自己的**线程**中，另一个线程将在终端中写入点以指示程序仍在运行。 该程序将运行三个线程。 每个线程将打印自己的结果，因此在此程序中不需要保存和返回值。

了解线程的基础知识将为进一步学习更高级的程序打下基础。

## 做好准备

对于这个示例，您将需要`htop`程序，以便您可以看到两个 CPU 核心的**CPU**负载增加。 当然，其他类似的程序也可以工作，例如**KDE**的**K Desktop Environment**（**KDE**）的 KSysGuard。 如果您的计算机有多个 CPU **core**，那就更好了。 大多数计算机今天都有多个核心，即使是树莓派和类似的小型计算机，所以这不应该是一个问题。 即使您只有单核 CPU，该程序仍然可以工作，但是很难可视化线程。

你还需要 GCC 编译器和 Make 工具。

## 如何做…

在本章中，我们将使用`Makefile`。 注意添加的`-lpthread`，这是通用 Makefile 中没有的东西：

```
CC=gcc
```

```
CFLAGS=-Wall -Wextra -pedantic -std=c99 -lpthread
```

现在，让我们继续编写程序。 代码有点长，所以它被分成了几个步骤。 尽管所有的代码都放在一个文件中。 将代码保存为`first-threaded.c`：

1.  让我们从头文件开始，一些函数原型，`main()`函数和一些必要的变量。 注意新的头文件`pthread.h`。 我们还有一个新类型，称为`pthread_t`。 此类型用于线程 ID。 还有一个`pthread_attr_t`类型，用于线程的属性。 我们还执行检查，以查看用户是否输入了两个参数（将检查这些参数是否为质数）。 然后，我们将使用`atoll()`将第一个和第二个参数转换为`long long`整数：

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
void *isprime(void *arg);
void *progress(void *arg);
int main(int argc, char *argv[])
{
   long long number1;
   long long number2;
   pthread_t tid_prime1;
   pthread_t tid_prime2;
   pthread_t tid_progress;
   pthread_attr_t threadattr;
   if ( argc != 3 )
   {
      fprintf(stderr, "Please supply two numbers.\n"
         "Example: %s 9 7\n", argv[0]);
      return 1;
   }
   number1 = atoll(argv[1]);
   number2 = atoll(argv[2]);
```

1.  接下来，我们将使用`pthread_attr_init()`初始化线程属性结构`threadattr`，并使用一些默认设置。

然后，我们将使用`pthread_create()`创建三个线程。`pthread_create()`函数有四个参数。第一个参数是线程 ID 变量；第二个参数是线程的属性；第三个参数是将在线程中执行的函数；第四个参数是该函数的参数。我们还将使用`pthread_detach()`将"进度条"线程标记为分离状态，这样当线程终止时，线程的资源将自动释放：

```
   pthread_attr_init(&threadattr);
   pthread_create(&tid_progress, &threadattr, 
      progress, NULL); 
   pthread_detach(tid_progress);
   pthread_create(&tid_prime1, &threadattr, 
      isprime, &number1);
   pthread_create(&tid_prime2, &threadattr, 
      isprime, &number2);
```

1.  为了使程序等待所有线程完成，我们必须为每个线程使用`pthread_join()`。请注意，我们不等待进度线程，但我们确实将其标记为分离状态。在这里，我们将在退出程序之前取消进度线程，使用`pthread_cancel()`：

```
   pthread_join(tid_prime1, NULL);
   pthread_join(tid_prime2, NULL);
   pthread_attr_destroy(&threadattr);
   if ( pthread_cancel(tid_progress) != 0 )
      fprintf(stderr, 
         "Couldn't cancel progress thread\n");
   printf("Done!\n");
   return 0;
}
```

1.  现在是时候编写将计算给定数字是否为质数的函数体了。请注意，函数的返回类型是 void 指针。参数也是 void 指针。这是`pthread_create()`要求的。由于参数是 void 指针，而我们希望它是`long long int`，因此我们必须先进行转换。我们通过将 void 指针转换为`long long int`并将其指向的内容保存在一个新变量中来实现这一点（有关更详细的选项，请参阅*参见*部分）。请注意，在这个函数中我们返回`NULL`。这是因为我们必须返回*something*，所以在这里使用`NULL`就可以了：

```
void *isprime(void *arg)
{
   long long int number = *((long long*)arg);
   long long int j;
   int prime = 1;

   /* Test if the number is divisible, starting 
    * from 2 */
   for(j=2; j<number; j++)
   {
      /* Use the modulo operator to test if the 
       * number is evenly divisible, i.e., a 
       * prime number */
      if(number%j == 0)
      {
         prime = 0;
      }
   }
   if(prime == 1)
   {
      printf("\n%lld is a prime number\n", 
         number);
      return NULL;
   }
   else
   {
      printf("\n%lld is not a prime number\n", 
         number);
      return NULL;
   }
}
```

1.  最后，我们编写进度表的函数。它并不是真正的进度表；它只是每秒打印一个点，以向用户显示程序仍在运行。在调用`printf()`后，我们必须使用`fflush()`，因为我们没有打印任何换行符（请记住 stdout 是行缓冲的）：

```
void *progress(void *arg)
{
   while(1)
   {
      sleep(1);
      printf(".");
      fflush(stdout);
   }
   return NULL;
}
```

1.  现在是时候使用我们的新 Makefile 编译程序了。请注意，我们收到了一个关于未使用的变量的警告。这是进度函数的`arg`变量。我们可以放心地忽略这个警告，因为我们知道我们没有使用它。

```
$> make first-threaded
gcc -Wall -Wextra -pedantic -std=c99 -lpthread    first-threaded.c   -o first-threaded
first-threaded.c: In function 'progress':
first-threaded.c:71:22: warning: unused parameter 'arg' [-Wunused-parameter]
 void *progress(void *arg)
```

1.  现在，在运行程序之前，打开一个新的终端并在其中启动`htop`。将它放在一个可以看到的地方。

1.  现在在第一个终端中运行程序。选择两个数字，不要太小，以至于程序会立即完成，但也不要太大，以至于程序会永远运行。对我来说，以下数字足够大，可以使程序运行大约一分半钟。这将取决于 CPU。在运行程序时，检查`htop`程序。您会注意到两个核心将使用 100%，直到计算第一个数字，然后它将只使用一个核心以 100%：

```
$> ./first-threaded 990233331 9902343047
..........
990233331 is not a prime number
...............................................................................
9902343047 is a prime number
Done!
```

## 工作原理...

两个数字分别在各自的线程中进行检查。与非线程化程序相比，这加快了进程。非线程化程序将依次检查每个数字。也就是说，第二个数字必须等到第一个数字完成后才能进行检查。但是使用线程化程序，就像我们在这里做的一样，可以同时检查两个数字。

`isprime()`函数是进行计算的地方。相同的函数用于两个线程。我们还为两个线程使用相同的默认属性。

我们通过为每个数字调用`pthread_create()`在线程中执行函数。请注意，在`pthread_create()`参数中的`isprime()`函数后面没有括号。在函数名后面加上括号会执行该函数。但是，我们希望`pthread_create()`函数执行该函数。

由于我们不会调用`pthread_cancel()`，我们将其标记为分离状态，以便在线程终止时释放其资源。我们使用`pthread_detach()`将其标记为分离状态。

默认情况下，线程具有其自己的`sleep()`函数是其中之一；因此，进度线程将在执行`sleep()`后取消。*可取消类型*可以更改为异步，这意味着它可以随时取消。

在`main()`函数的末尾，我们对两个线程 ID（执行`isprime()`的线程）调用了`pthread_join()`。这是必要的，以使进程等待线程完成；否则，它会立即结束。`pthread_join()`的第一个参数是线程 ID。第二个参数是一个变量，可以保存线程的返回值。但由于我们对返回值不感兴趣——它只返回`NULL`——我们将其设置为`NULL`，以忽略它。

## 还有更多…

要更改线程的*可取消性状态*，您可以使用`pthread_setcancelstate()`。有关更多信息，请参阅`man 3 pthread_setcancelstate`。

要更改线程的*可取消性类型*，您可以使用`pthread_setcanceltype()`。有关更多信息，请参阅`man 3 pthread_setcanceltype`。

要查看哪些函数是`man 7 pthreads`，并在该手册页面中搜索*取消点*。

从 void 指针转换为`long long int`可能看起来有点神秘。与我们在这里所做的一样，不要一行搞定：

```
long long int number = *((long long*)arg);
```

我们可以分两步写，这样会更详细一些，就像这样：

```
long long int *number_ptr = (long long*)arg;
```

```
long long int number = *number_ptr;
```

## 另请参阅

`pthread_create()`和`pthread_join()`的手册页面中有很多有用的信息。您可以使用`man 3 pthread_create`和`man 3 pthread_join`来阅读它们。

有关`pthread_detach()`的更多信息，请参阅`man 3 pthread_detach`。

有关`pthread_cancel()`的信息，请参阅`man 3 pthread_cancel`。

# 从线程中读取返回值

在这个配方中，我们将继续上一个配方。在这里，我们将从线程中获取答案作为**返回值**，而不是让它们自己打印结果。这就像从函数中返回值一样。

知道如何从线程中获取返回值使您能够用线程做更复杂的事情。

## 准备工作

为了使这个配方有意义，建议您先完成上一个配方。

您还需要我们在上一个配方中编写的 Makefile。

## 操作方法…

这个程序与上一个配方类似，但是每个线程不是打印自己的结果，而是将结果返回给`main()`。这类似于函数将值返回给`main()`，只是这里我们需要来回进行一些**转换**。这种方法的缺点是，除非我们有意将最小的数字给第一个线程，否则在两个线程都完成之前我们看不到结果。如果第一个线程有最大的数字，那么在第二个线程完成之前，即使它已经完成，我们也看不到第二个线程的结果。然而，即使我们看不到结果立即打印出来，它们仍然在两个独立的线程中进行处理，就像以前一样：

1.  代码很长，因此被分成了几个步骤。将代码写在名为`second-threaded.c`的单个文件中。和往常一样，我们从头文件、函数原型和`main()`函数的开头开始。请注意，这里有一个额外的头文件，名为`stdint.h`。这是为了`uintptr_t`类型，我们将把返回值转换为该类型。这比转换为`int`更安全，因为这保证与我们转换的指针大小相同。我们还创建了两个 void 指针（`prime1Return`和`prime2Return`），我们将保存返回值。除了这些更改，其余代码都是一样的：

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
void *isprime(void *arg);
void *progress(void *arg);
int main(int argc, char *argv[])
{
   long long number1;
   long long number2;
   pthread_t tid_prime1;
   pthread_t tid_prime2;
   pthread_t tid_progress;
   pthread_attr_t threadattr;
   void *prime1Return;
   void *prime2Return;
   if ( argc != 3 )
   {
      fprintf(stderr, "Please supply two numbers.\n"
         "Example: %s 9 7\n", argv[0]);
      return 1;
   }
   number1 = atoll(argv[1]);
   number2 = atoll(argv[2]);
   pthread_attr_init(&threadattr);
   pthread_create(&tid_progress, &threadattr, 
      progress, NULL);  
   pthread_detach(tid_progress);
   pthread_create(&tid_prime1, &threadattr, 
      isprime, &number1);
   pthread_create(&tid_prime2, &threadattr, 
      isprime, &number2);
```

1.  在下一部分中，我们将之前创建的 void 指针作为`pthread_join()`的第二个参数，或者实际上是这些变量的地址。这将把线程的返回值保存在这些变量中。然后，我们检查这些返回值，看看这些数字是否是质数。但由于变量是 void 指针，我们必须首先将其转换为`unitptr_t`类型：

```
   pthread_join(tid_prime1, &prime1Return);
   if (  (uintptr_t)prime1Return == 1 )
      printf("\n%lld is a prime number\n", 
         number1);
   else
      printf("\n%lld is not a prime number\n", 
         number1);

   pthread_join(tid_prime2, &prime2Return);   
   if ( (uintptr_t)prime2Return == 1 )
      printf("\n%lld is a prime number\n", 
         number2);
   else
      printf("\n%lld is not a prime number\n", 
         number2);

   pthread_attr_destroy(&threadattr);
   if ( pthread_cancel(tid_progress) != 0 )
      fprintf(stderr, 
         "Couldn't cancel progress thread\n");
   return 0;
}
```

1.  然后我们像以前一样有函数。但是这次，我们返回 0 或 1，转换为 void 指针（因为函数声明的就是这样，我们不能违反）：

```
void *isprime(void *arg)
{
   long long int number = *((long long*)arg);
   long long int j;
   int prime = 1;

   /* Test if the number is divisible, starting 
    * from 2 */
   for(j=2; j<number; j++)
   {
      /* Use the modulo operator to test if the 
       * number is evenly divisible, i.e., a 
       * prime number */
      if(number%j == 0)
         prime = 0;
   }
   if(prime == 1)
      return (void*)1;
   else
      return (void*)0;
}
void *progress(void *arg)
{
   while(1)
   {
      sleep(1);
      printf(".");
      fflush(stdout);
   }
   return NULL;
}
```

1.  现在，让我们编译程序。我们仍然会收到关于未使用变量的相同警告，但这是安全的。我们知道我们没有用它做任何事情。

```
$> make second-threaded
gcc -Wall -Wextra -pedantic -std=c99 -lpthread    second-threaded.c   -o second-threaded
second-threaded.c: In function 'progress':
second-threaded.c:79:22: warning: unused parameter 'arg' [-Wunused-parameter]
 void *progress(void *arg)
                ~~~~~~^~~
```

1.  现在让我们尝试运行程序，首先使用更大的数字作为第一个参数，然后使用较小的数字作为第一个参数：

```
$> ./second-threaded 9902343047 99023117
......................................................................................
9902343047 is a prime number
99023117 is not a prime number
$> ./second-threaded 99023117 9902343047
.
99023117 is not a prime number
.......................................................................................
9902343047 is a prime number
```

## 工作原理…

这个程序的基本原理与上一个教程中的相同。不同之处在于，我们将计算结果从线程返回到`main()`，就像一个函数一样。但由于我们`isprime()`函数的返回值是一个 void 指针，我们还必须返回这种类型。为了保存返回值，我们将一个变量的地址作为`pthread_join()`的第二个参数传递。

由于每次调用`pthread_join()`都会阻塞，直到其线程完成，我们在两个线程都完成之前不会得到结果（除非我们首先给出最小的数字）。

我们在本教程中使用的新类型`uintptr_t`是一个特殊类型，它与无符号整数指针的大小匹配。使用常规的`int`可能也可以，但不能保证。

# 导致竞争条件

竞争条件是指多个线程（或进程）同时尝试写入同一变量的情况。由于我们不知道哪个线程会首先访问该变量，我们无法安全地预测会发生什么。两个线程都会尝试首先访问它；它们会争先访问该变量。

了解是什么导致了竞争条件将有助于避免它们，使您的程序更安全。

## 准备工作

在本教程中，您只需要本章第一个教程中编写的 Makefile，以及 GCC 编译器和 Make 工具。

## 如何做…

在本教程中，我们将编写一个导致竞争条件的程序。如果程序能正常工作，它应该在每次运行时将 1 添加到`i`变量，最终达到 5,000,000,000。有五个线程，每个线程都将 1 添加到 1,000,000,000。但由于所有线程几乎同时访问`i`变量，它永远不会达到 5,000,000,000。每次线程访问它时，它都会获取当前值并添加 1。但在此期间，另一个线程可能也读取当前值并添加 1，然后覆盖另一个线程添加的 1。换句话说，线程正在覆盖彼此的工作：

1.  代码分为几个步骤。请注意，所有代码都放在一个文件中。将文件命名为`race.c`。我们将从头文件开始，`i`的类型为`long long int`。然后编写`main()`函数，这是相当简单的。它使用`pthread_create()`创建五个线程，然后使用`pthread_join()`等待它们完成。最后，它打印出结果变量`i`：

```
#include <stdio.h>
#include <pthread.h>
void *add(void *arg);
long long int i = 0;
int main(void)
{
   pthread_attr_t threadattr;
   pthread_attr_init(&threadattr);
   pthread_t tid_add1, tid_add2, tid_add3, 
     tid_add4, tid_add5;
   pthread_create(&tid_add1, &threadattr, 
      add, NULL);
   pthread_create(&tid_add2, &threadattr, 
      add, NULL);
   pthread_create(&tid_add3, &threadattr, 
      add, NULL);
   pthread_create(&tid_add4, &threadattr, 
      add, NULL);
   pthread_create(&tid_add5, &threadattr, 
      add, NULL);
   pthread_join(tid_add1, NULL);
   pthread_join(tid_add2, NULL);
   pthread_join(tid_add3, NULL);
   pthread_join(tid_add4, NULL);
   pthread_join(tid_add5, NULL);
   printf("Sum is %lld\n", i);
   return 0;
}
```

1.  现在我们编写`add()`函数，该函数将在线程内运行：

```
void *add(void *arg)
{
   for (long long int j = 1; j <= 1000000000; j++)
   {
      i = i + 1;
   }
   return NULL;
}
```

1.  让我们编译程序。再次忽略警告是安全的：

```
$> make race
gcc -Wall -Wextra -pedantic -std=c99 -lpthread    race.c   -o race
race.c: In function 'add':
race.c:35:17: warning: unused parameter 'arg' [-Wunused-parameter]
 void *add(void *arg)
           ~~~~~~^~~
```

1.  现在，让我们尝试运行程序。我们将运行它多次。请注意，每次运行时，我们都会得到不同的值。这是因为无法预测线程的时间。但最有可能的是，它永远不会达到 5,000,000,000，这应该是正确的值。请注意，程序将需要几秒钟才能完成：

```
$> ./race 
Sum is 1207835374
$> ./race 
Sum is 1132939275
$> ./race 
Sum is 1204521570
```

1.  目前，这个程序效率相当低。在继续使用`time`命令之前，我们将对程序进行计时。完成所需的时间在不同的计算机上会有所不同。在以后的教程中，我们将使程序更加高效，使互斥程序更加高效：

```
$> time ./race
Sum is 1188433970
real    0m20,195s
user    1m31,989s
sys     0m0,020s
```

## 工作原理…

由于所有线程同时读写同一变量，它们都会撤消彼此的工作。如果它们都按顺序运行，就像非线程化程序一样，结果将是 5,000,000,000，这正是我们想要的。

为了更好地理解这里发生了什么，让我们一步一步地来。请注意，这只是一个粗略的估计；确切的值和线程会因时间而异。

第一个线程读取`i`的值；假设它是 1。第二个线程也读取`i`，仍然是 1，因为第一个线程还没有增加值。现在第一个线程将值增加到 2 并保存到`i`。第二个线程也这样做；它也将值增加到 2（1+1=2）。现在，第三个线程开始并将变量`i`读取为 2 并将其增加到 3（2+1=3）。结果现在是 3，而不是 4。这将在程序执行过程中继续进行，并且无法预测结果将会是什么。每次程序运行时，线程的**时间**都会略有不同。以下图表包含了可能出现的问题的简化示例：

![图 11.1 - 竞争条件的示例](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/linux-sys-prog-tech/img/B13043_11_001.jpg)

图 11.1 - 竞争条件的示例

# 使用互斥锁避免竞争条件

**互斥锁**是一种**锁定机制**，它防止对**共享变量**的访问，以便不超过一个线程可以同时访问它。这可以防止竞争条件。使用互斥锁，我们只锁定代码的关键部分，例如共享变量的更新。这将确保程序的所有其他部分可以并行运行（如果这在锁定机制中是可能的）。

然而，如果我们在编写程序时不小心，互斥锁可能会大大减慢程序的速度，这将在这个食谱中看到。在下一个食谱中，我们将解决这个问题。

了解如何使用互斥锁将有助于您克服许多与竞争条件相关的问题，使您的程序更安全、更好。

## 准备工作

为了使这个食谱有意义，建议您先完成上一个食谱。您还需要我们在本章第一个食谱中编写的 Makefile，GCC 编译器和 Make 工具。

## 如何做…

这个程序建立在前一个食谱的基础上，但完整的代码在这里显示。代码分为几个步骤。但是，请记住所有的代码都放在同一个文件中。将文件命名为`locking.c`：

1.  我们将像往常一样从顶部开始。添加的代码已经高亮显示。首先，我们创建一个名为`mutex`的新变量，类型为`pthread_mutex_t`。这是用于锁定的变量。我们将这个变量放在全局区域，以便从`main()`和`add()`都可以访问到。第二个添加的部分是初始化互斥变量，使用`pthread_mutex_init()`。第二个参数使用`NULL`表示我们希望互斥锁使用默认属性：

```
#include <stdio.h>
#include <pthread.h>
void *add(void *arg);
long long int i = 0;
pthread_mutex_t i_mutex;
int main(void)
{
   pthread_attr_t threadattr;
   pthread_attr_init(&threadattr);
   pthread_t tid_add1, tid_add2, tid_add3, 
     tid_add4, tid_add5;
   if ( (pthread_mutex_init(&i_mutex, NULL)) != 0 )
   {
fprintf(stderr, 
         "Couldn't initialize mutex\n");
      return 1;
   }
   pthread_create(&tid_add1, &threadattr, 
      add, NULL);
   pthread_create(&tid_add2, &threadattr, 
      add, NULL);
   pthread_create(&tid_add3, &threadattr, 
      add, NULL);
   pthread_create(&tid_add4, &threadattr, 
      add, NULL);
   pthread_create(&tid_add5, &threadattr, 
      add, NULL);
   pthread_join(tid_add1, NULL);
   pthread_join(tid_add2, NULL);
   pthread_join(tid_add3, NULL);
   pthread_join(tid_add4, NULL);
   pthread_join(tid_add5, NULL);
```

1.  在我们完成计算后，我们使用`pthread_mutex_destroy()`销毁`mutex`变量：

```
   printf("Sum is %lld\n", i);
   if ( (pthread_mutex_destroy(&i_mutex)) != 0 )
   {
      fprintf(stderr, "Couldn't destroy mutex\n");
      return 1;
   }
   return 0;
}
```

1.  最后，我们在`add()`函数中使用锁定和解锁机制。我们锁定更新`i`变量的部分，并在更新完成后解锁。这样，变量在更新进行中被锁定，以便其他线程在更新完成之前无法访问它：

```
void *add(void *arg)
{
   for (long long int j = 1; j <= 1000000000; j++)
   {
      pthread_mutex_lock(&i_mutex);
      i = i + 1;
      pthread_mutex_unlock(&i_mutex);
   }
   return NULL;
}
```

1.  现在，让我们编译程序。像往常一样，我们可以忽略关于未使用变量的警告：

```
$> make locking
gcc -Wall -Wextra -pedantic -std=c99 -lpthread    locking.c   -o locking
locking.c: In function 'add':
locking.c:47:17: warning: unused parameter 'arg' [-Wunused-parameter]
 void *add(void *arg)
           ~~~~~~^~~
```

1.  现在是时候运行程序了。就像在上一个食谱中一样，我们将使用`time`命令计时执行。这次，计算将是正确的；最终结果将是 5,000,000,000。然而，程序将需要很长时间才能完成。在我的电脑上，需要超过 5 分钟才能完成：

```
$> time ./locking 
Sum is 5000000000
real    5m23,647s
user    8m24,596s
sys     16m11,407s
```

1.  让我们将这个结果与一个简单的非线程程序进行比较，它使用相同的基本算法实现相同的结果。让我们将这个程序命名为`non-threaded.c`：

```
#include <stdio.h>
int main(void)
{
   long long int i = 0;
   for (int x = 1; x <= 5; x++)
   {
      for (long long int j = 1; j <= 1000000000; j++)
      {
         i = i + 1;
      }
   }
   printf("Sum is %lld\n", i);
   return 0;
}
```

1.  让我们编译这个程序并计时。注意这个程序执行的速度有多快，同时又获得了相同的结果：

```
$> make non-threaded
gcc -Wall -Wextra -pedantic -std=c99 -lpthread    non-threaded.c   -o non-threaded
$> time ./non-threaded 
Sum is 5000000000
real    0m10,345s
user    0m10,341s
sys     0m0,000s
```

## 它是如何工作的…

线程化程序并不会自动比非线程化程序更快。我们在*步骤 7*中运行的非线程化程序甚至比前一个食谱中的线程化程序更快，尽管该程序甚至没有使用任何互斥锁。

那么，为什么会这样呢？

我们编写的多线程程序存在一些效率低下的问题。我们将从上一个示例中的`race.c`程序开始讨论问题。该程序比非多线程版本慢的原因是因为有许多小问题。例如，启动每个线程都需要一些时间（虽然很少，但仍然需要）。然后，每次仅更新全局的`i`变量一步也是低效的。所有线程同时访问同一个全局变量也是低效的。我们有五个线程，每个线程将其本地的`j`变量递增一次。每次这种情况发生时，线程都会更新全局的`i`变量。由于所有这些都发生了 50 亿次，所以比在单个线程中顺序运行要花费更长的时间。

然后，在本示例中的`locking.c`程序中，我们添加了一个互斥锁来锁定`i = i + 1`部分。由于这确保只有一个线程可以同时访问`i`变量，这使整个程序再次变成了顺序执行。而不是所有线程并行运行，以下情况发生：

1.  运行一个线程。

1.  锁定`i = i + 1`部分。

1.  运行`i = i + 1`以更新`i`。

1.  然后解锁`i = i + 1`。

1.  运行下一个线程。

1.  锁定`i = i + 1`部分。

1.  运行`i = i + 1`以更新`i`。

1.  然后解锁`i = i + 1`。

这些步骤将重复 5,000,000,000 次。每次线程启动都需要时间。然后需要额外的时间来锁定和解锁互斥锁，还需要时间来递增`i`变量。切换到另一个线程并重新开始整个锁定/解锁过程也需要时间。

在下一个示例中，我们将解决这些问题，使程序运行得更快。

## 另请参阅

有关互斥锁的更多信息，请参阅手册页`man 3 pthread_mutex_init`，`man 3 phtread_mutex_lock`，`man 3 phthread_mutex_unlock`和`man 3 pthread_mutex_destroy`。

# 使互斥程序更高效

在上一个示例中，我们看到多线程程序并不一定比非多线程程序快。我们还看到，当我们引入互斥锁时，程序变得非常慢。这种缓慢主要是由于来回切换、锁定和解锁数十亿次造成的。

解决所有这些锁定、解锁和来回切换的方法是尽可能少地锁定和解锁。而且，尽可能少地更新`i`变量，并在每个线程中尽可能多地完成工作。

在本示例中，我们将使我们的多线程程序运行得更快，更高效。

知道如何编写高效的多线程程序将帮助您避免许多线程问题。

## 准备工作

为了使本示例有意义，建议您完成本章中的前两个示例。除此之外，这里也有相同的要求；我们需要 Makefile、GCC 编译器和 Make 工具。

## 如何做…

这个程序是基于上一个示例中的`locking.c`程序构建的。唯一的区别是`add()`函数。因此，这里只显示`add()`函数；其余部分与`locking.c`相同。完整的程序可以从本章的 GitHub 目录中下载。文件名为`efficient.c`：

1.  复制`locking.c`并将新文件命名为`efficient.c`。

1.  重写`add()`函数，使其看起来像下面的代码。请注意，我们已经删除了`for`循环。相反，我们在`while`循环中递增一个本地的`j`变量，直到达到 10 亿。然后，我们将本地的`j`变量添加到全局的`i`变量中。这减少了我们必须锁定和解锁互斥锁的次数（从 50 亿次减少到 5 次）：

```
void *add(void *arg)
{
   long long int j = 1;
   while(j < 1000000000)
   {
      j = j + 1;
   }
   pthread_mutex_lock(&i_mutex);
   i = i + j;
   pthread_mutex_unlock(&i_mutex);
   return NULL;
}
```

1.  编译程序：

```
$> make efficient
gcc -Wall -Wextra -pedantic -std=c99 -lpthread    efficient.c   -o efficient
efficient.c: In function 'add':
efficient.c:47:17: warning: unused parameter 'arg' [-Wunused-parameter]
 void *add(void *arg)
           ~~~~~~^~~
```

1.  现在，让我们运行程序并使用`time`命令计时。请注意，这个程序运行得多快：

```
$ time ./efficient 
Sum is 5000000000
real    0m1,954s
user    0m8,858s
sys     0m0,004s
```

## 它是如何工作的…

这个程序比非线程化版本和第一个锁定版本都要快得多。作为执行时间的提醒，非线程化版本大约需要 10 秒才能完成；第一个线程化版本（`race.c`）大约需要 20 秒才能完成；第一个互斥版本（`locking.c`）需要超过 5 分钟才能完成。最终版本（`efficient.c`）只需要不到 2 秒就能完成——这是一个巨大的改进。

这个程序之所以快得多，有两个主要原因。首先，这个程序只锁定和解锁互斥锁 5 次（与上一个示例中的 5,000,000,000 次相比）。其次，每个线程现在可以在向全局变量写入任何内容之前完全完成其工作（`while`循环）。

简而言之，每个线程现在可以在没有任何中断的情况下完成其工作，使其真正成为线程化。只有当线程完成其工作后，它们才会将结果写入全局变量。

# 使用条件变量

`main()`使用一个条件变量来表示它已经完成，然后与该线程连接。

了解如何使用条件变量将有助于使您的线程程序更加灵活。

## 准备工作

为了使这个示例有意义，建议您先完成*从线程中读取返回值*示例。您还需要 GCC 编译器，我们在*编写您的第一个线程化程序*示例中编写的 Makefile 以及 Make 工具。

如何做...

在这个示例中，我们将从*从线程中读取返回值*示例中重新编写素数程序，以使用条件变量。完整的程序将在这里显示，但我们只讨论了这个示例的新增部分。

由于代码很长，它已经被分成了几个步骤。将代码保存在一个名为`cond-var.c`的文件中：

1.  我们将像往常一样从顶部开始。在这里，我们添加了三个新变量，一个我们称为`lock`的互斥锁，一个我们称为`ready`的条件变量，以及一个用于素数线程的线程 ID，我们称为`primeid`。`primeid`变量将用于从已完成的线程发送线程 ID：

```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
void *isprime(void *arg);
void *progress(void *arg);
pthread_mutex_t lock;
pthread_cond_t ready;
pthread_t primeid = 0;
int main(int argc, char *argv[])
{
   long long number1;
   long long number2;
   pthread_t tid_prime1;
   pthread_t tid_prime2;
   pthread_t tid_progress;
   pthread_attr_t threadattr;
   void *prime1Return;
   void *prime2Return;
```

1.  然后我们必须初始化**互斥锁**和**条件变量**：

```
   if ( (pthread_mutex_init(&lock, NULL)) != 0 )
   {
      fprintf(stderr, 
         "Couldn't initialize mutex\n");
      return 1;
   }
   if ( (pthread_cond_init(&ready, NULL)) != 0 )
   {
      fprintf(stderr, 
        "Couldn't initialize condition variable\n");
      return 1;
   }
```

1.  之后，我们检查参数的数量，就像以前一样。如果参数计数正确，我们就用`pthread_create()`启动线程，也和以前一样：

```
   if ( argc != 3 )
   {
      fprintf(stderr, "Please supply two numbers.\n"
         "Example: %s 9 7\n", argv[0]);
      return 1;
   }
   number1 = atoll(argv[1]);
   number2 = atoll(argv[2]);
   pthread_attr_init(&threadattr);
   pthread_create(&tid_progress, &threadattr, 
      progress, NULL);  
   pthread_detach(tid_progress);
   pthread_create(&tid_prime1, &threadattr, 
      isprime, &number1);
   pthread_create(&tid_prime2, &threadattr, 
      isprime, &number2);
```

1.  现在是有趣的部分。我们将从锁定互斥锁开始，以保护`primeid`变量。然后，我们使用`pthread_cond_wait()`等待条件变量的信号。这将释放互斥锁，以便线程可以写入`primeid`。请注意，我们还在`while`循环中循环`pthread_cond_wait()`调用。我们这样做是因为我们只想在`primeid`仍然为 0 时等待信号。由于`pthread_cond_wait()`将阻塞，它不会使用任何 CPU 周期。当我们收到信号时，我们移动到`if`语句。这将检查哪个线程已经完成并加入它。然后我们回去并使用`for`循环重新开始。每当`if`或`else`语句完成时——当一个线程已经加入时——`primeid`变量将被重置为 0。这将使下一次迭代再次等待`pthread_cond_wait()`：

```
   pthread_mutex_lock(&lock);
   for (int i = 0; i < 2; i++)
   {
      while (primeid == 0)
         pthread_cond_wait(&ready, &lock);
      if (primeid == tid_prime1)
      {
         pthread_join(tid_prime1, &prime1Return);
         if (  (uintptr_t)prime1Return == 1 )
            printf("\n%lld is a prime number\n", 
               number1);
         else
            printf("\n%lld is not a prime number\n", 
               number1);
         primeid = 0;
      }
      else
      {
         pthread_join(tid_prime2, &prime2Return);   
         if ( (uintptr_t)prime2Return == 1 )
            printf("\n%lld is a prime number\n", 
               number2);
         else
            printf("\n%lld is not a prime number\n", 
               number2);
         primeid = 0;
      }
   }
   pthread_mutex_unlock(&lock);
   pthread_attr_destroy(&threadattr);
   if ( pthread_cancel(tid_progress) != 0 )
      fprintf(stderr, 
         "Couldn't cancel progress thread\n");

   return 0;
}
```

1.  接下来，我们有`isprime()`函数。这里有一些新的行。一旦函数计算完数字，我们就锁定互斥锁以保护`primeid`变量。然后我们将`primeid`变量设置为线程的 ID。然后，我们发出条件变量（`ready`）的信号并释放互斥锁。这将唤醒`main()`函数，因为它现在正在等待`pthread_cond_wait()`：

```
void *isprime(void *arg)
{
   long long int number = *((long long*)arg);
   long long int j;
   int prime = 1;

   for(j=2; j<number; j++)
   {
      if(number%j == 0)
         prime = 0;
   }
   pthread_mutex_lock(&lock);
   primeid = pthread_self();
   pthread_cond_signal(&ready);
   pthread_mutex_unlock(&lock);
   if(prime == 1)
      return (void*)1;
   else
      return (void*)0;
}
```

1.  最后，我们有`progress()`函数。这里没有改变：

```
void *progress(void *arg)
{
   while(1)
   {
      sleep(1);
      printf(".");
      fflush(stdout);
   }
   return NULL;
}
```

1.  现在，让我们编译程序：

```
$> make cond-var
gcc -Wall -Wextra -pedantic -std=c99 -lpthread    cond-var.c   -o cond-var
cond-var.c: In function 'progress':
cond-var.c:114:22: warning: unused parameter 'arg' [-Wunused-parameter]
 void *progress(void *arg)
```

1.  现在让我们尝试一下这个程序。我们将用较小的数字作为第一个参数和第二个参数来测试它。无论如何，最快的计算数字都将立即显示出来，而不需要等待其他线程加入：

```
$> ./cond-var 990231117 9902343047
........
990231117 is not a prime number
................................................................................
9902343047 is a prime number
$> ./cond-var 9902343047 990231117
........
990231117 is not a prime number
...............................................................................
9902343047 is a prime number
```

## 它是如何工作的...

当我们在`while`循环中使用`pthread_cond_wait()`等待时，我们同时使用条件变量（`ready`）和互斥锁（`lock`）进行调用。这样，它就知道释放哪个互斥锁，等待哪个信号。就是在等待时释放互斥锁。

在等待期间，其他线程可以写入`primeid`变量。其他线程在写入变量之前会先用互斥锁锁定变量。一旦他们写入变量，就会发出条件变量的信号并释放互斥锁。这会唤醒`main()`函数，它目前正在使用`pthread_cond_wait()`等待。`main()`函数然后检查哪个线程完成了，并使用`pthread_join()`加入它。然后，`main()`函数将`primeid`变量重置为 0，并使用`pthread_cond_wait()`再次等待，直到下一个线程发出完成的信号。我们正在等待两个线程，所以`main()`中的`for`循环将运行两次。

每个线程都使用`pthread_self()`获得自己的线程 ID。

## 另请参阅

有关条件变量的更多信息，请参阅以下手册页面。

+   `man 3 pthread_cond_init()`

+   `man 3 pthread_cond_wait()`

+   `man 3 pthread_cond_signal()`


# 第十二章：调试您的程序

没有一个程序在第一次尝试时就是完美的。在本章中，我们将学习如何使用 GDB 和 Valgrind 来调试我们的程序。使用 Valgrind 这个工具，我们可以找到程序中的内存泄漏。

我们还将看看内存泄漏是什么，它们可能引起什么问题，以及如何防止它们。调试程序并查看内存是理解系统编程的重要步骤。

在本章中，我们将涵盖以下内容：

+   启动 GDB

+   使用 GDB 进入函数

+   使用 GDB 调查内存

+   在运行时修改变量

+   在分叉程序上使用 GDB

+   使用多线程调试程序

+   使用 Valgrind 找到一个简单的内存泄漏

+   使用 Valgrind 查找缓冲区溢出

# 技术要求

在本章中，您将需要 GBD 工具、Valgrind、GCC 编译器、通用 Makefile 和 Make 工具。

如果您还没有安装 GDB 和 Valgrind，现在可以这样做。根据您的发行版，按照以下说明进行操作。如果您没有安装`sudo`或没有`sudo`权限，您可以使用`su`切换到 root 用户（并省略`sudo`部分）。

对于 Debian 和 Ubuntu 系统，请运行以下命令：

```
$> sudo apt-get install gdb valgrind
```

对于 CentOS、Fedora 和 Red Hat 系统，请运行以下命令：

```
$> sudo dnf install gdb valgrind
```

本章的所有代码示例都可以在 GitHub 上找到：[`github.com/PacktPublishing/Linux-System-Programming-Techniques/tree/master/ch12`](https://github.com/PacktPublishing/Linux-System-Programming-Techniques/tree/master/ch12)。

查看以下链接以查看“代码实战”视频：[`bit.ly/3rvAvqZ`](https://bit.ly/3rvAvqZ)

# 启动 GDB

在这个教程中，我们将学习**GDB**，即**GNU 调试器**的基础知识。我们将学习如何启动 GDB，如何设置断点，以及如何逐步执行程序。我们还将学习**调试符号**是什么以及如何启用它们。

GDB 是 Linux 和其他类 Unix 系统中最流行的调试器。它允许您在程序运行时检查和更改变量，逐步执行指令，查看程序运行时的代码，读取返回值等等。

了解如何使用调试器可以节省您很多时间。您可以跟踪 GDB 的执行并发现错误，而不是猜测程序的问题。这可以节省您很多时间。

## 准备工作

对于这个教程，您将需要 GCC 编译器、Make 工具和 GDB 工具。有关 GDB 的安装说明，请参阅本章的*技术要求*部分。

## 如何做…

在这个教程中，我们将在一个正常工作的程序上使用 GDB。这里没有错误。相反，我们想专注于如何在 GDB 中做一些基本的事情：

1.  在一个文件中编写以下简单程序，并将其保存为`loop.c`。稍后，我们将使用 GDB 检查程序：

```
#include <stdio.h>
int main(void)
{
   int x;
   int y = 5;
   char text[20] = "Hello, world";
   for (x = 1; y < 100; x++)
   {
      y = (y*3)-x;
   }
   printf("%s\n", text);
   printf("y = %d\n", y);
   return 0;
}
```

1.  在我们充分利用 GDB 之前，我们需要在与 loop.c 程序相同的目录中启用`Makefile`。请注意，我们在`CFLAGS`中添加了`-g`选项。这些调试符号使我们能够在 GDB 中执行代码时看到代码：

```
CC=gcc
CFLAGS=-g -Wall -Wextra -pedantic -std=c99
```

1.  现在，是时候使用我们的新 Makefile 编译程序了：

```
$> make loop
gcc -g -Wall -Wextra -pedantic -std=c99    loop.c   -o loop
```

1.  在继续之前，让我们尝试一下程序：

```
$> ./loop 
Hello, world
y = 117
```

1.  从与`loop`和`loop.c`相同的目录中，通过输入以下内容启动 GDB 并使用 loop 程序（需要源代码`loop.c`以在 GBD 中显示代码）：

```
$> gdb ./loop
```

1.  现在您看到了一些版权文本和版本信息。在底部，有一个提示写着`(gdb)`。这是我们输入命令的地方。让我们运行程序看看会发生什么。我们只需输入`run`并按*Enter*：

```
(gdb) run
Starting program: /home/jack/ch12/code/loop 
Hello, world
y = 117
[Inferior 1 (process 10467) exited normally]
```

1.  这并没有告诉我们太多；我们本可以直接从终端运行程序。所以，这次我们设置了一个`include`行。相反，GDB 会自动将其设置在第一个有实际代码的逻辑位置。断点是执行应该停止的代码位置，这样我们就有机会对其进行调查。

```
(gdb) break 1
Breakpoint 1 at 0x55555555514d: file loop.c, line 6.
```

1.  现在我们可以重新运行程序。这次执行将在第 6 行（断点处）停止：

```
$> (gdb) run
Starting program: /home/jack/ch12/code/loop
Breakpoint 1, main () at loop.c:6
6          int y = 5;
```

1.  我们可以使用`watch`命令开始监视`y`变量。GDB 会告诉我们每次`y`被更新时：

```
$> (gdb) watch y
Hardware watchpoint 2: y
```

1.  现在我们可以使用`next`命令执行代码中的下一条语句。为了避免每次向前移动代码时都要输入`next`，我们可以直接按*Enter*。这样做会让 GDB 执行上一条命令。注意更新的`y`变量。还要注意到我们每走一步都能看到我们正在执行的代码：

```
(gdb) next
Hardware watchpoint 2: y
Old value = 0
New value = 5
main () at loop.c:7
7          char text[20] = "Hello, world";
(gdb) next
8          for (x = 1; y < 100; x++)
(gdb) next
10            y = (y*3)-x;
```

1.  显示的代码行是下一个要执行的语句。所以，从上一步开始，我们看到下一个要执行的是第 10 行，即`y = (y*3)-x`。所以让我们在这里按*Enter*，这将更新`y`变量，并且**watchpoint**会告诉我们这一点：

```
(gdb) next
Hardware watchpoint 2: y
Old value = 5
New value = 14
main () at loop.c:8
8          for (x = 1; y < 100; x++)
(gdb) next
10            y = (y*3)-x;
(gdb) next
Hardware watchpoint 2: y
Old value = 14
New value = 40
main () at loop.c:8
8          for (x = 1; y < 100; x++)
(gdb) next
10            y = (y*3)-x;
(gdb) next
Hardware watchpoint 2: y
Old value = 40
New value = 117
8          for (x = 1; y < 100; x++)
```

1.  在继续之前，让我们检查一下`text`字符数组和`x`变量的内容。我们用`print`命令打印变量和数组的内容。在这里我们看到`text`数组在实际文本之后填满了**空字符**：

```
(gdb) print text
$1 = "Hello, world\000\000\000\000\000\000\000"
(gdb) print x
$2 = 3
```

1.  让我们继续执行。在上一步中进程退出后，我们可以使用`quit`退出 GDB：

```
(gdb) next
12         printf("%s\n", text);
(gdb) next
Hello, world
13         printf("y = %d\n", y);
(gdb) next
y = 117
14         return 0;
(gdb) next
15      }
(gdb) next
Watchpoint 2 deleted because the program has left the block in which its expression is valid.
__libc_start_main (main=0x555555555145 <main>, argc=1, argv=0x7fffffffdbe8, 
    init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, 
    stack_end=0x7fffffffdbd8) at ../csu/libc-start.c:342
342     ../csu/libc-start.c: No such file or directory.
(gdb) next
[Inferior 1 (process 14779) exited normally]
(gdb) quit
```

## 工作原理

我们刚刚学会了 GDB 的所有基础知识。使用这些命令，我们可以进行大量的调试。还有一些东西要学，但我们已经走了很长的路。

我们使用`loop`程序启动了 GDB 程序。为了防止 GDB 在不调查情况下运行整个程序，我们使用`break`命令设置了一个断点。在我们的示例中，我们使用`break 1`在一行上设置了断点。也可以在特定函数上设置断点，比如`main()`。我们可以使用`break main`命令来做到这一点。

一旦断点设置好了，我们就可以用`run`命令运行程序。然后我们用`watch`监视`y`变量。我们使用`next`命令逐条执行语句。我们还学会了如何使用`print`命令打印变量和数组。

为了使所有这些成为可能，我们必须使用 GCC 的`-g`选项编译程序。这样可以启用调试符号。但是，为了在 GDB 中看到实际的代码，我们还需要源代码文件。

## 还有更多内容…

GDB 有一些很好的内置帮助。启动 GDB 而不加载程序。然后在`(gdb)`提示符下键入`help`。这将给您一个不同类别命令的列表。如果我们想要了解更多关于断点的信息，我们可以键入`help breakpoints`。这将给您一个很长的断点命令列表，例如`break`。要了解更多关于`break`命令的信息，键入`help break`。

# 使用 GDB 进入函数内部

当我们在具有函数的程序中使用`next`命令时，它将简单地执行该函数并继续。但是，还有另一个命令叫做`step`，它将进入函数，逐步执行它，然后返回到`main()`。在这个示例中，我们将检查`next`和`step`之间的区别。

了解如何使用 GDB 进入函数将帮助您调试整个程序，包括其函数。

## 准备工作

对于这个示例，您将需要 GDB 工具、GCC 编译器、本章中*Starting GDB*示例中编写的 Makefile 以及 Make 工具。

## 操作步骤

在这个示例中，我们将编写一个包含函数的小程序。然后，我们将使用`step`命令在 GDB 中进入该函数：

1.  将以下代码写入文件并保存为`area-of-circle.c`。该程序以圆的半径作为参数，并打印其面积：

```
#include <stdio.h>
#include <stdlib.h>
float area(float radius);
int main(int argc, char *argv[])
{
   float number;
   float answer;
   if (argc != 2)
   {
      fprintf(stderr, "Type the radius of a "
         "circle\n");
      return 1;
   }
   number = atof(argv[1]);
   answer = area(number);
   printf("The area of a circle with a radius of "
      "%.2f is %.2f\n", number, answer);
   return 0;
}
float area(float radius)
{
   static float pi = 3.14159;
   return pi*radius*radius;
}
```

1.  使用*Starting GDB*示例中的 Makefile 编译程序：

```
$> make area-of-circle
gcc -g -Wall -Wextra -pedantic -std=c99    area-of-circle.c   -o area-of-circle
```

1.  在使用 GDB 逐步调试之前，让我们尝试一下：

```
$> ./area-of-circle 9
The area of a circle with a radius of 9.00 is 254.47
```

1.  现在是时候使用 GDB 逐步执行程序了。使用`area-of-circle`程序启动 GDB：

```
$> gdb ./area-of-circle
```

1.  我们首先在`main()`函数处设置断点：

```
(gdb) break main
Breakpoint 1 at 0x1164: file area-of-circle.c, line 9.
```

1.  现在运行程序。在 GDB 中为程序指定参数，我们在`run`命令中设置参数：

```
(gdb) run 9
Starting program: /home/jack/ch12/code/area-of-circle 9
Breakpoint 1, main (argc=2, argv=0x7fffffffdbd8) at area-of-circle.c:9
9          if (argc != 2)
```

1.  使用`next`命令向前移动一步：

```
(gdb) next
15         number = atof(argv[1]);
```

1.  从上一步可以看出，要执行的下一个语句将是`atof()`函数。这是一个标准库函数，所以我们没有任何调试符号或源代码。因此，我们无法看到函数内部的任何东西。但是，我们仍然可以步进到它内部。一旦我们进入函数内部，我们可以让它执行并使用`finish`命令完成。这将告诉我们函数的**返回值**，这可能非常方便：

```
(gdb) step
atof (nptr=0x7fffffffdfed "9") at atof.c:27
27      atof.c: No such file or directory.
(gdb) finish
Run till exit from #0  atof (nptr=0x7fffffffdfed "9") at atof.c:27
main (argc=2, argv=0x7fffffffdbd8) at area-of-circle.c:15
15         number = atof(argv[1]);
Value returned is $1 = 9
```

1.  现在我们再次使用`next`，这将带我们到我们的`area`函数。我们想要步进到`area`函数内部，所以我们在这里使用`step`。这将告诉我们它被调用的值是 9。由于在`area`函数内部没有太多要做的，只需要返回，我们可以输入`finish`来得到它的返回值：

```
(gdb) next
16         answer = area(number);
(gdb) step
area (radius=9) at area-of-circle.c:25
25         return pi*radius*radius;
(gdb) finish
Run till exit from #0  area (radius=9) at area-of-circle.c:25
0x00005555555551b7 in main (argc=2, argv=0x7fffffffdbd8) at area-of-circle.c:16
16         answer = area(number);
Value returned is $2 = 254.468796
```

1.  现在，我们可以使用`next`来遍历程序的其余部分：

```
(gdb) next
17         printf("The area of a circle with a radius of "
(gdb) next
The area of a circle with a radius of 9.00 is 254.47
19         return 0;
(gdb) next
20      }
(gdb) next
__libc_start_main (main=0x555555555155 <main>, argc=2, argv=0x7fffffffdbd8, 
    init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, 
    stack_end=0x7fffffffdbc8) at ../csu/libc-start.c:342
342     ../csu/libc-start.c: No such file or directory.
(gdb) next
[Inferior 1 (process 2034) exited normally]
(gdb) quit
```

## 它是如何工作的...

使用`step`命令，我们可以步进到一个函数内部。但是，标准库中的函数没有任何调试符号或可用的源代码；因此，我们无法看到它们内部发生了什么。如果我们想要，我们可以获取源代码并使用调试符号进行编译；毕竟，Linux 是开源的。

但即使我们看不到函数内部发生了什么，步进到函数内部仍然是有价值的，因为我们可以使用`finish`得到它们的返回值。

# 使用 GDB 调查内存

使用 GDB，我们可以更多地了解事情在幕后是如何工作的，例如字符串。**字符串**是由空字符终止的字符数组。在这个示例中，我们将使用 GDB 调查一个字符数组，并看看空字符是如何结束一个字符串的。

了解如何使用 GDB 检查内存，如果遇到奇怪的**错误**，这将非常方便。我们可以直接在 GDB 中检查它们，而不是在 C 中猜测或循环遍历每个字符。

## 做好准备

对于这个示例，您将需要我们在*开始 GDB*示例中编写的 Makefile。您还需要 GCC 编译器和 Make 工具。

## 如何做...

在这个示例中，我们将编写一个简单的程序，用字符*x*填充一个字符数组。然后我们将一个新的、较短的字符串复制到上面，最后打印字符串。只有新复制的字符串被打印出来，即使所有的*x*字符仍然存在。使用 GDB，我们可以确认这一事实：

1.  在文件中写入以下代码并将其保存为`memtest.c`：

```
#include <stdio.h>
#include <string.h>
int main(void)
{
    char text[20];
    memset(text, 'x', 20);
    strcpy(text, "Hello");
    printf("%s\n", text);
    return 0;
}
```

1.  使用*开始 GDB*示例中的 Makefile 编译程序：

```
$> make memtest
gcc -g -Wall -Wextra -pedantic -std=c99    memtest.c   -o memtest
```

1.  让我们像运行其他程序一样运行它：

```
$> ./memtest 
Hello
```

1.  让我们用我们的`memtest`程序启动 GDB：

```
$> gdb ./memtest
```

1.  现在，让我们使用 GDB 检查`text`数组内部的内容。首先，在`main()`上设置一个断点，然后运行程序，并使用`next`在`strcpy()`函数执行后向前步进。然后，在 GDB 中使用`x`命令进行检查（`x`表示检查）。我们还必须告诉 GDB 检查 20 个字节，并使用十进制表示打印内容。因此，`x`命令将是`x/20bd text`。要将十进制数解释为字符，请参阅我们在*第二章*中讨论的 ASCII 表，*使您的程序易于脚本化*，网址为[`github.com/PacktPublishing/B13043-Linux-System-Programming-Cookbook/blob/master/ch2/ascii-table.md`](https://github.com/PacktPublishing/B13043-Linux-System-Programming-Cookbook/blob/master/ch2/ascii-table.md)：

```
(gdb) break main
Breakpoint 1 at 0x114d: file memtest.c, line 6.
(gdb) run
Starting program: /mnt/localnas_disk2/linux-sys/ch12/code/memtest 
Breakpoint 1, main () at memtest.c:6
warning: Source file is more recent than executable.
6           memset(text, 'x', 20);
(gdb) next
7           strcpy(text, "Hello");
(gdb) next
8           printf("%s\n", text);
(gdb) x/20bd text
0x7fffffffdae0: 72   101  108  108  111  0    120  120
0x7fffffffdae8: 120  120  120  120  120  120  120  120
0x7fffffffdaf0: 120  120  120  120
```

## 它是如何工作的...

使用 GDB 检查内存时，我们使用了`x`命令。`20bd`表示我们要读取的大小为 20，我们要以字节组的形式（`b`）呈现它，并使用十进制表示打印内容（`d`）。使用这个命令，我们得到了一个漂亮的表格，显示了数组中的每个字符作为一个十进制数打印出来。

内存的内容——当转换为字符时是`Hello\0xxxxxxxxxxxxxx`。空字符将*Hello*字符串与所有*x*字符分隔开。通过使用 GDB 并在运行时检查内存，我们可以学到很多东西。

## 还有更多...

除了以十进制表示形式打印内容之外，还可以以常规字符（`c`）、十六进制表示形式（`x`）、浮点数（`f`）等形式打印。这些字母与`printf()`的用法相同。

## 另请参阅

您可以在 GDB 中键入`help x`来了解如何使用`x`命令。

# 在运行时修改变量

使用 GDB 甚至可以在运行时修改变量。这对实验非常方便。您可以使用 GDB 更改变量，而不是更改源代码并重新编译程序，然后查看发生了什么。

知道如何在运行时更改变量和数组可以加快调试和实验阶段的速度。

## 准备工作

对于这个配方，您需要上一节中的`memtest.c`程序。您还需要本章中*开始使用 GDB*配方中的 Makefile，Make 工具和 GCC 编译器。

## 如何做…

在本节中，我们将继续使用上一节的程序。在这里，我们将用另一个字符替换第六个位置的**空字符**，并用一个空字符替换最后一个字符：

1.  如果您尚未编译上一节中的`memtest`程序，请立即这样做：

```
$> make memtest
gcc -g -Wall -Wextra -pedantic -std=c99    memtest.c   -o memtest
```

1.  使用您刚刚编译的`memtest`程序启动 GDB：

```
$> gdb ./memtest
```

1.  首先在`main()`处设置断点，然后运行程序。使用`next`向前步进到`strcpy()`函数之后：

```
(gdb) break main
Breakpoint 1 at 0x114d: file memtest.c, line 6.
(gdb) run
Starting program: /home/jack/ch12/code/memtest 
Breakpoint 1, main () at memtest.c:6
6           memset(text, 'x', 20);
(gdb) next
7           strcpy(text, "Hello");
(gdb) next
8           printf("%s\n", text);
```

1.  在更改数组之前，让我们首先使用`x`命令打印它，就像在上一节中一样：

```
(gdb) x/20bd text
0x7fffffffdae0: 72   101  108  108  111  0    120  120
0x7fffffffdae8: 120  120  120  120  120  120  120  120
0x7fffffffdaf0: 120  120  120  120
```

1.  现在我们知道内容是什么样的，我们可以用`y`替换第六个位置的空字符（实际上是第五个，我们从 0 开始计数）。我们还将最后一个位置替换为一个空字符。设置`set`命令：

```
(gdb) set text[5] = 'y'
(gdb) set text[19] = '\0'
(gdb) x/20bd text
0x7fffffffdae0: 72   101  108  108  111  121  120  120
0x7fffffffdae8: 120  120  120  120  120  120  120  120
0x7fffffffdaf0: 120  120  120  0
```

1.  让我们继续运行程序的其余部分。我们可以使用`continue`命令让程序一直运行到结束，而不是使用`next`命令一步步向前。请注意，`printf()`函数现在将打印字符串`Helloyxxxxxxxxxxxxxx`：

```
(gdb) continue
Continuing.
Helloyxxxxxxxxxxxxx
[Inferior 1 (process 4967) exited normally]
(gdb) quit
```

## 它是如何工作的…

使用 GDB 中的`set`命令，我们成功在运行时更改了`text`数组的内容。使用`set`命令，我们删除了第一个空字符，并在末尾插入了一个新的字符，使其成为一个长有效的字符串。由于我们在*Hello*后删除了空字符，`printf()`然后打印了整个字符串。

# 在分叉程序上使用 GDB

使用 GDB 调试**分叉**程序将自动跟踪**父进程**，就像普通的非分叉程序一样。但是也可以跟踪**子进程**，这就是我们将在本节中学习的内容。

能够跟踪子进程在调试中很重要，因为许多程序会产生子进程。我们不想局限于只有非分叉程序。

## 准备工作

对于这个配方，您需要本章中*开始使用 GDB*配方中的 Makefile，Make 工具和 GCC 编译器。

## 如何做…

在本节中，我们将编写一个小程序进行分叉。我们将在子进程中放置一个`for`循环，以确认我们是在子进程还是父进程中。在 GDB 中的第一次运行中，我们将像通常一样运行程序。这将使 GDB 跟踪父进程。然后，在下一次运行中，我们将跟踪子进程：

1.  在文件中写入以下代码，并将其保存为`forking.c`。该代码类似于我们在*第六章*中编写的`forkdemo.c`程序，*生成进程和使用作业控制*：

```
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
int main(void)
{
   pid_t pid;
   printf("My PID is %d\n", getpid());
   /* fork, save the PID, and check for errors */
   if ( (pid = fork()) == -1 )
   {
      perror("Can't fork");
      return 1;
   }
   if (pid == 0)
   {
      /* if pid is 0 we are in the child process */
      printf("Hello from the child process!\n");
      for(int i = 0; i<10; i++)
      {
          printf("Counter in child: %d\n", i);
      }
   }
   else if(pid > 0)
   {
      /* parent process */
      printf("My child has PID %d\n", pid);
      wait(&pid);
   }
   return 0;
}
```

1.  编译程序：

```
$> make forking
gcc -g -Wall -Wextra -pedantic -std=c99    forking.c   -o forking
```

1.  在我们在 GDB 中运行程序之前，让我们先尝试一下：

```
$> ./forking 
My PID is 9868
My child has PID 9869
Hello from the child process!
Counter in child: 0
Counter in child: 1
Counter in child: 2
Counter in child: 3
Counter in child: 4
Counter in child: 5
Counter in child: 6
Counter in child: 7
Counter in child: 8
Counter in child: 9
```

1.  在第一次通过 GDB 运行时，我们将像通常一样运行它。这将使 GDB 自动跟踪父进程。首先使用`forking`程序启动 GDB：

```
$> gdb ./forking
```

1.  像往常一样，在`main()`设置断点并运行。然后，我们将使用`next`命令向前一步，直到看到*Counter in child*文本。这将证明我们确实在父进程中，因为我们从未通过`for`循环。还要注意，GDB 告诉我们程序已经 fork 并且从子进程中分离（意味着我们在父进程中）。GDB 还打印了子进程的 PID：

```
(gdb) break main
Breakpoint 1 at 0x118d: file forking.c, line 9.
(gdb) run
Starting program: /home/jack/ch12/code/forking 
Breakpoint 1, main () at forking.c:9
9          printf("My PID is %d\n", getpid());
(gdb) next
My PID is 10568
11         if ( (pid = fork()) == -1 )
(gdb) next
[Detaching after fork from child process 10577]
Hello from the child process!
Counter in child: 0
Counter in child: 1
Counter in child: 2
Counter in child: 3
Counter in child: 4
Counter in child: 5
Counter in child: 6
Counter in child: 7
Counter in child: 8
Counter in child: 9
16         if (pid == 0)
(gdb) continue
Continuing.
My child has PID 10577
[Inferior 1 (process 10568) exited normally]
(gdb) quit
```

1.  现在，让我们再次运行程序。但是这次，我们会告诉 GDB 跟随子进程。像之前一样用`forking`程序启动 GDB：

```
$> gdb ./forking
```

1.  像之前一样，在`main()`设置断点。之后，我们告诉 GDB 使用`set`命令跟随子进程，就像之前看到的那样。只是这次，我们设置了一个叫做`follow-fork-mode`的东西。我们将它设置为`child`。然后像往常一样运行程序：

```
(gdb) break main
Breakpoint 1 at 0x118d: file forking.c, line 9.
(gdb) set follow-fork-mode child
(gdb) run
Starting program: /home/jack/ch12/code/forking 
Breakpoint 1, main () at forking.c:9
9          printf("My PID is %d\n", getpid());
```

1.  现在，使用`next`命令向前移动一步两次。程序现在会 fork，并且 GDB 会告诉我们它正在附加到子进程并且从父进程中分离。这意味着我们现在在子进程中：

```
(gdb) next
My PID is 11561
11         if ( (pid = fork()) == -1 )
(gdb) next
[Attaching after process 11561 fork to child process 11689]
[New inferior 2 (process 11689)]
[Detaching after fork from parent process 11561]
[Inferior 1 (process 11561) detached]
My child has PID 11689
[Switching to process 11689]
main () at forking.c:11
11         if ( (pid = fork()) == -1 )
```

1.  让我们再向前移动一点，看看我们最终进入了子进程中的`for`循环：

```
(gdb) next
16         if (pid == 0)
(gdb) next
19            printf("Hello from the child process!\n");
(gdb) next
Hello from the child process!
20            for(int i = 0; i<10; i++)
(gdb) next
22                printf("Counter in child: %d\n", i);
(gdb) next
Counter in child: 0
20            for(int i = 0; i<10; i++)
(gdb) next
22                printf("Counter in child: %d\n", i);
(gdb) next
Counter in child: 1
20            for(int i = 0; i<10; i++)
(gdb) next
22                printf("Counter in child: %d\n", i);
(gdb) continue
Continuing.
Counter in child: 2
Counter in child: 3
Counter in child: 4
Counter in child: 5
Counter in child: 6
Counter in child: 7
Counter in child: 8
Counter in child: 9
[Inferior 2 (process 11689) exited normally]
```

## 操作步骤如下…

使用`set follow-fork-mode`，我们可以告诉 GDB 在程序 fork 时跟随哪个进程。这对于调试 fork 的守护进程很方便。您可以将`follow-fork-mode`设置为`parent`或`child`。默认值是`parent`。我们不跟随的进程将继续像往常一样运行。

## 还有更多…

还有`follow-exec-mode`，它告诉 GDB 如果程序调用`exec()`函数要跟随哪个进程。

有关`follow-exec-mode`和`follow-fork-mode`的更多信息，您可以在 GDB 中使用`help set follow-exec-mode`和`help set follow-fork-mode`命令。

# 使用多线程调试程序

使用 GBD 可以查看程序中的线程，并且可以在**线程**之间跳转。了解如何在程序中跳转线程将使多线程程序更容易调试。编写多线程程序可能很困难，但使用 GDB 可以更容易地确保它们正常工作。

## 准备工作

在这个示例中，我们将使用*第十一章*中的`first-threaded.c`程序，*在程序中使用线程*。本章的 GitHub 目录中有源代码的副本。

你还需要 GCC 编译器。

## 操作步骤如下…

在这个示例中，我们将使用 GDB 查看`first-threaded.c`程序中的线程：

1.  让我们从编译程序开始：

```
$> gcc -g -Wall -Wextra -pedantic -std=c99 \
> -lpthread first-threaded.c -o first-threaded
```

1.  在通过调试器运行程序之前，让我们先运行一下，回顾一下程序的工作方式：

```
$> ./first-threaded 990233331 9902343047
........
990233331 is not a prime number
...............................................................................
9902343047 is a prime number
Done!
```

1.  现在我们知道程序如何工作，让我们在 GDB 中启动它：

```
$> gdb ./first-threaded
```

1.  让我们像之前一样在`main()`设置断点。然后用相同的两个数字运行它：

```
(gdb) break main
Breakpoint 1 at 0x11e4: file first-threaded.c, line 17.
(gdb) run 990233331 9902343047
Starting program: /home/jack/ch12/code/first-threaded 990233331 9902343047
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Breakpoint 1, main (argc=3, argv=0x7fffffffdbb8) at first-threaded.c:17
17         if ( argc != 3 )
```

1.  现在我们使用`next`命令向前移动。一旦线程启动，GDB 会用文本*New thread*通知我们：

```
(gdb) next
23         number1 = atoll(argv[1]);
(gdb) next
24         number2 = atoll(argv[2]);
(gdb) next
25         pthread_attr_init(&threadattr);
(gdb) next
26         pthread_create(&tid_progress, &threadattr, 
(gdb) next
[New Thread 0x7ffff7dad700 (LWP 19182)]
28         pthread_create(&tid_prime1, &threadattr, 
(gdb) next
[New Thread 0x7ffff75ac700 (LWP 19183)]
30         pthread_create(&tid_prime2, &threadattr,
```

1.  现在我们可以使用`info threads`命令打印当前线程的信息。注意这也会告诉我们线程当前正在执行的函数。每行上单词*Thread*前面的数字是 GDB 的线程 ID：

```
(gdb) info threads
  Id   Target Id                                          Frame 
* 1    Thread 0x7ffff7dae740 (LWP 19175) "first-threaded" main (argc=3, argv=0x7fffffffdbb8)
    at first-threaded.c:30
  2    Thread 0x7ffff7dad700 (LWP 19182) "first-threaded" 0x00007ffff7e77720 in __GI___nanosleep
    (requested_time=requested_time@entry=0x7ffff7dacea0, 
    remaining=remaining@entry=0x7ffff7dacea0) at ../sysdeps/unix/sysv/linux/nanosleep.c:28
  3    Thread 0x7ffff75ac700 (LWP 19183) "first-threaded" 0x000055555555531b in isprime (
    arg=0x7fffffffdac8) at first-threaded.c:52
```

1.  现在，让我们切换到当前执行`isprime`函数的第 3 个线程。我们使用`thread`命令切换线程：

```
(gdb) thread 3
[Switching to thread 3 (Thread 0x7ffff75ac700 (LWP 19183))]
#0  0x000055555555531b in isprime (arg=0x7fffffffdac8) at first-threaded.c:52
52            if(number%j == 0)
```

1.  在线程内部，我们可以打印变量的内容，使用`next`命令向前移动等。在这里我们还看到另一个线程正在启动：

```
(gdb) print number
$1 = 990233331
(gdb) print j
$2 = 13046
(gdb) next
.[New Thread 0x7ffff6dab700 (LWP 19978)]
47         for(j=2; j<number; j++)
(gdb) next
.52           if(number%j == 0)
(gdb) next 
.47        for(j=2; j<number; j++)
(gdb) continue
Continuing.
.........
990233331 is not a prime number
[Thread 0x7ffff75ac700 (LWP 19183) exited]
...............................................................................
9902343047 is a prime number
Done!
[Thread 0x7ffff6dab700 (LWP 19978) exited]
[Thread 0x7ffff7dad700 (LWP 19182) exited]
[Inferior 1 (process 19175) exited normally]
```

## 操作步骤如下…

就像我们可以跟踪子进程一样，我们也可以跟踪线程。虽然处理线程的方法有些不同，但仍然可以。每个线程启动后，GDB 会通知我们。然后我们可以使用`info threads`命令打印有关当前运行线程的信息。该命令为每个线程提供了一个线程 ID、其地址以及当前所在的帧或函数。然后我们使用`thread`命令跳转到线程 3。一旦我们进入线程，我们就可以打印`number`和`j`变量的内容，向代码中前进等等。

## 还有更多...

在 GDB 中，还有更多关于线程的操作。要查找有关线程的更多命令，可以在 GDB 中使用以下命令：

+   `help thread`

+   `help info threads`

## 另请参阅

关于 GDB 还有很多信息在[`www.gnu.org/software/gdb`](https://www.gnu.org/software/gdb)，所以可以查看更深入的信息。

# 使用 Valgrind 查找简单的内存泄漏

**Valgrind**是一个很棒的程序，可以找到**内存泄漏**和其他与内存相关的错误。它甚至可以告诉你是否在分配的内存区域中放入了太多数据。这些都是很难在没有 Valgrind 这样的工具的情况下找到的错误。即使程序泄漏内存或者在内存区域中放入了太多数据，它仍然可以长时间正常运行。这就是这些错误如此难以找到的原因。但是有了 Valgrind，我们可以检查程序是否存在各种与内存相关的问题。

## 入门

对于这个示例，您需要在计算机上安装 Valgrind 工具。如果您还没有安装它，可以按照本章的*技术要求*部分中列出的说明进行操作。

您还需要 Make 工具、GCC 编译器和*开始使用 GDB*示例中的 Makefile。

## 如何做...

在这个示例中，我们将编写一个使用`calloc()`分配内存但从未使用`free()`释放的程序。然后我们通过 Valgrind 运行程序，看看它对此有何说法：

1.  编写以下程序，并将其保存为`leak.c`。首先，我们创建一个指向字符的指针。然后，我们使用`calloc()`分配了 20 个字节的内存，并将其地址返回给`c`。然后我们将一个字符串复制到该内存中，并使用`printf()`打印内容。但是，我们从未使用`free()`释放内存，这是我们应该始终要做的：

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void)
{
    char *c;
    c = calloc(sizeof(char), 20);
    strcpy(c, "Hello!");
    printf("%s\n", c);
    return 0;
}
```

1.  编译程序：

```
$> make leak
gcc -g -Wall -Wextra -pedantic -std=c99    leak.c   -o leak
```

1.  首先，我们像平常一样运行程序。一切都很顺利：

```
$> ./leak 
Hello!
```

1.  现在，我们通过 Valgrind 运行程序。在`HEAP SUMMARY`下，它会告诉我们程序退出时仍有 20 个字节被分配。在`LEAK SUMMARY`下，我们还看到有 20 个字节*明确丢失*。这意味着我们忘记使用`free()`释放内存：

```
$> valgrind ./leak 
==9541== Memcheck, a memory error detector
==9541== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==9541== Using Valgrind-3.14.0 and LibVEX; rerun with -h for copyright info
==9541== Command: ./leak
==9541== 
Hello!
==9541== 
==9541== HEAP SUMMARY:
==9541==     in use at exit: 20 bytes in 1 blocks
==9541==   total heap usage: 2 allocs, 1 frees, 1,044 bytes allocated
==9541== 
==9541== LEAK SUMMARY:
==9541==    definitely lost: 20 bytes in 1 blocks
==9541==    indirectly lost: 0 bytes in 0 blocks
==9541==      possibly lost: 0 bytes in 0 blocks
==9541==    still reachable: 0 bytes in 0 blocks
==9541==         suppressed: 0 bytes in 0 blocks
==9541== Rerun with --leak-check=full to see details of leaked memory
==9541== 
==9541== For counts of detected and suppressed errors, rerun with: -v
==9541== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```

1.  打开`leak.c`，在`return 0;`之前添加`free(c);`。然后重新编译程序。

1.  在 Valgrind 中重新运行程序。这次，程序退出时不会有任何丢失或使用的字节。我们还看到有两个分配，并且它们都已被释放：

```
$>  valgrind ./leak 
==10354== Memcheck, a memory error detector
==10354== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==10354== Using Valgrind-3.14.0 and LibVEX; rerun with -h for copyright info
==10354== Command: ./leak
==10354== 
Hello!
==10354== 
==10354== HEAP SUMMARY:
==10354==     in use at exit: 0 bytes in 0 blocks
==10354==   total heap usage: 2 allocs, 2 frees, 1,044 bytes allocated
==10354== 
==10354== All heap blocks were freed -- no leaks are possible
==10354== 
==10354== For counts of detected and suppressed errors, rerun with: -v
==10354== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```

## 它是如何工作的...

Valgrind 说我们有两个分配的原因是，尽管我们只分配了一个内存块，程序中的其他函数也分配了内存。

在 Valgrind 的输出末尾，我们还看到了文本*所有堆块都已被释放*，这意味着我们已经使用`free()`释放了所有内存。

Valgrind 并不严格要求调试符号；我们可以测试几乎任何程序是否存在内存泄漏。例如，我们可以运行`valgrind cat leak.c`，Valgrind 将检查`cat`是否存在内存泄漏。

## 另请参阅

Valgrind 还有很多其他用途。查看其手册页面，使用`man valgrind`。还有很多有用的信息在[`www.valgrind.org`](https://www.valgrind.org)上。

# 使用 Valgrind 查找缓冲区溢出

Valgrind 还可以帮助我们找到**缓冲区溢出**。当我们在缓冲区中放入的数据超过其容量时，就会发生缓冲区溢出。缓冲区溢出是许多安全漏洞的原因，很难检测到。但是有了 Valgrind，情况会变得稍微容易一些。它可能并非始终 100%准确，但在一路上确实是一个很好的帮助。

知道如何找到缓冲区溢出将使您的程序更加安全。

## 准备工作

对于这个示例，您将需要 GCC 编译器，Make 工具以及本章中*开始 GDB*示例中的 Makefile。

## 如何做…

在这个示例中，我们将编写一个小程序，将过多的数据复制到缓冲区中。然后我们将通过 Valgrind 运行程序，看看它如何指出问题：

1.  在文件中写入以下代码，并将其保存为`overflow.c`。程序使用`calloc()`分配了 20 个字节，然后将一个 26 个字节的字符串复制到该缓冲区中。然后使用`free()`释放内存：

```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(void)
{
    char *c;
    c = calloc(sizeof(char), 20);
    strcpy(c, "Hello, how are you doing?");
    printf("%s\n", c);
    free(c);
    return 0;
}
```

1.  编译程序：

```
$> make overflow
gcc -g -Wall -Wextra -pedantic -std=c99    overflow.c   -o overflow
```

1.  首先，我们像平常一样运行程序。很可能，我们不会看到任何问题。它会正常工作。这就是为什么这种类型的错误很难找到的原因：

```
$> ./overflow 
Hello, how are you doing
```

1.  现在，让我们通过 Valgrind 运行程序，看看它对此有何看法：

```
c buffer, especially the text *4 bytes after a block of size 20 alloc'd*. That means that we have written 4 bytes of data *after* the 20 bytes we allocated. There are more lines like these, and they all point us toward the overflow.
```

## 它是如何工作的…

由于程序在分配的内存之外写入数据，Valgrind 将检测到它为无效写入和无效读取。我们甚至可以跟踪分配内存后写入了多少字节及其地址。这将使在代码中找到问题变得更容易。我们可能已经分配了几个缓冲区，但在这里我们清楚地看到，溢出的是 20 个字节的缓冲区。

## 还有更多...

为了获得更详细的输出，您可以在 Valgrind 中添加`-v`，例如，`valgrind -v ./overflow`。这将输出几页详细的输出。
