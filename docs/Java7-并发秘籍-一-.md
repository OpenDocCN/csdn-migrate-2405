# Java7 并发秘籍（一）

> 原文：[`zh.annas-archive.org/md5/F8E5EF0E7E4290BD7C1CC58C96A57EB0`](https://zh.annas-archive.org/md5/F8E5EF0E7E4290BD7C1CC58C96A57EB0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

当您使用计算机时，可以同时进行多项任务。您可以在编辑器中编辑文档并听音乐，同时阅读电子邮件。这是因为您的操作系统允许任务并发。并发编程涉及平台提供的元素和机制，使多个任务或程序同时运行并相互通信以交换数据或相互同步。Java 是一个并发平台，并提供了许多类来在 Java 程序中执行并发任务。随着每个版本的更新，Java 增加了为程序员提供的功能，以便更轻松地开发并发程序。本书涵盖了 Java 并发 API 第 7 版中包含的最重要和有用的机制，因此您将能够直接在应用程序中使用它们，具体包括：

+   基本线程管理

+   线程同步机制

+   使用执行器进行线程创建和管理委托

+   Fork/Join 框架以增强应用程序的性能

+   并发程序的数据结构

+   调整一些并发类的默认行为以满足您的需求

+   测试 Java 并发应用程序

# 本书涵盖的内容

第一章 *线程管理* 将教读者如何对线程进行基本操作。通过基本示例，解释了线程的创建、执行和状态管理。

第二章 *基本线程同步* 将教读者如何使用 Java 的低级机制来同步代码。详细解释了锁和 `synchronized` 关键字。

第三章 *线程同步工具* 将教读者如何使用 Java 的高级工具来管理 Java 中线程之间的同步。其中包括如何使用新的 Java 7 `Phaser` 类来同步分阶段的任务。

第四章 *线程执行器* 将教读者将线程管理委托给执行器。它们允许运行、管理和获取并发任务的结果。

第五章 *Fork/Join 框架* 将教读者如何使用新的 Java 7 Fork/Join 框架。这是一种特殊类型的执行器，旨在使用分而治之的技术将任务分解为更小的任务。

第六章 *并发集合* 将教读者如何使用 Java 语言提供的一些并发数据结构。这些数据结构必须在并发程序中使用，以避免在其实现中使用同步代码块。

第七章 *自定义并发类* 将教读者如何调整 Java 并发 API 中一些最有用的类以满足其需求。

第八章 *测试并发应用程序* 将教读者如何获取有关 Java 7 并发 API 中一些最有用结构状态的信息。读者还将学习如何使用一些免费工具来调试并发应用程序，例如 Eclipse、NetBeans IDE 或 FindBugs 应用程序，以检测其应用程序可能存在的错误。

*第九章* *附加信息* 不包含在书中，但可以从以下链接免费下载：[`www.packtpub.com/sites/default/files/downloads/Additional`](http://www.packtpub.com/sites/default/files/downloads/Additional)

本章将教读者同步、执行器和 Fork/Join 框架的概念，以及并发数据结构和监视并发对象的内容，这些内容在各自的章节中没有包含。

*附录*，*并发编程设计*不在书中，但可以从以下链接免费下载：[`www.packtpub.com/sites/default/files/downloads/Concurrent`](http://www.packtpub.com/sites/default/files/downloads/Concurrent)

本附录将教读者一些每个程序员在开发并发应用程序时应考虑的技巧。

# 您需要为本书做好准备的内容

要跟进本书，您需要对 Java 编程语言有基本了解。您应该知道如何使用 IDE，比如 Eclipse 或 NetBeans，但这不是必要的先决条件。

# 本书适合谁

如果您是一名 Java 开发人员，希望进一步了解并发编程和多线程的知识，以及发现 Java 7 的新并发特性，那么*Java 7 并发烹饪书*就是为您准备的。您应该已经熟悉一般的 Java 开发实践，并且对线程有基本的了解会是一个优势。

# 约定

在本书中，您将找到一些不同类型信息的文本样式。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码词显示如下：“扩展`Thread`类并重写`run()`方法”。

代码块设置如下：

```java
  public Calculator(int number) {
    this.number=number;
  }
```

**新术语**和**重要词汇**以粗体显示。例如，屏幕上看到的单词，比如菜单或对话框中的单词，会以这样的方式出现在文本中：“在菜单栏的**文件**菜单中选择**新建项目**选项创建新项目”。

### 注意

警告或重要说明会以这样的方式出现在方框中。

### 提示

提示和技巧会以这样的方式出现。

# 读者反馈

我们始终欢迎读者的反馈。让我们知道您对本书的看法——您喜欢或不喜欢的地方。读者的反馈对我们开发您真正受益的标题非常重要。

要向我们发送一般反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在消息主题中提及书名。

如果您对某个专题有专业知识，并且有兴趣撰写或为书籍做出贡献，请参阅我们的作者指南[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您是 Packt 书籍的自豪所有者，我们有一些事情可以帮助您充分利用您的购买。

## 下载示例代码

您可以从您在[`www.PacktPub.com`](http://www.PacktPub.com)购买的所有 Packt 书籍中下载示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.PacktPub.com/support`](http://www.PacktPub.com/support)并注册，以便将文件直接发送到您的电子邮件。

## 勘误

尽管我们已经尽一切努力确保内容的准确性，但错误是难免的。如果您在我们的书中发现错误——可能是文本或代码中的错误——我们将不胜感激地希望您向我们报告。通过这样做，您可以帮助其他读者避免挫败，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/support`](http://www.packtpub.com/support)报告，选择您的书，点击**勘误提交表**链接，并输入您的勘误详情。一旦您的勘误经过验证，您的提交将被接受，并且勘误将被上传到我们的网站上，或者添加到该标题的勘误列表中的任何现有勘误下的勘误部分。您可以通过从[`www.packtpub.com/support`](http://www.packtpub.com/support)选择您的标题来查看任何现有的勘误。

## 盗版

互联网上侵犯版权材料的盗版问题是跨媒体持续存在的问题。在 Packt，我们非常重视版权和许可的保护。如果您在互联网上发现我们作品的任何非法副本，请立即向我们提供地址或网站名称，以便我们采取补救措施。

请通过`<copyright@packtpub.com>`与我们联系，并提供涉嫌盗版材料的链接。

我们感谢您帮助保护我们的作者，以及我们为您提供有价值内容的能力。

## 问题

如果您在阅读本书的过程中遇到任何问题，请通过`<questions@packtpub.com>`与我们联系，我们将尽力解决。


# 第一章：线程管理

在本章中，我们将涵盖：

+   创建和运行线程

+   获取和设置线程信息

+   中断线程

+   控制线程的中断

+   休眠和恢复线程

+   等待线程的最终化

+   创建和运行守护线程

+   在线程中处理不受控制的异常

+   使用本地线程变量

+   将线程分组

+   在一组线程中处理不受控制的异常

+   通过工厂创建线程

# 介绍

在计算机世界中，当我们谈论**并发**时，我们谈论的是在计算机中同时运行的一系列任务。如果计算机有多个处理器或多核处理器，这种同时性可以是真实的，或者如果计算机只有一个核心处理器，这种同时性可以是表面的。

所有现代操作系统都允许执行并发任务。您可以在读取电子邮件的同时听音乐和在网页上阅读新闻。我们可以说这种并发是**进程级**的并发。但在一个进程内部，我们也可以有各种同时进行的任务。在进程内部运行的并发任务称为**线程**。

与并发相关的另一个概念是**并行**。并发概念有不同的定义和关系。一些作者在你在单核处理器上使用多个线程执行应用程序时谈论并发，因此同时你可以看到你的程序执行是表面的。此外，当您在多核处理器或具有多个处理器的计算机上使用多个线程执行应用程序时，您也可以谈论并行。其他作者在应用程序的线程在没有预定义顺序的情况下执行时谈论并发，并在使用各种线程简化问题解决方案时谈论并行，其中所有这些线程都以有序的方式执行。

本章介绍了一些示例，展示了如何使用 Java 7 API 执行线程的基本操作。您将看到如何在 Java 程序中创建和运行线程，如何控制它们的执行，以及如何将一些线程分组以将它们作为一个单元进行操作。

# 创建和运行线程

在这个示例中，我们将学习如何在 Java 应用程序中创建和运行线程。与 Java 语言中的每个元素一样，线程都是**对象**。在 Java 中创建线程有两种方式：

+   扩展`Thread`类并重写`run()`方法

+   构建一个实现`Runnable`接口的类，然后创建一个`Thread`类的对象，将`Runnable`对象作为参数传递

在这个示例中，我们将使用第二种方法创建一个简单的程序，创建并运行 10 个线程。每个线程计算并打印 1 到 10 之间的数字的乘法表。

## 准备工作

本示例已使用 Eclipse IDE 实现。如果您使用 Eclipse 或其他 IDE，如 NetBeans，请打开它并创建一个新的 Java 项目。

## 如何做...

按照以下步骤实现示例：

1.  创建一个名为`Calculator`的类，实现`Runnable`接口。

```java
public class Calculator implements Runnable {
```

1.  声明一个名为`number`的`private`整数属性，并实现初始化其值的类的构造函数。

```java
  private int number;
  public Calculator(int number) {
    this.number=number;
  }
```

1.  实现`run()`方法。这个方法将执行我们正在创建的线程的指令，因此这个方法将计算数字的乘法表。

```java
  @Override
  public void run() {
    for (int i=1; i<=10; i++){
      System.out.printf("%s: %d * %d = %d\n",Thread.currentThread().getName(),number,i,i*number);
    }
  }
```

1.  现在，实现应用程序的主类。创建一个名为`Main`的类，其中包含`main()`方法。

```java
public class Main {
  public static void main(String[] args) {
```

1.  在`main()`方法中，创建一个有 10 次迭代的`for`循环。在循环内，创建一个`Calculator`类的对象，一个`Thread`类的对象，将`Calculator`对象作为参数传递，并调用线程对象的`start()`方法。

```java
    for (int i=1; i<=10; i++){
      Calculator calculator=new Calculator(i);
      Thread thread=new Thread(calculator);
      thread.start();
    }
```

1.  运行程序，看看不同的线程如何并行工作。

## 它是如何工作的...

程序的输出部分如下截图所示。我们可以看到，我们创建的所有线程都并行运行以完成它们的工作，如下截图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-cncr-cb/img/7881_01_01.jpg)

每个 Java 程序至少有一个执行线程。运行程序时，JVM 会运行调用程序的`main()`方法的执行线程。

当我们调用`Thread`对象的`start()`方法时，我们正在创建另一个执行线程。我们的程序将有多少执行线程，就会调用多少次`start()`方法。

Java 程序在所有线程完成时结束（更具体地说，当所有非守护线程完成时）。如果初始线程（执行`main()`方法的线程）结束，其余线程将继续执行直到完成。如果其中一个线程使用`System.exit()`指令来结束程序的执行，所有线程都将结束执行。

创建`Thread`类的对象并不会创建新的执行线程。调用实现`Runnable`接口的类的`run()`方法也不会创建新的执行线程。只有调用`start()`方法才会创建新的执行线程。

## 还有更多...

正如我们在本示例的介绍中提到的，还有另一种创建新执行线程的方法。您可以实现一个继承`Thread`类并重写这个类的`run()`方法的类。然后，您可以创建这个类的对象并调用`start()`方法来创建一个新的执行线程。

## 另请参阅

+   在第一章的*通过工厂创建线程*示例中，*线程管理*

# 获取和设置线程信息

`Thread`类保存了一些信息属性，可以帮助我们识别线程、了解其状态或控制其优先级。这些属性包括：

+   **ID**：此属性为每个`Thread`存储一个唯一标识符。

+   **名称**：此属性存储`Thread`的名称。

+   **优先级**：此属性存储`Thread`对象的优先级。线程的优先级可以在 1 到 10 之间，其中 1 是最低优先级，10 是最高优先级。不建议更改线程的优先级，但如果需要，可以使用这个选项。

+   **状态**：此属性存储`Thread`的状态。在 Java 中，`Thread`可以处于以下六种状态之一：`new`、`runnable`、`blocked`、`waiting`、`time``waiting`或`terminated`。

在本示例中，我们将开发一个程序，为 10 个线程设置名称和优先级，然后显示它们的状态信息，直到它们完成。这些线程将计算一个数字的乘法表。

## 准备工作

本示例使用 Eclipse IDE 实现。如果您使用 Eclipse 或其他 IDE，如 NetBeans，请打开它并创建一个新的 Java 项目。

## 操作步骤...

按照以下步骤实现示例：

1.  创建一个名为`Calculator`的类，并指定它实现`Runnable`接口。

```java
public class Calculator implements Runnable {
```

1.  声明一个名为`number`的`int`私有属性，并实现初始化该属性的类的构造函数。

```java
  private int number;
  public Calculator(int number) {
    this.number=number;
  }
```

1.  实现`run()`方法。这个方法将执行我们正在创建的线程的指令，因此这个方法将计算并打印一个数字的乘法表。

```java
  @Override
  public void run() {
    for (int i=1; i<=10; i++){
      System.out.printf("%s: %d * %d = %d\n",Thread.currentThread().getName(),number,i,i*number);
    }
  }
```

1.  现在，我们实现这个示例的主类。创建一个名为`Main`的类，并实现`main()`方法。

```java
public class Main {
  public static void main(String[] args) {
```

1.  创建一个包含 10 个`threads`和 10 个`Thread.State`的数组，用于存储我们将要执行的线程及其状态。

```java
    Thread threads[]=new Thread[10];
    Thread.State status[]=new Thread.State[10];
```

1.  创建 10 个`Calculator`类的对象，每个对象都初始化为不同的数字，并创建 10 个`threads`来运行它们。将其中五个的优先级设置为最大值，将其余的优先级设置为最小值。

```java
    for (int i=0; i<10; i++){
      threads[i]=new Thread(new Calculator(i));
      if ((i%2)==0){
        threads[i].setPriority(Thread.MAX_PRIORITY);
      } else {
        threads[i].setPriority(Thread.MIN_PRIORITY);
      }
      threads[i].setName("Thread "+i);
    }
```

1.  创建一个`PrintWriter`对象来写入线程状态的文件。

```java
    try (FileWriter file = new FileWriter(".\\data\\log.txt");
PrintWriter pw = new PrintWriter(file);){
```

1.  在这个文件上写下 10 个“线程”的状态。现在，它变成了`NEW`。

```java
      for (int i=0; i<10; i++){
pw.println("Main : Status of Thread "+i+" : "  +             threads[i].getState());
        status[i]=threads[i].getState();
      }
```

1.  开始执行这 10 个线程。

```java
      for (int i=0; i<10; i++){
        threads[i].start();
      }
```

1.  直到这 10 个线程结束，我们将检查它们的状态。如果我们检测到线程状态的变化，我们就把它们写在文件中。

```java
      boolean finish=false;
      while (!finish) {
        for (int i=0; i<10; i++){
          if (threads[i].getState()!=status[i]) {
            writeThreadInfo(pw, threads[i],status[i]);
            status[i]=threads[i].getState();
          }
        }      
        finish=true;
        for (int i=0; i<10; i++){
finish=finish &&(threads[i].getState()==State.TERMINATED);
        }
      }
```

1.  实现`writeThreadInfo()`方法，该方法写入`Thread`的 ID、名称、优先级、旧状态和新状态。

```java
  private static void writeThreadInfo(PrintWriter pw, Thread thread, State state) {
pw.printf("Main : Id %d - %s\n",thread.getId(),thread.getName());
pw.printf("Main : Priority: %d\n",thread.getPriority());
pw.printf("Main : Old State: %s\n",state);
pw.printf("Main : New State: %s\n",thread.getState());
pw.printf("Main : ************************************\n");
  }
```

1.  运行示例并打开`log.txt`文件，查看这 10 个线程的演变。

## 它是如何工作的...

下面的截图显示了该程序执行过程中`log.txt`文件的一些行。在这个文件中，我们可以看到优先级最高的线程在优先级最低的线程之前结束。我们还可以看到每个线程状态的演变。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-cncr-cb/img/7881_01_02.jpg)

在控制台显示的程序是线程计算的乘法表和文件`log.txt`中不同线程状态的演变。通过这种方式，你可以更好地看到线程的演变。

`Thread`类有属性来存储线程的所有信息。JVM 使用线程的优先级来选择在每个时刻使用 CPU 的线程，并根据每个线程的情况更新每个线程的状态。

如果你没有为线程指定名称，JVM 会自动分配一个格式为 Thread-XX 的名称，其中 XX 是一个数字。你不能修改线程的 ID 或状态。`Thread`类没有实现`setId()`和`setStatus()`方法来允许它们的修改。

## 还有更多...

在这个示例中，你学会了如何使用`Thread`对象访问信息属性。但你也可以从`Runnable`接口的实现中访问这些属性。你可以使用`Thread`类的静态方法`currentThread()`来访问运行`Runnable`对象的`Thread`对象。

你必须考虑到，如果你尝试设置一个不在 1 到 10 之间的优先级，`setPriority()`方法可能会抛出`IllegalArgumentException`异常。

## 另请参阅

+   *中断线程*在第一章中的*线程管理*中的示例

# 中断线程

一个具有多个执行线程的 Java 程序只有在所有线程的执行结束时才会结束（更具体地说，当所有非守护线程结束执行或其中一个线程使用`System.exit()`方法时）。有时，你需要结束一个线程，因为你想终止一个程序，或者程序的用户想取消`Thread`对象正在执行的任务。

Java 提供了中断机制来指示线程我们想要结束它。这种机制的一个特点是`Thread`必须检查它是否被中断，它可以决定是否响应最终化请求。`Thread`可以忽略它并继续执行。

在这个示例中，我们将开发一个程序，创建`Thread`，并在 5 秒后使用中断机制强制结束它。

## 准备就绪

本示例使用 Eclipse IDE 实现。如果你使用 Eclipse 或其他 IDE，如 NetBeans，打开它并创建一个新的 Java 项目。

## 如何做...

按照以下步骤实现示例：

1.  创建一个名为`PrimeGenerator`的类，该类扩展了`Thread`类。

```java
public class PrimeGenerator extends Thread{
```

1.  重写`run()`方法，包括一个将无限运行的循环。在这个循环中，我们将处理从 1 开始的连续数字。对于每个数字，我们将计算它是否是一个质数，如果是，我们将把它写入控制台。

```java
  @Override
  public void run() {
    long number=1L;
    while (true) {
      if (isPrime(number)) {
        System.out.printf("Number %d is Prime",number);
      }
```

1.  处理完一个数字后，通过调用`isInterrupted()`方法来检查线程是否被中断。如果这个方法返回`true`，我们就写一条消息并结束线程的执行。

```java
      if (isInterrupted()) {
        System.out.printf("The Prime Generator has been Interrupted");
        return;
      }
      number++;
    }
  }
```

1.  实现`isPrime()`方法。它返回一个`boolean`值，指示接收的参数是否为质数（`true`）还是不是（`false`）。

```java
  private boolean isPrime(long number) {
    if (number <=2) {
      return true;
    }
    for (long i=2; i<number; i++){
      if ((number % i)==0) {
        return false;
      }
    }
    return true;
  }
```

1.  现在，通过实现一个名为`Main`的类并实现`main()`方法来实现示例的主类。

```java
public class Main {
  public static void main(String[] args) {
```

1.  创建并启动`PrimeGenerator`类的对象。

```java
    Thread task=new PrimeGenerator();
    task.start();
```

1.  等待 5 秒并中断`PrimeGenerator`线程。

```java
    try {
      Thread.sleep(5000);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
task.interrupt();
```

1.  运行示例并查看结果。

## 它是如何工作的...

以下屏幕截图显示了上一个示例的执行结果。我们可以看到`PrimeGenerator`线程在检测到被中断时写入消息并结束其执行。请参考以下屏幕截图：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-cncr-cb/img/7881_01_03.jpg)

`Thread`类有一个属性，用于存储一个`boolean`值，指示线程是否已被中断。当您调用线程的`interrupt()`方法时，您将该属性设置为`true`。`isInterrupted()`方法只返回该属性的值。

## 还有更多...

`Thread`类还有另一个方法来检查`Thread`是否已被中断。它是静态方法`interrupted()`，用于检查当前执行线程是否已被中断。

### 注意

`isInterrupted()`和`interrupted()`方法之间有一个重要的区别。第一个不会改变`interrupted`属性的值，但第二个会将其设置为`false`。由于`interrupted()`方法是一个静态方法，建议使用`isInterrupted()`方法。

如我之前提到的，`Thread`可以忽略其中断，但这不是预期的行为。

# 控制线程的中断

在上一个示例中，您学习了如何中断线程的执行以及如何控制`Thread`对象中的中断。在上一个示例中展示的机制可以用于可以被中断的简单线程。但是，如果线程实现了分为一些方法的复杂算法，或者它具有具有递归调用的方法，我们可以使用更好的机制来控制线程的中断。Java 为此提供了`InterruptedException`异常。当检测到线程中断时，您可以抛出此异常并在`run()`方法中捕获它。

在本示例中，我们将实现一个`Thread`，它在文件夹及其所有子文件夹中查找具有确定名称的文件，以展示如何使用`InterruptedException`异常来控制线程的中断。

## 准备工作

本示例使用 Eclipse IDE 实现。如果您使用 Eclipse 或其他 IDE（如 NetBeans），请打开它并创建一个新的 Java 项目。

## 操作步骤...

按照以下步骤实现示例：

1.  创建一个名为`FileSearch`的类，并指定它实现`Runnable`接口。

```java
public class FileSearch implements Runnable {
```

1.  声明两个`private`属性，一个用于要搜索的文件名，另一个用于初始文件夹。实现类的构造函数，初始化这些属性。

```java
  private String initPath;
  private String fileName;
  public FileSearch(String initPath, String fileName) {
    this.initPath = initPath;
    this.fileName = fileName;
  }
```

1.  实现`FileSearch`类的`run()`方法。它检查属性`fileName`是否为目录，如果是，则调用`processDirectory()`方法。该方法可能会抛出`InterruptedException`异常，因此我们必须捕获它们。

```java
  @Override
  public void run() {
    File file = new File(initPath);
    if (file.isDirectory()) {
      try {
        directoryProcess(file);
      } catch (InterruptedException e) {
        System.out.printf("%s: The search has been interrupted",Thread.currentThread().getName());
      }
    }
  }
```

1.  实现`directoryProcess()`方法。该方法将获取文件夹中的文件和子文件夹并对它们进行处理。对于每个目录，该方法将使用递归调用并将目录作为参数传递。对于每个文件，该方法将调用`fileProcess()`方法。在处理所有文件和文件夹后，该方法检查`Thread`是否已被中断，如果是，则抛出`InterruptedException`异常。

```java
  private void directoryProcess(File file) throws InterruptedException {
    File list[] = file.listFiles();
    if (list != null) {
      for (int i = 0; i < list.length; i++) {
        if (list[i].isDirectory()) {
          directoryProcess(list[i]);
        } else {
          fileProcess(list[i]);
        }
      }
    }
    if (Thread.interrupted()) {
      throw new InterruptedException();
    }
  }
```

1.  实现`processFile()`方法。此方法将比较其正在处理的文件的名称与我们正在搜索的名称。如果名称相等，我们将在控制台中写入一条消息。在此比较之后，`Thread`将检查它是否已被中断，如果是，则抛出`InterruptedException`异常。

```java
  private void fileProcess(File file) throws InterruptedException {
    if (file.getName().equals(fileName)) {
      System.out.printf("%s : %s\n",Thread.currentThread().getName() ,file.getAbsolutePath());
    }
    if (Thread.interrupted()) {
      throw new InterruptedException();
    }
  }
```

1.  现在，让我们实现示例的主类。实现一个名为`Main`的类，其中包含`main()`方法。

```java
public class Main {
  public static void main(String[] args) {
```

1.  创建并初始化`FileSearch`类的对象和`Thread`以执行其任务。然后，开始执行`Thread`。

```java
    FileSearch searcher=new FileSearch("C:\\","autoexec.bat");
    Thread thread=new Thread(searcher);
    thread.start();
```

1.  等待 10 秒并中断`Thread`。

```java
    try {
      TimeUnit.SECONDS.sleep(10);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
    thread.interrupt();
  }
```

1.  运行示例并查看结果。

## 工作原理...

以下屏幕截图显示了此示例执行的结果。您可以看到`FileSearch`对象在检测到已被中断时结束其执行。请参考以下屏幕截图：

![工作原理...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-cncr-cb/img/7881_01_04.jpg)

在此示例中，我们使用 Java 异常来控制`Thread`的中断。运行示例时，程序开始通过检查文件夹来检查它们是否有文件。例如，如果您进入文件夹`\b\c\d`，程序将对`processDirectory()`方法进行三次递归调用。当它检测到已被中断时，它会抛出`InterruptedException`异常，并在`run()`方法中继续执行，无论已经进行了多少次递归调用。

## 还有更多...

`InterruptedException`异常由一些与并发 API 相关的 Java 方法抛出，例如`sleep()`。

## 另请参阅

+   第一章中的*中断线程示例*，*线程管理*

# 休眠和恢复线程

有时，您可能会对在一定时间内中断`Thread`的执行感兴趣。例如，程序中的一个线程每分钟检查一次传感器状态。其余时间，线程什么也不做。在此期间，线程不使用计算机的任何资源。此时间结束后，当 JVM 选择执行时，线程将准备好继续执行。您可以使用`Thread`类的`sleep()`方法来实现这一目的。该方法接收一个整数作为参数，表示线程暂停执行的毫秒数。当休眠时间结束时，线程在`sleep()`方法调用后的指令中继续执行，当 JVM 分配给它们 CPU 时间时。

另一种可能性是使用`TimeUnit`枚举的元素的`sleep()`方法。此方法使用`Thread`类的`sleep()`方法将当前线程置于休眠状态，但它以表示的单位接收参数，并将其转换为毫秒。

在本示例中，我们将开发一个程序，使用`sleep()`方法每秒写入实际日期。

## 准备就绪

本示例已使用 Eclipse IDE 实现。如果您使用 Eclipse 或其他 IDE，如 NetBeans，请打开它并创建一个新的 Java 项目。

## 如何做...

按照以下步骤实现示例：

1.  创建一个名为`FileClock`的类，并指定它实现`Runnable`接口。

```java
public class FileClock implements Runnable {
```

1.  实现`run()`方法。

```java
  @Override
  public void run() {
```

1.  编写一个具有 10 次迭代的循环。在每次迭代中，创建一个`Date`对象，将其写入文件，并调用`TimeUnit`类的`SECONDS`属性的`sleep()`方法，以暂停线程的执行一秒钟。使用此值，线程将大约休眠一秒钟。由于`sleep()`方法可能会抛出`InterruptedException`异常，因此我们必须包含捕获它的代码。在线程被中断时，包括释放或关闭线程正在使用的资源的代码是一个良好的实践。

```java
    for (int i = 0; i < 10; i++) {
      System.out.printf("%s\n", new Date());
      try {
        TimeUnit.SECONDS.sleep(1);
      } catch (InterruptedException e) {
        System.out.printf("The FileClock has been interrupted");
      }
    }
  }
```

1.  我们已经实现了线程。现在，让我们实现示例的主类。创建一个名为`FileMain`的类，其中包含`main()`方法。

```java
public class FileMain {
  public static void main(String[] args) {
```

1.  创建一个`FileClock`类的对象和一个线程来执行它。然后，开始执行`Thread`。

```java
    FileClock clock=new FileClock();
    Thread thread=new Thread(clock);
    thread.start();
```

1.  在主`Thread`中调用`TimeUnit`类的 SECONDS 属性的`sleep()`方法，等待 5 秒。

```java
    try {
      TimeUnit.SECONDS.sleep(5);
    } catch (InterruptedException e) {
      e.printStackTrace();
    };
```

1.  中断`FileClock`线程。

```java
    thread.interrupt();
```

1.  运行这个例子并查看结果。

## 它是如何工作的...

当你运行这个例子时，你可以看到程序每秒写入一个`Date`对象，然后显示`FileClock`线程已被中断的消息。

当你调用`sleep()`方法时，`Thread`离开 CPU 并停止执行一段时间。在这段时间内，它不会消耗 CPU 时间，所以 CPU 可以执行其他任务。

当`Thread`正在睡眠并被中断时，该方法会立即抛出`InterruptedException`异常，而不会等到睡眠时间结束。

## 还有更多...

Java 并发 API 还有另一个方法，可以让`Thread`对象离开 CPU。这就是`yield()`方法，它告诉 JVM`Thread`对象可以离开 CPU 去做其他任务。JVM 不能保证会遵守这个请求。通常，它只用于调试目的。

# 等待线程的最终化

在某些情况下，我们需要等待线程的最终化。例如，我们可能有一个程序，在继续执行之前需要开始初始化所需的资源。我们可以将初始化任务作为线程运行，并在继续程序的其余部分之前等待其最终化。

为此，我们可以使用`Thread`类的`join()`方法。当我们使用一个线程对象调用这个方法时，它会暂停调用线程的执行，直到被调用的对象完成执行。

在这个示例中，我们将学习如何在初始化示例中使用这个方法。

## 准备工作

这个示例是使用 Eclipse IDE 实现的。如果你使用 Eclipse 或其他 IDE，比如 NetBeans，打开它并创建一个新的 Java 项目。

## 如何做...

按照以下步骤实现示例：

1.  创建一个名为`DataSourcesLoader`的类，并指定它实现`Runnable`接口。

```java
public class DataSourcesLoader implements Runnable {
```

1.  实现`run()`方法。它写入一个消息表示它开始执行，睡眠 4 秒，然后写入另一个消息表示它结束执行。

```java
  @Override
  public void run() {
    System.out.printf("Beginning data sources loading: %s\n",new Date());
    try {
      TimeUnit.SECONDS.sleep(4);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
    System.out.printf("Data sources loading has finished: %s\n",new Date());
  }
```

1.  创建一个名为`NetworkConnectionsLoader`的类，并指定它实现`Runnable`接口。实现`run()`方法。它将与`DataSourcesLoader`类的`run()`方法相同，但这将睡眠 6 秒。

1.  现在，创建一个包含`main()`方法的`Main`类。

```java
public class Main {
  public static void main(String[] args) {
```

1.  创建一个`DataSourcesLoader`类的对象和一个`Thread`来运行它。

```java
    DataSourcesLoader dsLoader = new DataSourcesLoader();
    Thread thread1 = new Thread(dsLoader,"DataSourceThread");
```

1.  创建一个`NetworkConnectionsLoader`类的对象和一个`Thread`来运行它。

```java
    NetworkConnectionsLoader ncLoader = new NetworkConnectionsLoader();
    Thread thread2 = new Thread(ncLoader,"NetworkConnectionLoader");
```

1.  调用两个`Thread`对象的`start()`方法。

```java
    thread1.start();
    thread2.start(); 
```

1.  等待使用`join()`方法来完成两个线程的最终化。这个方法可能会抛出`InterruptedException`异常，所以我们必须包含捕获它的代码。

```java
    try {
      thread1.join();
      thread2.join();
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
```

1.  写一个消息表示程序结束。

```java
    System.out.printf("Main: Configuration has been loaded: %s\n",new Date());
```

1.  运行程序并查看结果。

## 它是如何工作的...

当你运行这个程序时，你可以看到两个`Thread`对象开始执行。首先，`DataSourcesLoader`线程完成执行。然后，`NetworkConnectionsLoader`类完成执行，此时，主`Thread`对象继续执行并写入最终消息。

## 还有更多...

Java 提供了`join()`方法的另外两种形式：

+   join (long milliseconds)

+   join (long milliseconds, long nanos)

在`join()`方法的第一个版本中，调用线程不是无限期地等待被调用的线程的最终化，而是等待方法参数指定的毫秒数。例如，如果对象`thread1`有代码`thread2.join(1000)`，线程`thread1`会暂停执行，直到以下两种情况之一为真：

+   `thread2`完成了它的执行

+   已经过去了 1000 毫秒

当这两个条件中的一个为真时，`join()`方法返回。

`join()`方法的第二个版本与第一个版本类似，但接收毫秒数和纳秒数作为参数。

# 创建和运行守护线程

Java 有一种特殊类型的线程称为**守护**线程。这种类型的线程具有非常低的优先级，通常只有在程序中没有其他线程运行时才会执行。当守护线程是程序中唯一运行的线程时，JVM 会结束程序并完成这些线程。

具有这些特性，守护线程通常用作运行在同一程序中的普通（也称为用户）线程的服务提供者。它们通常有一个无限循环，等待服务请求或执行线程的任务。它们不能执行重要的工作，因为我们不知道它们何时会有 CPU 时间，并且如果没有其他线程运行，它们随时可以结束。这种类型线程的典型例子是 Java 垃圾收集器。

在这个示例中，我们将学习如何创建一个守护线程，开发一个包含两个线程的示例；一个用户线程在队列中写入事件，一个守护线程清理队列，删除超过 10 秒前生成的事件。

## 准备工作

这个示例已经使用 Eclipse IDE 实现。如果你使用 Eclipse 或其他 IDE，比如 NetBeans，打开它并创建一个新的 Java 项目。

## 如何做...

按照以下步骤实现示例：

1.  创建`Event`类。这个类只存储我们的程序将使用的事件的信息。声明两个私有属性，一个叫做`date`，类型为`java.util.Date`，另一个叫做`event`，类型为`String`。生成方法来写入和读取它们的值。

1.  创建`WriterTask`类并指定它实现`Runnable`接口。

```java
public class WriterTask implements Runnable {
```

1.  声明存储事件的队列并实现类的构造函数，初始化这个队列。

```java
private Deque<Event> deque;
  public WriterTask (Deque<Event> deque){
    this.deque=deque;
  }
```

1.  实现这个任务的`run()`方法。这个方法将有一个循环，循环 100 次。在每次迭代中，我们创建一个新的`Event`，将其保存在队列中，并休眠一秒。

```java
  @Override
  public void run() {
    for (int i=1; i<100; i++) {
      Event event=new Event();
      event.setDate(new Date());
      event.setEvent(String.format("The thread %s has generated an event",Thread.currentThread().getId()));
      deque.addFirst(event);
      try {
        TimeUnit.SECONDS.sleep(1);
      } catch (InterruptedException e) {
        e.printStackTrace();
      }
    }
  }
```

1.  创建`CleanerTask`类并指定它扩展`Thread`类。

```java
public class CleanerTask extends Thread {
```

1.  声明存储事件的队列并实现类的构造函数，初始化这个队列。在构造函数中，使用`setDaemon()`方法将这个`Thread`标记为守护线程。

```java
  private Deque<Event> deque;
  public CleanerTask(Deque<Event> deque) {
    this.deque = deque;
    setDaemon(true);
  }
```

1.  实现`run()`方法。它有一个无限循环，获取实际日期并调用`clean()`方法。

```java
  @Override
  public void run() {
    while (true) {
      Date date = new Date();
      clean(date);
    }
  }
```

1.  实现`clean()`方法。获取最后一个事件，如果它是在 10 秒前创建的，就删除它并检查下一个事件。如果删除了一个事件，就写入事件的消息和队列的新大小，这样你就可以看到它的演变。

```java
  private void clean(Date date) {
    long difference;
    boolean delete;

    if (deque.size()==0) {
      return;
    }
    delete=false;
    do {
      Event e = deque.getLast();
      difference = date.getTime() - e.getDate().getTime();
      if (difference > 10000) {
        System.out.printf("Cleaner: %s\n",e.getEvent());
        deque.removeLast();
        delete=true;
      }  
    } while (difference > 10000);
    if (delete){
      System.out.printf("Cleaner: Size of the queue: %d\n",deque.size());
    }
  }
```

1.  现在，实现主类。创建一个名为`Main`的类，其中包含一个`main()`方法。

```java
public class Main {
  public static void main(String[] args) {
```

1.  使用`Deque`类创建队列来存储事件。

```java
    Deque<Event> deque=new ArrayDeque<Event>();
```

1.  创建并启动三个`WriterTask`线程和一个`CleanerTask`。

```java
    WriterTask writer=new WriterTask(deque);
    for (int i=0; i<3; i++){
      Thread thread=new Thread(writer);
      thread.start();
    }
    CleanerTask cleaner=new CleanerTask(deque);
    cleaner.start();
```

1.  运行程序并查看结果。

## 工作原理...

如果分析程序的一次执行输出，可以看到队列开始增长，直到有 30 个事件，然后在执行结束之前，它的大小将在 27 和 30 个事件之间变化。

程序以三个`WriterTask`线程开始。每个`Thread`写入一个事件并休眠一秒。在第一个 10 秒之后，我们在队列中有 30 个线程。在这 10 秒内，`CleanerTasks`一直在执行，而三个`WriterTask`线程在休眠，但它没有删除任何事件，因为它们都是在不到 10 秒前生成的。在执行的其余时间里，`CleanerTask`每秒删除三个事件，而三个`WriterTask`线程写入另外三个事件，所以队列的大小在 27 和 30 个事件之间变化。

您可以调整`WriterTask`线程睡眠的时间。如果使用较小的值，您会发现`CleanerTask`的 CPU 时间较少，并且队列的大小会增加，因为`CleanerTask`不会删除任何事件。

## 还有更多...

在调用`start()`方法之前，您只能调用`setDaemon()`方法。一旦线程正在运行，就无法修改其守护进程状态。

您可以使用`isDaemon()`方法来检查线程是否是守护线程（方法返回`true`）还是用户线程（方法返回`false）。

# 处理线程中的未受控异常

Java 中有两种异常：

+   **已检查的异常**：这些异常必须在方法的`throws`子句中指定或在其中捕获。例如，`IOException`或`ClassNotFoundException`。

+   **未检查的异常**：这些异常不必指定或捕获。例如，`NumberFormatException`。

当在`Thread`对象的`run()`方法中抛出已检查的异常时，我们必须捕获和处理它们，因为`run()`方法不接受`throws`子句。当在`Thread`对象的`run()`方法中抛出未检查的异常时，默认行为是在控制台中写入堆栈跟踪并退出程序。

幸运的是，Java 为我们提供了一种机制来捕获和处理`Thread`对象中抛出的未检查异常，以避免程序结束。

在这个示例中，我们将使用一个示例来学习这个机制。

## 准备工作

这个示例使用 Eclipse IDE 实现。如果您使用 Eclipse 或其他 IDE，如 NetBeans，打开它并创建一个新的 Java 项目。

## 如何做...

按照以下步骤实现示例：

1.  首先，我们必须实现一个类来处理未检查的异常。这个类必须实现`UncaughtExceptionHandler`接口，并实现该接口中声明的`uncaughtException()`方法。在我们的情况下，将这个类命名为`ExceptionHandler`，并使该方法写入有关抛出异常的`Exception`和`Thread`的信息。以下是代码：

```java
public class ExceptionHandler implements UncaughtExceptionHandler {
  public void uncaughtException(Thread t, Throwable e) {
    System.out.printf("An exception has been captured\n");
    System.out.printf("Thread: %s\n",t.getId());
    System.out.printf("Exception: %s: %s\n",e.getClass().getName(),e.getMessage());
    System.out.printf("Stack Trace: \n");
    e.printStackTrace(System.out);
    System.out.printf("Thread status: %s\n",t.getState());
  }
}
```

1.  现在，实现一个抛出未检查异常的类。将这个类命名为`Task`，指定它实现`Runnable`接口，实现`run()`方法，并强制异常，例如，尝试将`string`值转换为`int`值。

```java
public class Task implements Runnable {
  @Override
  public void run() {
    int numero=Integer.parseInt("TTT");
  }
}
```

1.  现在，实现示例的主类。使用`main()`方法实现一个名为`Main`的类。

```java
public class Main {
  public static void main(String[] args) {
```

1.  创建一个`Task`对象和`Thread`来运行它。使用`setUncaughtExceptionHandler()`方法设置未检查的异常处理程序，并开始执行`Thread`。

```java
    Task task=new Task();
    Thread thread=new Thread(task);
    thread.setUncaughtExceptionHandler(new ExceptionHandler());
    thread.start();
    }
}
```

1.  运行示例并查看结果。

## 它是如何工作的...

在下面的屏幕截图中，您可以看到示例执行的结果。异常被抛出并被处理程序捕获，该处理程序在控制台中写入有关抛出异常的`Exception`和`Thread`的信息。请参考以下屏幕截图：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-cncr-cb/img/7881_01_05.jpg)

当线程中抛出异常并且未被捕获（必须是未检查的异常）时，JVM 会检查线程是否有相应方法设置的未捕获异常处理程序。如果有，JVM 将使用`Thread`对象和`Exception`作为参数调用此方法。

如果线程没有未捕获的异常处理程序，JVM 会在控制台中打印堆栈跟踪并退出程序。

## 还有更多...

`Thread`类还有另一个与未捕获异常处理相关的方法。这是静态方法`setDefaultUncaughtExceptionHandler()`，它为应用程序中的所有`Thread`对象建立异常处理程序。

当在`Thread`中抛出未捕获的异常时，JVM 会寻找此异常的三个可能处理程序。

首先，查找`Thread`对象的未捕获异常处理程序，就像我们在这个示例中学到的那样。如果这个处理程序不存在，那么 JVM 将查找`Thread`对象的`ThreadGroup`的未捕获异常处理程序，就像在*在一组线程中处理不受控制的异常*示例中解释的那样。如果这个方法不存在，JVM 将查找默认的未捕获异常处理程序，就像我们在这个示例中学到的那样。

如果没有处理程序退出，JVM 会在控制台中写入异常的堆栈跟踪，并退出程序。

## 另请参阅

+   第一章中的*在一组线程中处理不受控制的异常*示例，*线程管理*

# 使用本地线程变量

并发应用程序中最关键的一个方面是共享数据。这在那些扩展了`Thread`类或实现了`Runnable`接口的对象中尤为重要。

如果你创建了一个实现了`Runnable`接口的类的对象，然后使用相同的`Runnable`对象启动各种`Thread`对象，所有线程都共享相同的属性。这意味着，如果你在一个线程中改变了一个属性，所有线程都会受到这个改变的影响。

有时，你可能会对一个属性感兴趣，这个属性不会在运行相同对象的所有线程之间共享。Java 并发 API 提供了一个称为线程本地变量的清晰机制，性能非常好。

在这个示例中，我们将开发一个程序，其中包含第一段中暴露的问题，以及使用线程本地变量机制解决这个问题的另一个程序。

## 准备工作

这个示例已经使用 Eclipse IDE 实现。如果你使用 Eclipse 或其他 IDE，比如 NetBeans，打开它并创建一个新的 Java 项目。

## 如何做...

按照以下步骤实现示例：

1.  首先，我们将实现一个程序，其中包含先前暴露的问题。创建一个名为`UnsafeTask`的类，并指定它实现了`Runnable`接口。声明一个`private``java.util.Date`属性。

```java
public class UnsafeTask implements Runnable{
  private Date startDate;
```

1.  实现`UnsafeTask`对象的`run()`方法。这个方法将初始化`startDate`属性，将它的值写入控制台，休眠一段随机时间，然后再次写入`startDate`属性的值。

```java
  @Override
  public void run() {
    startDate=new Date();
    System.out.printf("Starting Thread: %s : %s\n",Thread.currentThread().getId(),startDate);
    try {
      TimeUnit.SECONDS.sleep( (int)Math.rint(Math.random()*10));
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
    System.out.printf("Thread Finished: %s : %s\n",Thread.currentThread().getId(),startDate);
  }
```

1.  现在，让我们实现这个有问题的应用程序的主类。创建一个名为`Main`的类，其中包含一个`main()`方法。这个方法将创建一个`UnsafeTask`类的对象，并使用该对象启动三个线程，在每个线程之间休眠 2 秒。

```java
public class Core {
  public static void main(String[] args) {
    UnsafeTask task=new UnsafeTask();
    for (int i=0; i<10; i++){
      Thread thread=new Thread(task);
      thread.start();
      try {
        TimeUnit.SECONDS.sleep(2);
      } catch (InterruptedException e) {
        e.printStackTrace();
      }
    }
  }
}
```

1.  在下面的截图中，你可以看到这个程序执行的结果。每个`Thread`有不同的开始时间，但当它们完成时，所有的`startDate`属性都有相同的值。![如何做...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-cncr-cb/img/7881_01_06.jpg)

1.  如前所述，我们将使用线程本地变量机制来解决这个问题。

1.  创建一个名为`SafeTask`的类，并指定它实现了`Runnable`接口。

```java
public class SafeTask implements Runnable {
```

1.  声明一个`ThreadLocal<Date>`类的对象。这个对象将具有一个包含`initialValue()`方法的隐式实现。这个方法将返回实际的日期。

```java
  private static ThreadLocal<Date> startDate= new ThreadLocal<Date>() {
    protected Date initialValue(){
      return new Date();
    }
  };
```

1.  实现`run()`方法。它具有与`UnsafeClass`的`run()`方法相同的功能，但它改变了访问`startDate`属性的方式。

```java
  @Override
  public void run() {
    System.out.printf("Starting Thread: %s : %s\n",Thread.currentThread().getId(),startDate.get());
    try {
      TimeUnit.SECONDS.sleep((int)Math.rint(Math.random()*10));
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
    System.out.printf("Thread Finished: %s : %s\n",Thread.currentThread().getId(),startDate.get());
  }
```

1.  这个示例的主类与不安全的示例相同，只是改变了`Runnable`类的名称。

1.  运行示例并分析差异。

## 它是如何工作的...

在下面的截图中，你可以看到安全示例执行的结果。现在，三个`Thread`对象都有自己的`startDate`属性的值。参考下面的截图：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-cncr-cb/img/7881_01_07.jpg)

线程本地变量为使用这些变量的每个`Thread`存储一个属性的值。您可以使用`get()`方法读取该值，并使用`set()`方法更改该值。第一次访问线程本地变量的值时，如果它对于调用它的`Thread`对象没有值，则线程本地变量将调用`initialValue()`方法为该`Thread`分配一个值，并返回初始值。

## 还有更多...

线程本地类还提供了`remove()`方法，用于删除调用它的线程的线程本地变量中存储的值。

Java 并发 API 包括`InheritableThreadLocal`类，它提供了从线程创建的线程继承值的功能。如果线程 A 在线程本地变量中有一个值，并且它创建另一个线程 B，则线程 B 将在线程本地变量中具有与线程 A 相同的值。您可以重写`childValue()`方法，该方法用于初始化线程本地变量中子线程的值。它将父线程在线程本地变量中的值作为参数。

# 将线程分组

Java 并发 API 提供的一个有趣功能是能够对线程进行分组。这使我们能够将组中的线程视为单个单位，并提供对属于组的`Thread`对象的访问，以对它们进行操作。例如，如果有一些线程执行相同的任务，并且您想要控制它们，无论有多少线程正在运行，每个线程的状态都将通过单个调用中断所有线程。

Java 提供了`ThreadGroup`类来处理线程组。`ThreadGroup`对象可以由`Thread`对象和另一个`ThreadGroup`对象组成，生成线程的树形结构。

在这个示例中，我们将学习如何使用`ThreadGroup`对象开发一个简单的示例。我们将有 10 个线程在随机时间段内休眠（例如模拟搜索），当其中一个完成时，我们将中断其余的线程。

## 准备工作

这个示例使用 Eclipse IDE 实现。如果您使用 Eclipse 或其他 IDE，如 NetBeans，打开它并创建一个新的 Java 项目。

## 如何做...

按照以下步骤实现示例：

1.  首先，创建一个名为`Result`的类。它将存储首先完成的`Thread`的名称。声明一个名为`name`的`private`字符串属性和用于读取和设置该值的方法。

1.  创建一个名为`SearchTask`的类，并指定它实现`Runnable`接口。

```java
public class SearchTask implements Runnable {
```

1.  声明`Result`类的`private`属性并实现该类的构造函数以初始化此属性。

```java
  private Result result;
  public SearchTask(Result result) {
    this.result=result;
  }
```

1.  实现`run()`方法。它将调用`doTask()`方法并等待其完成或出现`InterruptedException`异常。该方法将写入消息以指示此`Thread`的开始、结束或中断。

```java
  @Override
  public void run() {
    String name=Thread.currentThread().getName();
    System.out.printf("Thread %s: Start\n",name);
    try {
      doTask();
      result.setName(name);
    } catch (InterruptedException e) {
      System.out.printf("Thread %s: Interrupted\n",name);
      return;
    }
    System.out.printf("Thread %s: End\n",name);
  }
```

1.  实现`doTask()`方法。它将创建一个`Random`对象来生成一个随机数，并调用`sleep()`方法来休眠该随机数的时间。

```java
  private void doTask() throws InterruptedException {
    Random random=new Random((new Date()).getTime());
    int value=(int)(random.nextDouble()*100);
    System.out.printf("Thread %s: %d\n",Thread.currentThread().getName(),value);
    TimeUnit.SECONDS.sleep(value);
  }
```

1.  现在，通过创建一个名为`Main`的类并实现`main()`方法来创建示例的主类。

```java
public class Main {
  public static void main(String[] args) {
```

1.  首先，创建一个`ThreadGroup`对象并将其命名为`Searcher`。

```java
    ThreadGroup threadGroup = new ThreadGroup("Searcher");
```

1.  然后，创建一个`SearchTask`对象和一个`Result`对象。

```java
    Result result=new Result();     SearchTask searchTask=new SearchTask(result);
```

1.  现在，使用`SearchTask`对象创建 10 个`Thread`对象。当调用`Thread`类的构造函数时，将其作为`ThreadGroup`对象的第一个参数传递。

```java
    for (int i=0; i<5; i++) {
      Thread thread=new Thread(threadGroup, searchTask);
      thread.start();
      try {
        TimeUnit.SECONDS.sleep(1);
      } catch (InterruptedException e) {
        e.printStackTrace();
      }
    }
```

1.  使用`list()`方法写入关于`ThreadGroup`对象的信息。

```java
    System.out.printf("Number of Threads: %d\n",threadGroup.activeCount());
    System.out.printf("Information about the Thread Group\n");
    threadGroup.list();
```

1.  使用`activeCount()`和`enumerate()`方法来了解有多少`Thread`对象与`ThreadGroup`对象相关联，并获取它们的列表。我们可以使用此方法来获取每个`Thread`的状态，例如。

```java
    Thread[] threads=new Thread[threadGroup.activeCount()];
    threadGroup.enumerate(threads);
    for (int i=0; i<threadGroup.activeCount(); i++) {
      System.out.printf("Thread %s: %s\n",threads[i].getName(),threads[i].getState());
    }
```

1.  调用`waitFinish()`方法。我们稍后将实现此方法。它将等待直到`ThreadGroup`对象的一个线程结束。

```java
    waitFinish(threadGroup);
```

1.  使用`interrupt()`方法中断组中其余的线程。

```java
    threadGroup.interrupt();
```

1.  实现`waitFinish()`方法。它将使用`activeCount()`方法来控制其中一个线程的结束。

```java
  private static void waitFinish(ThreadGroup threadGroup) {
    while (threadGroup.activeCount()>9) {
      try {
        TimeUnit.SECONDS.sleep(1);
      } catch (InterruptedException e) {
        e.printStackTrace();
      }
    }
  }
```

1.  运行示例并查看结果。

## 它是如何工作的...

在下面的屏幕截图中，您可以看到`list()`方法的输出以及当我们写入每个`Thread`对象的状态时生成的输出，如下面的屏幕截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-cncr-cb/img/7881_01_08.jpg)

`ThreadGroup`类存储`Thread`对象和与之关联的其他`ThreadGroup`对象，因此它可以访问它们所有的信息（例如状态）并对其所有成员执行操作（例如中断）。

## 还有更多...

`ThreadGroup`类有更多的方法。查看 API 文档以获得所有这些方法的完整解释。

# 在一组线程中处理不受控制的异常

在每种编程语言中，一个非常重要的方面是提供管理应用程序中错误情况的机制。Java 语言，就像几乎所有现代编程语言一样，实现了基于异常的机制来管理错误情况。它提供了许多类来表示不同的错误。当检测到错误情况时，Java 类会抛出这些异常。您也可以使用这些异常，或者实现自己的异常来管理类中产生的错误。

Java 还提供了一种机制来捕获和处理这些异常。有些异常必须使用方法的`throws`子句捕获或重新抛出。这些异常称为已检查异常。有些异常不必指定或捕获。这些是未检查的异常。

在这个示例中，*控制线程的中断*，你学会了如何使用一个通用方法来处理`Thread`对象中抛出的所有未捕获的异常。

另一种可能性是建立一个方法，捕获`ThreadGroup`类的任何`Thread`抛出的所有未捕获的异常。

在这个示例中，我们将学习使用一个例子来设置这个处理程序。

## 准备工作

这个示例使用 Eclipse IDE 实现。如果你使用 Eclipse 或其他 IDE 如 NetBeans，打开它并创建一个新的 Java 项目。

## 操作步骤...

按照以下步骤实现示例：

1.  首先，我们必须通过创建一个名为`MyThreadGroup`的类来扩展`ThreadGroup`类，该类从`ThreadGroup`类扩展。我们必须声明一个带有一个参数的构造函数，因为`ThreadGroup`类没有没有参数的构造函数。

```java
public class MyThreadGroup extends ThreadGroup {
  public MyThreadGroup(String name) {
    super(name);
  }
```

1.  重写`uncaughtException()`方法。当`ThreadGroup`类的一个线程抛出异常时，将调用此方法。在这种情况下，此方法将在控制台中写入有关异常和抛出异常的`Thread`的信息，并中断`ThreadGroup`类中的其余线程。

```java
  @Override
  public void uncaughtException(Thread t, Throwable e) {
    System.out.printf("The thread %s has thrown an Exception\n",t.getId());
    e.printStackTrace(System.out);
    System.out.printf("Terminating the rest of the Threads\n");
    interrupt();
  }
```

1.  创建一个名为`Task`的类，并指定它实现`Runnable`接口。

```java
public class Task implements Runnable {
```

1.  实现`run()`方法。在这种情况下，我们将引发一个`AritmethicException`异常。为此，我们将在随机数之间除以 1000，直到随机生成器生成零并抛出异常。

```java
  @Override
  public void run() {
    int result;
    Random random=new Random(Thread.currentThread().getId());
    while (true) {
      result=1000/((int)(random.nextDouble()*1000));
      System.out.printf("%s : %f\n",Thread.currentThread().getId(),result);
      if (Thread.currentThread().isInterrupted()) {
        System.out.printf("%d : Interrupted\n",Thread.currentThread().getId());
        return;
      }
    }
  }
```

1.  现在，我们将通过创建一个名为`Main`的类并实现`main()`方法来实现示例的主类。

```java
public class Main {
  public static void main(String[] args) {
```

1.  创建一个`MyThreadGroup`类的对象。

```java
    MyThreadGroup threadGroup=new MyThreadGroup("MyThreadGroup");
```

1.  创建一个`Task`类的对象。

```java
    Task task=new Task();
```

1.  创建两个带有这个`Task`的`Thread`对象并启动它们。

```java
    for (int i=0; i<2; i++){
      Thread t=new Thread(threadGroup,task);
      t.start();
    }
```

1.  运行示例并查看结果。

## 它是如何工作的...

当你运行示例时，你会看到其中一个`Thread`对象抛出了异常，另一个被中断了。

当在`Thread`中抛出未捕获的异常时，JVM 会寻找这个异常的三个可能的处理程序。

首先，查找线程的未捕获异常处理程序，就像在*处理线程中的不受控制的异常*配方中所解释的那样。如果这个处理程序不存在，那么 JVM 会查找线程的`ThreadGroup`类的未捕获异常处理程序，就像我们在这个配方中学到的那样。如果这个方法不存在，JVM 会查找默认的未捕获异常处理程序，就像在*处理线程中的不受控制的异常*配方中所解释的那样。

如果没有处理程序退出，JVM 会在控制台中写入异常的堆栈跟踪，并退出程序。

## 另请参阅

+   第一章中的*处理线程中的不受控制的异常*配方，*线程管理*

# 通过工厂创建线程

工厂模式是面向对象编程世界中最常用的设计模式之一。它是一种创建模式，其目标是开发一个使命将是创建一个或多个类的其他对象的对象。然后，当我们想要创建其中一个类的对象时，我们使用工厂而不是使用`new`运算符。

有了这个工厂，我们可以集中创建对象，并获得一些优势：

+   很容易改变创建的对象的类或创建这些对象的方式。

+   很容易限制为有限资源创建对象。例如，我们只能有一个类型的*n*个对象。

+   很容易生成有关对象创建的统计数据。

Java 提供了一个接口，即`ThreadFactory`接口，用于实现`Thread`对象工厂。Java 并发 API 的一些高级工具使用线程工厂来创建线程。

在这个配方中，我们将学习如何实现`ThreadFactory`接口，以创建具有个性化名称的`Thread`对象，同时保存创建的`Thread`对象的统计数据。

## 准备工作

这个配方的示例是使用 Eclipse IDE 实现的。如果您使用 Eclipse 或其他 IDE，如 NetBeans，打开它并创建一个新的 Java 项目。

## 如何做...

按照以下步骤实现示例：

1.  创建一个名为`MyThreadFactory`的类，并指定它实现`ThreadFactory`接口。

```java
public class MyThreadFactory implements ThreadFactory {
```

1.  声明三个属性：一个名为`counter`的整数，我们将用它来存储创建的`Thread`对象的数量，一个名为`name`的`String`，它是每个创建的`Thread`的基本名称，以及一个名为`stats`的`String`对象列表，用于保存有关创建的`Thread`对象的统计数据。我们还实现了初始化这些属性的类的构造函数。

```java
  private int counter;
  private String name;
  private List<String> stats;

  public MyThreadFactory(String name){
    counter=0;
    this.name=name;
    stats=new ArrayList<String>();
  }
```

1.  实现`newThread()`方法。这个方法将接收一个`Runnable`接口，并为这个`Runnable`接口返回一个`Thread`对象。在我们的例子中，我们生成`Thread`对象的名称，创建新的`Thread`对象，并保存统计数据。

```java
  @Override
  public Thread newThread(Runnable r) {
    Thread t=new Thread(r,name+"-Thread_"+counter);
    counter++;
    stats.add(String.format("Created thread %d with name %s on %s\n",t.getId(),t.getName(),new Date()));
    return t;
  }
```

1.  实现`getStatistics()`方法，返回包含所有创建的`Thread`对象的统计数据的`String`对象。

```java
  public String getStats(){
    StringBuffer buffer=new StringBuffer();
    Iterator<String> it=stats.iterator();

    while (it.hasNext()) {
      buffer.append(it.next());
      buffer.append("\n");
    }

    return buffer.toString();
  }
```

1.  创建一个名为`Task`的类，并指定它实现`Runnable`接口。在这个例子中，这些任务除了睡一秒钟之外什么也不做。

```java
public class Task implements Runnable {
  @Override
  public void run() {
    try {
      TimeUnit.SECONDS.sleep(1);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
  }
}
```

1.  创建示例的主类。创建一个名为`Main`的类，并实现`main()`方法。

```java
public class Main {
  public static void main(String[] args) {
```

1.  创建一个`MyThreadFactory`对象和一个`Task`对象。

```java
    MyThreadFactory factory=new MyThreadFactory("MyThreadFactory");
    Task task=new Task();
```

1.  使用`MyThreadFactory`对象创建 10 个`Thread`对象并启动它们。

```java
    Thread thread;
    System.out.printf("Starting the Threads\n");
    for (int i=0; i<10; i++){
      thread=factory.newThread(task);
      thread.start();
    }
```

1.  在控制台中写入线程工厂的统计数据。

```java
    System.out.printf("Factory stats:\n");
    System.out.printf("%s\n",factory.getStats());
```

1.  运行示例并查看结果。

## 它是如何工作的...

`ThreadFactory`接口只有一个名为`newThread`的方法。它接收一个`Runnable`对象作为参数，并返回一个`Thread`对象。当您实现`ThreadFactory`接口时，您必须实现该接口并重写此方法。大多数基本的`ThreadFactory`只有一行。

```java
return new Thread(r);
```

您可以通过添加一些变体来改进这个实现：

+   创建个性化的线程，就像示例中使用特殊格式的名称或甚至创建我们自己的`thread`类一样，该类继承了 Java 的`Thread`类。

+   保存线程创建统计信息，如前面的示例所示

+   限制创建的线程数量

+   验证线程的创建

+   以及您可以想象的任何其他内容

使用工厂设计模式是一种良好的编程实践，但是，如果您实现了`ThreadFactory`接口来集中创建线程，您必须审查代码以确保所有线程都是使用该工厂创建的。

## 参见

+   第七章中的*实现 ThreadFactory 接口生成自定义线程*配方，*自定义并发类*

+   第七章中的*在 Executor 对象中使用我们的 ThreadFactory*配方，*自定义并发类*


# 第二章：基本线程同步

在本章中，我们将涵盖：

+   同步一个方法

+   在同步类中排列独立属性

+   在同步代码中使用条件

+   使用锁同步代码块

+   使用读/写锁同步数据访问

+   修改锁的公平性

+   在锁中使用多个条件

# 介绍

并发编程中最常见的情况之一是多个执行线程共享资源。在并发应用程序中，多个线程读取或写入相同的数据，或者访问相同的文件或数据库连接是正常的。这些共享资源可能引发错误情况或数据不一致，我们必须实现机制来避免这些错误。

这些问题的解决方案是通过**关键部分**的概念得到的。关键部分是指访问共享资源的代码块，不能同时由多个线程执行。

为了帮助程序员实现关键部分，Java（以及几乎所有编程语言）提供了**同步**机制。当一个线程想要访问关键部分时，它使用这些同步机制之一来查找是否有其他线程正在执行关键部分。如果没有，线程就进入关键部分。否则，线程被同步机制挂起，直到正在执行关键部分的线程结束。当多个线程等待一个线程完成关键部分的执行时，JVM 会选择其中一个，其余的等待他们的轮到。

本章介绍了一些教授如何使用 Java 语言提供的两种基本同步机制的方法：

+   关键字`synchronized`

+   `Lock`接口及其实现

# 同步一个方法

在这个示例中，我们将学习如何使用 Java 中最基本的同步方法之一，即使用`Synchronized`关键字来控制对方法的并发访问。只有一个执行线程将访问使用`Synchronized`关键字声明的对象的方法。如果另一个线程尝试访问同一对象的任何使用`Synchronized`关键字声明的方法，它将被挂起，直到第一个线程完成方法的执行。

换句话说，使用`Synchronized`关键字声明的每个方法都是一个关键部分，Java 只允许执行对象的一个关键部分。

静态方法有不同的行为。只有一个执行线程将访问使用`Synchronized`关键字声明的静态方法之一，但另一个线程可以访问该类对象的其他非静态方法。在这一点上你必须非常小心，因为如果一个是静态的，另一个不是，两个线程可以访问两个不同的`Synchronized`方法。如果这两个方法都改变了相同的数据，就可能出现数据不一致的错误。

为了学习这个概念，我们将实现一个示例，其中有两个线程访问一个共同的对象。我们将有一个银行账户和两个线程；一个向账户转账，另一个从账户取款。没有同步方法，我们可能会得到不正确的结果。同步机制确保账户的最终余额是正确的。

## 准备就绪

这个示例已经在 Eclipse IDE 中实现。如果你使用 Eclipse 或其他 IDE，比如 NetBeans，打开它并创建一个新的 Java 项目。

## 如何做...

按照以下步骤实现示例：

1.  创建一个名为`Account`的类来模拟我们的银行账户。它只有一个名为`balance`的`double`属性。

```java
public class Account {
      private double balance;
```

1.  实现`setBalance()`和`getBalance()`方法来写入和读取属性的值。

```java
  public double getBalance() {
    return balance;
  }

  public void setBalance(double balance) {
    this.balance = balance;
  }
```

1.  实现一个名为`addAmount()`的方法，该方法增加传递给方法的特定金额的余额值。只有一个线程应该更改余额的值，因此使用`synchronized`关键字将此方法转换为临界区。

```java
  public synchronized void addAmount(double amount) {
    double tmp=balance;
    try {
      Thread.sleep(10);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
    tmp+=amount;
    balance=tmp;
  }
```

1.  实现一个名为`subtractAmount()`的方法，该方法减少传递给方法的特定金额的余额值。只有一个线程应该更改余额的值，因此使用`synchronized`关键字将此方法转换为临界区。

```java
  public synchronized void subtractAmount(double amount) {
    double tmp=balance;
    try {
      Thread.sleep(10);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
    tmp-=amount;
    balance=tmp;
  }
```

1.  实现一个模拟 ATM 的类。它将使用`subtractAmount()`方法来减少账户的余额。这个类必须实现`Runnable`接口以作为线程执行。

```java
public class Bank implements Runnable {
```

1.  将一个`Account`对象添加到这个类中。实现初始化该`Account`对象的类的构造函数。

```java
  private Account account;

  public Bank(Account account) {
    this.account=account;
  }
```

1.  实现`run()`方法。它对一个账户进行`100`次`subtractAmount()`方法的调用以减少余额。

```java
  @Override
   public void run() {
    for (int i=0; i<100; i++){
      account.sustractAmount(1000);
    }
  }
```

1.  实现一个模拟公司的类，并使用`Account`类的`addAmount()`方法来增加账户的余额。这个类必须实现`Runnable`接口以作为线程执行。

```java
public class Company implements Runnable {
```

1.  将一个`Account`对象添加到这个类中。实现初始化该账户对象的类的构造函数。

```java
  private Account account;

  public Company(Account account) {
    this.account=account;
  }
```

1.  实现`run()`方法。它对一个账户进行`100`次`addAmount()`方法的调用以增加余额。

```java
  @Override
   public void run() {
    for (int i=0; i<100; i++){
      account.addAmount(1000);
    }
  }
```

1.  通过创建一个名为`Main`的类并包含`main()`方法来实现应用程序的主类。

```java
public class Main {

  public static void main(String[] args) {
```

1.  创建一个`Account`对象并将其余额初始化为`1000`。

```java
    Account  account=new Account();
    account.setBalance(1000);
```

1.  创建一个`Company`对象和一个`Thread`来运行它。

```java
    Company  company=new Company(account);
    Thread companyThread=new Thread(company);  
```

1.  创建一个`Bank`对象和一个`Thread`来运行它。

```java
    Bank bank=new Bank(account);
    Thread bankThread=new Thread(bank);
```

1.  将初始余额写入控制台。

```java
    System.out.printf("Account : Initial Balance: %f\n",account.getBalance());
Start the threads.
    companyThread.start();
    bankThread.start();
```

1.  使用`join()`方法等待两个线程的完成，并在控制台中打印出账户的最终余额。

```java
    try {
      companyThread.join();
      bankThread.join();
      System.out.printf("Account : Final Balance: %f\n",account.getBalance());
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
```

## 它是如何工作的...

在这个示例中，您已经开发了一个应用程序，该应用程序增加和减少了模拟银行账户余额的类的余额。该程序对`addAmount()`方法进行了`100`次调用，每次调用都会将余额增加`1000`，并对`subtractAmount()`方法进行了`100`次调用，每次调用都会将余额减少`1000`。您应该期望最终余额和初始余额相等。

您已经尝试使用一个名为`tmp`的变量来存储账户余额的值，因此您读取了账户余额，增加了临时变量的值，然后再次设置了账户余额的值。此外，您还使用了`Thread`类的`sleep()`方法引入了一点延迟，以便执行该方法的线程休眠 10 毫秒，因此如果另一个线程执行该方法，它可能会修改账户余额，从而引发错误。正是`synchronized`关键字机制避免了这些错误。

如果您想看到共享数据并发访问的问题，请删除`addAmount()`和`subtractAmount()`方法的`synchronized`关键字并运行程序。没有`synchronized`关键字，当一个线程在读取账户余额的值后休眠时，另一个方法将读取账户余额，因此两个方法都将修改相同的余额，其中一个操作不会反映在最终结果中。

正如您在下面的屏幕截图中所看到的，您可能会得到不一致的结果：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-cncr-cb/img/7881_02_01.jpg)

如果您经常运行程序，您将获得不同的结果。线程的执行顺序不受 JVM 保证。因此，每次执行它们时，线程都将以不同的顺序读取和修改账户的余额，因此最终结果将不同。

现在，按照之前学到的方法添加`synchronize`关键字，并再次运行程序。如下截图所示，现在您可以获得预期的结果。如果经常运行程序，您将获得相同的结果。请参考以下截图：

![工作原理...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-cncr-cb/img/7881_02_02.jpg)

使用`synchronized`关键字，我们可以保证并发应用程序中对共享数据的正确访问。

正如我们在本节介绍中提到的，只有一个线程可以访问使用`synchronized`关键字声明的对象的方法。如果一个线程（A）正在执行一个`synchronized`方法，另一个线程（B）想要执行同一对象的其他`synchronized`方法，它将被阻塞，直到线程（A）结束。但是如果 threadB 可以访问同一类的不同对象，则它们都不会被阻塞。

## 还有更多...

`synchronized`关键字会降低应用程序的性能，因此您只能在并发环境中修改共享数据的方法上使用它。如果有多个线程调用`synchronized`方法，只有一个线程会一次执行它们，而其他线程将等待。如果操作不使用`synchronized`关键字，则所有线程可以同时执行操作，从而减少总执行时间。如果您知道某个方法不会被多个线程调用，请不要使用`synchronized`关键字。

您可以使用带有`synchronized`方法的递归调用。由于线程可以访问对象的`synchronized`方法，因此可以调用该对象的其他`synchronized`方法，包括正在执行的方法。它不必再次访问`synchronized`方法。

我们可以使用`synchronized`关键字来保护对一段代码的访问，而不是整个方法。我们应该以这种方式使用`synchronized`关键字来保护对共享数据的访问，将其余操作排除在此块之外，从而获得更好的应用性能。目标是使关键部分（一次只能由一个线程访问的代码块）尽可能短。我们已经使用`synchronized`关键字来保护对更新建筑物中人数的指令的访问，排除了不使用共享数据的此块的长操作。当您以这种方式使用`synchronized`关键字时，必须将对象引用作为参数传递。只有一个线程可以访问该对象的`synchronized`代码（块或方法）。通常，我们会使用`this`关键字来引用执行方法的对象。

```java
    synchronized (this) {
      // Java code
    }
```

# 安排同步类中的独立属性

当您使用`synchronized`关键字来保护一段代码时，您必须将一个对象引用作为参数传递。通常，您会使用`this`关键字来引用执行方法的对象，但您也可以使用其他对象引用。通常，这些对象将专门为此目的创建。例如，如果一个类中有两个独立的属性被多个线程共享，您必须同步对每个变量的访问，但如果一个线程同时访问其中一个属性，另一个线程访问另一个属性，则不会有问题。

在本节中，您将学习如何通过一个示例来解决这种情况的编程，该示例模拟了一个具有两个屏幕和两个售票处的电影院。当售票处出售票时，它们是为两个电影院中的一个而不是两个，因此每个电影院中的空座位数是独立的属性。

## 准备工作

本节示例已使用 Eclipse IDE 实现。如果您使用 Eclipse 或其他 IDE（如 NetBeans），请打开它并创建一个新的 Java 项目。

## 如何做...

按照以下步骤实现示例：

1.  创建一个名为`Cinema`的类，并向其添加两个名为`vacanciesCinema1`和`vacanciesCinema2`的`long`属性。

```java
public class Cinema {

  private long vacanciesCinema1;
  private long vacanciesCinema2;
```

1.  在`Cinema`类中添加两个额外的`Object`属性，命名为`controlCinema1`和`controlCinema2`。

```java
  private final Object controlCinema1, controlCinema2;
```

1.  实现`Cinema`类的构造函数，初始化类的所有属性。

```java
  public Cinema(){
    controlCinema1=new Object();
    controlCinema2=new Object();
    vacanciesCinema1=20;
    vacanciesCinema2=20;
  }
```

1.  实现`sellTickets1()`方法，当第一个电影院的一些票被售出时调用。它使用`controlCinema1`对象来控制对`同步`代码块的访问。

```java
  public boolean sellTickets1 (int number) {
    synchronized (controlCinema1) {
      if (number<vacanciesCinema1) {
        vacanciesCinema1-=number;
        return true;
      } else {
        return false;
      }
    }
  }
```

1.  实现`sellTickets2()`方法，当第二个电影院的一些票被售出时调用。它使用`controlCinema2`对象来控制对`同步`代码块的访问。

```java
  public boolean sellTickets2 (int number){
    synchronized (controlCinema2) {
      if (number<vacanciesCinema2) {
        vacanciesCinema2-=number;
        return true;
      } else {
        return false;
      }
    }
  }
```

1.  实现`returnTickets1()`方法，当第一个电影院的一些票被退回时调用。它使用`controlCinema1`对象来控制对`同步`代码块的访问。

```java
  public boolean returnTickets1 (int number) {
    synchronized (controlCinema1) {
      vacanciesCinema1+=number;
      return true;
    }
  }
```

1.  实现`returnTickets2()`方法，当第二个电影院的一些票被退回时调用。它使用`controlCinema2`对象来控制对`同步`代码块的访问。

```java
  public boolean returnTickets2 (int number) {
    synchronized (controlCinema2) {
      vacanciesCinema2+=number;
      return true;
    }
  }
```

1.  实现另外两个方法，返回每个电影院的空位数。

```java
  public long getVacanciesCinema1() {
    return vacanciesCinema1;
  }

  public long getVacanciesCinema2() {
    return vacanciesCinema2;
  }
```

1.  实现`TicketOffice1`类，并指定它实现`Runnable`接口。

```java
public class TicketOffice1 implements Runnable {
```

1.  声明一个`Cinema`对象，并实现该类的构造函数来初始化该对象。

```java
  private Cinema cinema;

  public TicketOffice1 (Cinema cinema) {
    this.cinema=cinema;
  }
```

1.  实现`run()`方法，模拟对两个电影院的一些操作。

```java
  @Override
   public void run() {
    cinema.sellTickets1(3);
    cinema.sellTickets1(2);
    cinema.sellTickets2(2);
    cinema.returnTickets1(3);
    cinema.sellTickets1(5);
    cinema.sellTickets2(2);
    cinema.sellTickets2(2);
    cinema.sellTickets2(2);
  }
```

1.  实现`TicketOffice2`类，并指定它实现`Runnable`接口。

```java
public class TicketOffice2 implements Runnable {
```

1.  声明一个`Cinema`对象，并实现该类的构造函数来初始化该对象。

```java
  private Cinema cinema;

  public TicketOffice2(Cinema cinema){
    this.cinema=cinema;
  }
```

1.  实现`run()`方法，模拟对两个电影院的一些操作。

```java
  @Override
  public void run() {
    cinema.sellTickets2(2);
    cinema.sellTickets2(4);
    cinema.sellTickets1(2);
    cinema.sellTickets1(1);
    cinema.returnTickets2(2);
    cinema.sellTickets1(3);
    cinema.sellTickets2(2);
    cinema.sellTickets1(2);
  }
```

1.  通过创建一个名为`Main`的类并向其中添加`main()`方法来实现示例的主类。

```java
public class Main {

  public static void main(String[] args) {
```

1.  声明并创建一个`Cinema`对象。

```java
    Cinema cinema=new Cinema();
```

1.  创建一个`TicketOffice1`对象和`Thread`来执行它。

```java
    TicketOffice1 ticketOffice1=new TicketOffice1(cinema);
    Thread thread1=new Thread(ticketOffice1,"TicketOffice1");
```

1.  创建一个`TicketOffice2`对象和`Thread`来执行它。

```java
    TicketOffice2 ticketOffice2=new TicketOffice2(cinema);
    Thread thread2=new Thread(ticketOffice2,"TicketOffice2");
```

1.  启动两个线程。

```java
    thread1.start();
    thread2.start();
```

1.  等待线程完成。

```java
    try {
      thread1.join();
      thread2.join();
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
```

1.  将两个电影院的空位数写入控制台。

```java
    System.out.printf("Room 1 Vacancies: %d\n",cinema.getVacanciesCinema1());
    System.out.printf("Room 2 Vacancies: %d\n",cinema.getVacanciesCinema2());
```

## 它是如何工作的...

当使用`同步`关键字保护一段代码时，使用一个对象作为参数。JVM 保证只有一个线程可以访问使用该对象保护的所有代码块（请注意，我们总是谈论对象，而不是类）。

### 注意

在这个示例中，我们有一个对象来控制对`vacanciesCinema1`属性的访问，因此每次只有一个线程可以修改这个属性，另一个对象控制对`vacanciesCinema2`属性的访问，因此每次只有一个线程可以修改这个属性。但可能会有两个线程同时运行，一个修改`vacancesCinema1`属性，另一个修改`vacanciesCinema2`属性。

当运行此示例时，您可以看到最终结果始终是每个电影院预期的空位数。在下面的屏幕截图中，您可以看到应用程序执行的结果：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-cncr-cb/img/7881_02_03.jpg)

## 还有更多...

`同步`关键字还有其他重要的用途。请参阅*另请参阅*部分，了解其他解释此关键字用法的示例。

## 另请参阅

+   在第二章的*基本线程同步*中的*在同步代码中使用条件*示例中

# 在同步代码中使用条件

并发编程中的一个经典问题是**生产者-消费者**问题。我们有一个数据缓冲区，一个或多个生产者将数据保存在缓冲区中，一个或多个消费者从缓冲区中取数据。

由于缓冲区是共享数据结构，我们必须使用同步机制来控制对它的访问，比如`同步`关键字，但我们有更多的限制。如果缓冲区已满，生产者就不能将数据保存在缓冲区中，如果缓冲区为空，消费者就不能从缓冲区中取数据。

对于这种情况，Java 提供了在`Object`类中实现的`wait()`、`notify()`和`notifyAll()`方法。线程可以在`同步`代码块中调用`wait()`方法。如果它在`同步`代码块之外调用`wait()`方法，JVM 会抛出`IllegalMonitorStateException`异常。当线程调用`wait()`方法时，JVM 会让线程进入睡眠状态，并释放控制`同步`代码块的对象，允许其他线程执行由该对象保护的其他`同步`代码块。要唤醒线程，必须在由相同对象保护的代码块中调用`notify()`或`notifyAll()`方法。

在这个示例中，您将学习如何使用`同步`关键字和`wait()`、`notify()`和`notifyAll()`方法来实现生产者-消费者问题。

## 准备工作

这个示例的实现使用了 Eclipse IDE。如果您使用 Eclipse 或其他 IDE，比如 NetBeans，打开它并创建一个新的 Java 项目。

## 如何做...

按照以下步骤实现示例：

1.  创建一个名为`EventStorage`的类。它有两个属性：一个名为`maxSize`的`int`属性和一个名为`storage`的`LinkedList<Date>`属性。

```java
public class EventStorage {

  private int maxSize;
  private List<Date> storage;
```

1.  实现初始化类属性的类构造函数。

```java
  public EventStorage(){
    maxSize=10;
    storage=new LinkedList<>();
  }
```

1.  实现`同步`方法`set()`以将事件存储在存储中。首先，检查存储是否已满。如果满了，调用`wait()`方法直到存储有空余空间。在方法结束时，调用`notifyAll()`方法唤醒所有在`wait()`方法中睡眠的线程。

```java
  public synchronized void set(){
      while (storage.size()==maxSize){
        try {
          wait();
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
      }
      storage.offer(new Date());
      System.out.printf("Set: %d",storage.size());
      notifyAll();
  }
```

1.  实现`同步`方法`get()`以获取存储的事件。首先，检查存储是否有事件。如果没有事件，调用`wait()`方法，直到存储有事件为止。在方法结束时，调用`notifyAll()`方法唤醒所有在`wait()`方法中睡眠的线程。

```java
  public synchronized void get(){
      while (storage.size()==0){
        try {
          wait();
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
      }
       System.out.printf("Get: %d: %s",storage.size(),((LinkedList<?>)storage).poll());
      notifyAll();
  }
```

1.  创建一个名为`Producer`的类，并指定它实现`Runnable`接口。它将实现示例的生产者。

```java
public class Producer implements Runnable {
```

1.  声明一个`EventStore`对象并实现初始化该对象的类构造函数。

```java
  private EventStorage storage;

  public Producer(EventStorage storage){
    this.storage=storage;
  }
```

1.  实现调用`EventStorage`对象的`set()`方法`100`次的`run()`方法。

```java
   @Override
  public void run() {
    for (int i=0; i<100; i++){
      storage.set();
    }
  }
```

1.  创建一个名为`Consumer`的类，并指定它实现`Runnable`接口。它将实现示例的消费者。

```java
public class Consumer implements Runnable {
```

1.  声明一个`EventStorage`对象并实现初始化该对象的类构造函数。

```java
  private EventStorage storage;

  public Consumer(EventStorage storage){
    this.storage=storage;
  }
```

1.  实现`run()`方法。它调用`EventStorage`对象的`get()`方法`100`次。

```java
  @Override
   public void run() {
    for (int i=0; i<100; i++){
      storage.get();
    }
  }
```

1.  通过实现一个名为`Main`的类并添加`main()`方法来创建示例的主类。

```java
public class Main {

  public static void main(String[] args) {
```

1.  创建一个`EventStorage`对象。

```java
    EventStorage storage=new EventStorage();
```

1.  创建一个`Producer`对象和一个`Thread`来运行它。

```java
    Producer producer=new Producer(storage);
    Thread thread1=new Thread(producer);
```

1.  创建一个`Consumer`对象和一个`Thread`来运行它。

```java
    Consumer consumer=new Consumer(storage);
    Thread thread2=new Thread(consumer);
```

1.  启动两个线程。

```java
    thread2.start();
    thread1.start();
```

## 它是如何工作的...

这个例子的关键是`EventStorage`类的`set()`和`get()`方法。首先，`set()`方法检查存储属性中是否有空闲空间。如果满了，调用`wait()`方法等待空闲空间。当其他线程调用`notifyAll()`方法时，线程会被唤醒并再次检查条件。`notifyAll()`方法不能保证线程会被唤醒。这个过程会重复，直到存储中有空闲空间并且可以生成新的事件并存储它。

`get()`方法的行为类似。首先，它检查存储中是否有事件。如果`EventStorage`类为空，调用`wait()`方法等待事件。当其他线程调用`notifyAll()`方法时，线程会被唤醒并再次检查条件，直到存储中有事件为止。

### 注意

您必须不断检查条件，并在`while`循环中调用`wait()`方法。直到条件为`true`为止，您才能继续。

如果您运行此示例，您将看到生产者和消费者如何设置和获取事件，但存储中从未有超过 10 个事件。

## 还有更多...

`synchronized`关键字还有其他重要的用途。请参阅*另请参阅*部分，了解解释此关键字用法的其他配方。

## 另请参阅

+   第二章中的*在同步类中排列独立属性*配方，*基本线程同步*

# 使用锁同步代码块

Java 提供了另一种用于同步代码块的机制。这是一种比`synchronized`关键字更强大和灵活的机制。它基于`Lock`接口和实现它的类（如`ReentrantLock`）。这种机制具有一些优势，如下所示：

+   它允许以更灵活的方式构造同步块。使用`synchronized`关键字，您必须以结构化的方式获取和释放同步代码块的控制权。`Lock`接口允许您获得更复杂的结构来实现您的临界区。

+   `Lock`接口提供了比`synchronized`关键字更多的功能。其中一个新功能是`tryLock()`方法。此方法尝试获取锁的控制权，如果无法获取（因为它被其他线程使用），则返回该锁。使用`synchronized`关键字时，当线程（A）尝试执行同步代码块时，如果有另一个线程（B）正在执行它，线程（A）将被挂起，直到线程（B）完成同步块的执行。使用锁，您可以执行`tryLock()`方法。此方法返回一个`Boolean`值，指示是否有另一个线程运行由此锁保护的代码。

+   `Lock`接口允许对读和写操作进行分离，具有多个读取者和仅一个修改者。

+   `Lock`接口的性能比`synchronized`关键字更好。

在这个配方中，您将学习如何使用锁来同步代码块，并使用`Lock`接口和实现它的`ReentrantLock`类创建临界区，实现一个模拟打印队列的程序。

## 准备就绪...

这个配方的示例是使用 Eclipse IDE 实现的。如果您使用 Eclipse 或其他 IDE，如 NetBeans，请打开它并创建一个新的 Java 项目。

## 如何做...

按照以下步骤实现示例：

1.  创建一个名为`PrintQueue`的类，它将实现打印队列。

```java
public class PrintQueue {
```

1.  声明一个`Lock`对象，并使用`ReentrantLock`类的新对象对其进行初始化。

```java
  private final Lock queueLock=new ReentrantLock();
```

1.  实现`printJob()`方法。它将接收`Object`作为参数，并不会返回任何值。

```java
  public void printJob(Object document){
```

1.  在`printJob()`方法内部，通过调用`lock()`方法获取`Lock`对象的控制权。

```java
    queueLock.lock();
```

1.  然后，包括以下代码来模拟打印文档：

```java
    try {
      Long duration=(long)(Math.random()*10000);
      System.out.println(Thread.currentThread().getName()+ ": PrintQueue: Printing a Job during "+(duration/1000)+ 
" seconds");
      Thread.sleep(duration);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
```

1.  最后，使用`unlock()`方法释放`Lock`对象的控制权。

```java
finally {
      queueLock.unlock();
    }    
```

1.  创建一个名为`Job`的类，并指定它实现`Runnable`接口。

```java
public class Job implements Runnable {
```

1.  声明一个`PrintQueue`类的对象，并实现初始化该对象的类的构造函数。

```java
  private PrintQueue printQueue;

  public Job(PrintQueue printQueue){
    this.printQueue=printQueue;
  }
```

1.  实现`run()`方法。它使用`PrintQueue`对象发送打印作业。

```java
  @Override
  public void run() {
    System.out.printf("%s: Going to print a document\n", Thread.currentThread().getName());
    printQueue.printJob(new Object());
    System.out.printf("%s: The document has been printed\n", Thread.currentThread().getName());    
  }
```

1.  通过实现一个名为`Main`的类并向其中添加`main()`方法，创建应用程序的主类。

```java
public class Main {

  public static void main (String args[]){
```

1.  创建一个共享的`PrintQueue`对象。

```java
    PrintQueue printQueue=new PrintQueue();
```

1.  创建 10 个`Job`对象和 10 个线程来运行它们。

```java
    Thread thread[]=new Thread[10];
    for (int i=0; i<10; i++){
      thread[i]=new Thread(new Job(printQueue),"Thread "+ i);
    }
```

1.  启动 10 个线程。

```java
    for (int i=0; i<10; i++){
      thread[i].start();
    }
```

## 它是如何工作的...

在下面的屏幕截图中，您可以看到一个执行的部分输出，例如：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-cncr-cb/img/7881_02_04.jpg)

示例的关键在于`PrintQueue`类的`printJob()`方法。当我们想要使用锁实现临界区并确保只有一个执行线程运行代码块时，我们必须创建一个`ReentrantLock`对象。在临界区的开始，我们必须使用`lock()`方法获取锁的控制权。当一个线程（A）调用此方法时，如果没有其他线程控制着锁，该方法将给予线程（A）锁的控制权，并立即返回以允许该线程执行临界区。否则，如果有另一个线程（B）执行由此锁控制的临界区，`lock()`方法将使线程（A）进入休眠状态，直到线程（B）完成临界区的执行。

在临界区的结束，我们必须使用`unlock()`方法释放锁的控制权，并允许其他线程运行此临界区。如果在临界区结束时不调用`unlock()`方法，那些正在等待该块的其他线程将永远等待，导致死锁情况。如果在临界区中使用 try-catch 块，请不要忘记将包含`unlock()`方法的语句放在`finally`部分中。

## 还有更多...

`Lock`接口（以及`ReentrantLock`类）包括另一个方法来获取锁的控制权。这就是`tryLock()`方法。与`lock()`方法最大的区别在于，如果使用它的线程无法获得`Lock`接口的控制权，该方法将立即返回，而不会使线程进入休眠状态。该方法返回一个`boolean`值，如果线程获得了锁的控制权，则返回`true`，否则返回`false`。

### 注意

请注意，程序员有责任考虑此方法的结果并相应地采取行动。如果该方法返回`false`值，则预期您的程序不会执行临界区。如果执行了，您的应用程序可能会产生错误的结果。

`ReentrantLock`类还允许使用递归调用。当一个线程控制着一个锁并进行递归调用时，它将继续控制着锁，因此调用`lock()`方法将立即返回，线程将继续执行递归调用。此外，我们还可以调用其他方法。

### 更多信息

您必须非常小心地使用`Locks`以避免**死锁**。当两个或更多线程被阻塞等待永远不会被解锁的锁时，就会发生这种情况。例如，一个线程（A）锁定了一个锁（X），而另一个线程（B）锁定了一个锁（Y）。如果现在，线程（A）尝试锁定锁（Y），而线程（B）同时尝试锁定锁（X），那么两个线程将无限期地被阻塞，因为它们正在等待永远不会被释放的锁。请注意，问题出现在于两个线程尝试以相反的顺序获取锁。附录*并发编程设计*解释了一些设计并发应用程序并避免这些死锁问题的好建议。

## 另请参阅

+   在第二章的*基本线程同步*中的*同步方法*配方

+   在第二章的*基本线程同步*中的*在锁中使用多个条件*配方中

+   在第八章的*测试并发应用*中的*监视锁*接口配方

# 使用读/写锁同步数据访问

锁提供的最重要的改进之一是`ReadWriteLock`接口和`ReentrantReadWriteLock`类，它是唯一实现它的类。这个类有两个锁，一个用于读操作，一个用于写操作。可以有多个线程同时使用读操作，但只能有一个线程使用写操作。当一个线程执行写操作时，不能有任何线程执行读操作。

在本示例中，您将学习如何使用`ReadWriteLock`接口来实现一个程序，该程序使用它来控制对存储两种产品价格的对象的访问。

## 准备就绪...

您应该阅读*Synchronizing a block of code with a Lock*一节，以更好地理解本节。

## 如何做...

按照以下步骤实现示例：

1.  创建一个名为`PricesInfo`的类，用于存储两种产品的价格信息。

```java
public class PricesInfo {
```

1.  声明两个名为`price1`和`price2`的`double`属性。

```java
  private double price1;
  private double price2;
```

1.  声明一个名为`lock`的`ReadWriteLock`对象。

```java
  private ReadWriteLock lock;
```

1.  实现初始化三个属性的类的构造函数。对于`lock`属性，我们创建一个新的`ReentrantReadWriteLock`对象。

```java
  public PricesInfo(){
    price1=1.0;
    price2=2.0;
    lock=new ReentrantReadWriteLock();
  }
```

1.  实现`getPrice1()`方法，该方法返回`price1`属性的值。它使用读锁来控制对该属性值的访问。

```java
  public double getPrice1() {
    lock.readLock().lock();
    double value=price1;
    lock.readLock().unlock();
    return value;
  }
```

1.  实现`getPrice2()`方法，该方法返回`price2`属性的值。它使用读锁来控制对该属性值的访问。

```java
  public double getPrice2() {
    lock.readLock().lock();
    double value=price2;
    lock.readLock().unlock();
    return value;
  }
```

1.  实现`setPrices()`方法，用于设置两个属性的值。它使用写锁来控制对它们的访问。

```java
  public void setPrices(double price1, double price2) {
    lock.writeLock().lock();
    this.price1=price1;
    this.price2=price2;
    lock.writeLock().unlock();
  }
```

1.  创建一个名为`Reader`的类，并指定它实现`Runnable`接口。该类实现了`PricesInfo`类属性值的读取器。

```java
public class Reader implements Runnable {
```

1.  声明一个名为`PricesInfo`的对象，并实现初始化该对象的类的构造函数。

```java
  private PricesInfo pricesInfo;

  public Reader (PricesInfo pricesInfo){
    this.pricesInfo=pricesInfo;
  }
```

1.  为这个类实现`run()`方法。它读取两个价格的值 10 次。

```java
  @Override
  public void run() {
    for (int i=0; i<10; i++){
      System.out.printf("%s: Price 1: %f\n", Thread.currentThread().getName(),pricesInfo.getPrice1());
      System.out.printf("%s: Price 2: %f\n", Thread.currentThread().getName(),pricesInfo.getPrice2());
    }
  }
```

1.  创建一个名为`Writer`的类，并指定它实现`Runnable`接口。该类实现了`PricesInfo`类属性值的修改器。

```java
public class Writer implements Runnable {
```

1.  声明一个名为`PricesInfo`的对象，并实现初始化该对象的类的构造函数。

```java
  private PricesInfo pricesInfo;

  public Writer(PricesInfo pricesInfo){
    this.pricesInfo=pricesInfo;
  }
```

1.  实现`run()`方法。它在修改两个价格的值之间休眠两秒，共修改三次。

```java
  @Override
  public void run() {
    for (int i=0; i<3; i++) {
      System.out.printf("Writer: Attempt to modify the prices.\n");
      pricesInfo.setPrices(Math.random()*10, Math.random()*8);
      System.out.printf("Writer: Prices have been modified.\n");
      try {
        Thread.sleep(2);
      } catch (InterruptedException e) {
        e.printStackTrace();
      }
    }
  }  
```

1.  通过创建一个名为`Main`的类并向其中添加`main()`方法来实现示例的主类。

```java
public class Main {

  public static void main(String[] args) {
```

1.  创建一个`PricesInfo`对象。

```java
    PricesInfo pricesInfo=new PricesInfo();
```

1.  创建五个`Reader`对象和五个`Thread`来执行它们。

```java
    Reader readers[]=new Reader[5];
    Thread threadsReader[]=new Thread[5];

    for (int i=0; i<5; i++){
      readers[i]=new Reader(pricesInfo);
      threadsReader[i]=new Thread(readers[i]);
    }
```

1.  创建一个`Writer`对象和一个`Thread`来执行它。

```java
    Writer writer=new Writer(pricesInfo);
      Thread  threadWriter=new Thread(writer);
```

1.  启动线程。

```java
    for (int i=0; i<5; i++){
      threadsReader[i].start();
    }
    threadWriter.start();
```

## 它是如何工作的...

在下面的截图中，您可以看到此示例的一个执行输出的一部分：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-cncr-cb/img/7881_02_05.jpg)

正如我们之前提到的，`ReentrantReadWriteLock`类有两个锁，一个用于读操作，一个用于写操作。在读操作中使用的锁是通过`ReadWriteLock`接口中声明的`readLock()`方法获得的。这个锁是一个实现了`Lock`接口的对象，所以我们可以使用`lock()`、`unlock()`和`tryLock()`方法。在写操作中使用的锁是通过`ReadWriteLock`接口中声明的`writeLock()`方法获得的。这个锁是一个实现了`Lock`接口的对象，所以我们可以使用`lock()`、`unlock()`和`tryLock()`方法。程序员有责任确保正确使用这些锁，使用它们的目的与它们设计的目的相同。当您获得`Lock`接口的读锁时，您不能修改变量的值。否则，您可能会遇到数据不一致的错误。

## 另请参阅

+   在第二章的*Synchronizing a block of code with a Lock*一节中，*基本线程同步*

+   在第八章的*监视锁接口*食谱中，*测试并发应用程序*

# 修改锁的公平性

`ReentrantLock`和`ReentrantReadWriteLock`类的构造函数接受一个名为`fair`的`boolean`参数，允许您控制这两个类的行为。`false`值是默认值，称为**非公平模式**。在此模式下，当有一些线程等待锁（`ReentrantLock`或`ReentrantReadWriteLock`）并且锁必须选择其中一个来访问临界区时，它会选择一个而没有任何标准。`true`值称为**公平模式**。在此模式下，当有一些线程等待锁（`ReentrantLock`或`ReentrantReadWriteLock`）并且锁必须选择一个来访问临界区时，它会选择等待时间最长的线程。请注意，前面解释的行为仅用于`lock()`和`unlock()`方法。由于`tryLock()`方法在使用`Lock`接口时不会使线程进入睡眠状态，因此公平属性不会影响其功能。

在本食谱中，我们将修改在*使用锁同步代码块*食谱中实现的示例，以使用此属性并查看公平和非公平模式之间的区别。

## 做好准备...

我们将修改在*使用锁同步代码块*食谱中实现的示例，因此请阅读该食谱以实现此示例。

## 如何做...

按照以下步骤实现示例：

1.  实现在*使用锁同步代码块*食谱中解释的示例。

1.  在`PrintQueue`类中，修改`Lock`对象的构造。新的指令如下所示：

```java
  private Lock queueLock=new ReentrantLock(true);
```

1.  修改`printJob()`方法。将打印模拟分为两个代码块，在它们之间释放锁。

```java
  public void printJob(Object document){
    queueLock.lock();
    try {
      Long duration=(long)(Math.random()*10000);
      System.out.println(Thread.currentThread().getName()+": PrintQueue: Printing a Job during "+(duration/1000)+" seconds");
      Thread.sleep(duration);
    } catch (InterruptedException e) {
      e.printStackTrace();
    } finally {
       queueLock.unlock();
    }
    queueLock.lock();
    try {
      Long duration=(long)(Math.random()*10000);
      System.out.println(Thread.currentThread().getName()+": PrintQueue: Printing a Job during "+(duration/1000)+" seconds");
      Thread.sleep(duration);
    } catch (InterruptedException e) {
      e.printStackTrace();
    } finally {
          queueLock.unlock();
       } 
  }
```

1.  在`Main`类中修改启动线程的代码块。新的代码块如下所示：

```java
    for (int i=0; i<10; i++){
      thread[i].start();
      try {
        Thread.sleep(100);
      } catch (InterruptedException e) {
        e.printStackTrace();
      }
    }
```

## 它是如何工作的...

在下面的屏幕截图中，您可以看到此示例的一次执行输出的一部分：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-cncr-cb/img/7881_02_06.jpg)

所有线程的创建间隔为 0.1 秒。请求控制锁的第一个线程是**线程 0**，然后是**线程 1**，依此类推。当**线程 0**运行由锁保护的第一个代码块时，我们有九个线程等待执行该代码块。当**线程 0**释放锁时，立即再次请求锁，因此我们有 10 个线程尝试获取锁。由于启用了公平模式，`Lock`接口将选择**线程 1**，因此它是等待时间最长的线程。然后选择**线程 2**，然后是**线程 3**，依此类推。直到所有线程都通过了由锁保护的第一个代码块，它们才会执行由锁保护的第二个代码块。

一旦所有线程执行了由锁保护的第一个代码块，再次轮到**线程 0**。然后是**线程 1**，依此类推。

要查看与非公平模式的区别，请更改传递给锁构造函数的参数并将其设置为`false`值。在下面的屏幕截图中，您可以看到修改后示例的执行结果：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-cncr-cb/img/7881_02_07.jpg)

在这种情况下，线程按照它们被创建的顺序执行，但每个线程都执行两个受保护的代码块。但是，这种行为不能保证，因为如前所述，锁可以选择任何线程来让其访问受保护的代码。在这种情况下，JVM 不能保证线程的执行顺序。

## 还有更多...

读/写锁在其构造函数中也有公平参数。此参数在这种类型的锁中的行为与我们在本食谱介绍中解释的相同。

## 另请参阅

+   在第二章中的*使用锁同步代码块*示例中，*基本线程同步*

+   在第二章中的*使用读/写锁同步数据访问*示例中，*基本线程同步*

+   在第七章中的*实现自定义锁类*示例中，*自定义并发类*

# 在锁中使用多个条件

一个锁可以与一个或多个条件关联。这些条件在`Condition`接口中声明。这些条件的目的是允许线程控制锁，并检查条件是否为`true`，如果为`false`，则暂停，直到另一个线程唤醒它们。`Condition`接口提供了挂起线程和唤醒挂起线程的机制。

并发编程中的一个经典问题是**生产者-消费者**问题。我们有一个数据缓冲区，一个或多个将数据保存在缓冲区中的**生产者**，以及一个或多个从缓冲区中取出数据的**消费者**，正如本章前面所述

在这个示例中，您将学习如何使用锁和条件来实现生产者-消费者问题。

## 准备就绪...

您应该阅读*使用锁同步代码块*示例，以更好地理解这个示例。

## 如何做...

按照以下步骤实现示例：

1.  首先，让我们实现一个类，模拟文本文件。创建一个名为`FileMock`的类，具有两个属性：一个名为`content`的`String`数组和一个名为`index`的`int`。它们将存储文件的内容和将被检索的模拟文件的行。

```java
public class FileMock {

  private String content[];
  private int index;
```

1.  实现类的构造函数，初始化文件内容为随机字符。

```java
  public FileMock(int size, int length){
    content=new String[size];
    for (int i=0; i<size; i++){
      StringBuilder buffer=new StringBuilder(length);
      for (int j=0; j<length; j++){
        int indice=(int)Math.random()*255;
        buffer.append((char)indice);
      }
      content[i]=buffer.toString();
    }
    index=0;
  }
```

1.  实现`hasMoreLines()`方法，如果文件有更多行要处理，则返回`true`，如果已经到达模拟文件的末尾，则返回`false`。

```java
  public boolean hasMoreLines(){
    return index<content.length;
  }
```

1.  实现`getLine()`方法，返回由索引属性确定的行并增加其值。

```java
  public String getLine(){
    if (this.hasMoreLines()) {
      System.out.println("Mock: "+(content.length-index));
      return content[index++];
    } 
    return null;
  }
```

1.  现在，实现一个名为`Buffer`的类，它将实现生产者和消费者共享的缓冲区。

```java
public class Buffer {
```

1.  这个类有六个属性：

+   一个名为`buffer`的`LinkedList<String>`属性，用于存储共享数据

+   定义一个名为`maxSize`的`int`类型，用于存储缓冲区的长度

+   一个名为`lock`的`ReentrantLock`对象，用于控制修改缓冲区的代码块的访问

+   两个名为`lines`和`space`的`Condition`属性

+   一个名为`pendingLines`的`boolean`类型，它将指示缓冲区中是否有行

```java
  private LinkedList<String> buffer;

  private int maxSize;

  private ReentrantLock lock;

  private Condition lines;
  private Condition space;

  private boolean pendingLines;
```

1.  实现类的构造函数。它初始化先前描述的所有属性。

```java
  public Buffer(int maxSize) {
    this.maxSize=maxSize;
    buffer=new LinkedList<>();
    lock=new ReentrantLock();
    lines=lock.newCondition();
    space=lock.newCondition();
    pendingLines=true;
  }
```

1.  实现`insert()`方法。它接收`String`作为参数，并尝试将其存储在缓冲区中。首先，它获取锁的控制权。当它拥有它时，它会检查缓冲区是否有空间。如果缓冲区已满，它会调用`space`条件中的`await()`方法等待空闲空间。当另一个线程调用`space`条件中的`signal()`或`signalAll()`方法时，线程将被唤醒。发生这种情况时，线程将行存储在缓冲区中，并调用`lines`条件上的`signallAll()`方法。正如我们将在下一刻看到的，这个条件将唤醒所有等待缓冲区中行的线程。

```java
  public void insert(String line) {
    lock.lock();
    try {
      while (buffer.size() == maxSize) {
        space.await();
      }
      buffer.offer(line);
      System.out.printf("%s: Inserted Line: %d\n", Thread.currentThread().getName(),buffer.size());
      lines.signalAll();
    } catch (InterruptedException e) {
      e.printStackTrace();
    } finally {
      lock.unlock();
    }
  }
```

1.  实现`get()`方法。它返回缓冲区中存储的第一个字符串。首先，它获取锁的控制权。当它拥有它时，它会检查缓冲区中是否有行。如果缓冲区为空，它会调用`lines`条件中的`await()`方法等待缓冲区中的行。当另一个线程调用`lines`条件中的`signal()`或`signalAll()`方法时，该线程将被唤醒。当发生这种情况时，该方法获取缓冲区中的第一行，调用`space`条件上的`signalAll()`方法，并返回`String`。

```java
  public String get() {
    String line=null;
    lock.lock();    
    try {
      while ((buffer.size() == 0) &&(hasPendingLines())) {
        lines.await();
      }

      if (hasPendingLines()) {
        line = buffer.poll();
        System.out.printf("%s: Line Readed: %d\n",Thread.currentThread().getName(),buffer.size());
        space.signalAll();
      }
    } catch (InterruptedException e) {
      e.printStackTrace();
    } finally {
      lock.unlock();
    }
    return line;
  }
```

1.  实现`setPendingLines()`方法，建立`pendingLines`属性的值。当生产者没有更多行要生产时，将调用它。

```java
  public void setPendingLines(boolean pendingLines) {
    this.pendingLines=pendingLines;
  }
```

1.  实现`hasPendingLines()`方法。如果有更多行要处理，则返回`true`，否则返回`false`。

```java
  public boolean hasPendingLines() {
    return pendingLines || buffer.size()>0;
  }
```

1.  现在轮到生产者了。实现一个名为`Producer`的类，并指定它实现`Runnable`接口。

```java
public class Producer implements Runnable {
```

1.  声明两个属性：`FileMock`类的一个对象和`Buffer`类的另一个对象。

```java
  private FileMock mock;

  private Buffer buffer;
```

1.  实现初始化两个属性的类的构造函数。

```java
  public Producer (FileMock mock, Buffer buffer){
    this.mock=mock;
    this.buffer=buffer;  
  }
```

1.  实现`run()`方法，读取`FileMock`对象中创建的所有行，并使用`insert()`方法将它们存储在缓冲区中。完成后，使用`setPendingLines()`方法通知缓冲区不会再生成更多行。

```java
   @Override
  public void run() {
    buffer.setPendingLines(true);
    while (mock.hasMoreLines()){
      String line=mock.getLine();
      buffer.insert(line);
    }
    buffer.setPendingLines(false);
  }
```

1.  接下来是消费者的轮次。实现一个名为`Consumer`的类，并指定它实现`Runnable`接口。

```java
public class Consumer implements Runnable {
```

1.  声明一个`Buffer`对象并实现初始化它的类的构造函数。

```java
  private Buffer buffer;

  public Consumer (Buffer buffer) {
    this.buffer=buffer;
  }
```

1.  实现`run()`方法。在缓冲区有待处理的行时，它尝试获取并处理其中的一行。

```java
   @Override  
  public void run() {
    while (buffer.hasPendingLines()) {
      String line=buffer.get();
      processLine(line);
    }
  }
```

1.  实现辅助方法`processLine()`。它只休眠 10 毫秒，模拟对行进行某种处理。

```java
  private void processLine(String line) {
    try {
      Random random=new Random();
      Thread.sleep(random.nextInt(100));
    } catch (InterruptedException e) {
      e.printStackTrace();
    }    
  }
```

1.  通过创建一个名为`Main`的类并向其中添加`main()`方法来实现示例的主类。

```java
public class Main {

  public static void main(String[] args) {
```

1.  创建一个`FileMock`对象。

```java
    FileMock mock=new FileMock(100, 10);
```

1.  创建一个`Buffer`对象。

```java
    Buffer buffer=new Buffer(20);
```

1.  创建一个`Producer`对象和一个`Thread`来运行它。

```java
    Producer producer=new Producer(mock, buffer);
    Thread threadProducer=new Thread(producer,"Producer");
```

1.  创建三个`Consumer`对象和三个线程来运行它。

```java
    Consumer consumers[]=new Consumer[3];
    Thread threadConsumers[]=new Thread[3];

    for (int i=0; i<3; i++){
      consumers[i]=new Consumer(buffer); 
      threadConsumers[i]=new Thread(consumers[i],"Consumer "+i);
    }
```

1.  启动生产者和三个消费者。

```java
    threadProducer.start();
    for (int i=0; i<3; i++){
      threadConsumers[i].start();
    }
```

## 它是如何工作的...

所有的`Condition`对象都与一个锁相关联，并且是使用`Lock`接口中声明的`newCondition()`方法创建的。在我们可以对条件进行任何操作之前，必须控制与条件相关联的锁，因此条件的操作必须在以`Lock`对象的`lock()`方法调用开始的代码块中，并以相同`Lock`对象的`unlock()`方法结束。

当一个线程调用条件的`await()`方法时，它会自动释放锁的控制权，以便另一个线程可以获取它并开始执行相同的临界区或由该锁保护的另一个临界区。

### 注意

当一个线程调用条件的`signal()`或`signallAll()`方法时，等待该条件的一个或所有线程被唤醒，但这并不保证使它们休眠的条件现在是`true`，因此必须将`await()`调用放在`while`循环中。在条件为`true`之前，不能离开该循环。条件为`false`时，必须再次调用`await()`。

在使用`await()`和`signal()`时必须小心。如果在条件中调用`await()`方法，但从未在该条件中调用`signal()`方法，线程将永远休眠。

在休眠时，线程可能会被中断，在调用`await()`方法后，因此必须处理`InterruptedException`异常。

## 还有更多...

`Condition`接口有`await()`方法的其他版本，如下所示：

+   `await(long time, TimeUnit unit)`: 线程将休眠直到：

+   它被中断了

+   另一个线程在条件中调用`signal()`或`signalAll()`方法

+   指定的时间已经过去

+   `TimeUnit`类是一个枚举，具有以下常量：`DAYS`、`HOURS`、`MICROSECONDS`、`MILLISECONDS`、`MINUTES`、`NANOSECONDS`和`SECONDS`

+   `awaitUninterruptibly()`: 线程将休眠直到另一个线程调用`signal()`或`signalAll()`方法，这是不可中断的

+   `awaitUntil(Date date)`: 线程将休眠直到：

+   它被中断了

+   另一个线程在条件中调用`signal()`或`signalAll()`方法

+   指定的日期到达

您可以使用条件与读/写锁的`ReadLock`和`WriteLock`锁。

## 另请参阅

+   在《第二章》（ch02.html“第二章基本线程同步”）的*使用锁同步代码块*配方中

+   在《第二章》（ch02.html“第二章基本线程同步”）的*使用读/写锁同步数据访问*配方
