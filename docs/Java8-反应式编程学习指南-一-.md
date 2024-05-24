# Java8 反应式编程学习指南（一）

> 原文：[`zh.annas-archive.org/md5/A4E30A017482EBE61466A691985993DC`](https://zh.annas-archive.org/md5/A4E30A017482EBE61466A691985993DC)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

响应式编程已经存在几十年了。自 Smalltalk 语言年轻时起，就有一些响应式编程的实现。然而，它最近才变得流行，并且现在成为一种趋势。你会问为什么现在？因为它适合编写快速、实时应用程序，当前的技术和 Web 需求如此。

我是在 2008 年参与其中的，当时我所在的团队正在开发一个名为 Sophie 2 的多媒体图书创建器。它必须快速响应，因此我们创建了一个名为 Prolib 的框架，它提供了可以相互依赖的对象属性（换句话说，我们为 Swing 实现了绑定等等）。将模型数据与 GUI 连接起来就像这样自然而然。

当然，这远非 RX 所具有的函数式方法。2010 年，微软发布了 RX，之后 Netflix 将其移植到 Java—RxJava。然而，Netflix 将 RxJava 发布给开源社区，该项目取得了巨大成功。许多其他语言都有其 RX 端口以及许多替代方案。现在，您可以在 Java 后端上使用响应式编程进行编码，并将其连接到 RxJava 的前端。

这本书试图向您解释响应式编程的全部内容以及如何在 RxJava 中使用它。它有许多小例子，并以小步骤解释概念和 API 细节。阅读本书后，您将对 RxJava、函数式编程和响应式范式有所了解。

# 本书涵盖的内容

第一章，响应式编程简介，将向您介绍响应式编程的概念，并告诉您为什么应该了解它。本章包含演示 RxJava 如何融合响应式编程概念的示例。

第二章，使用 Java 8 的函数式构造，将教您如何使用 Java 8 的新 lambda 构造。它将解释一些函数式编程概念，并向您展示如何在响应式程序中与 RxJava 一起使用它们。

第三章，创建和连接 Observables、Observers 和 Subjects，将向您展示 RxJava 库的基本构建模块，称为 Observables。您将学习“热”和“冷”Observables 之间的区别，以及如何使用订阅实例订阅和取消订阅它们。

第四章，转换、过滤和累积您的数据，将引导您了解基本的响应式操作符，您将学习如何使用它们来实现逐步计算。本章将让您了解如何转换 Observables 发出的事件，如何仅筛选出我们需要的数据，以及如何对其进行分组、累积和处理。

第五章，组合器、条件和错误处理，将向您介绍更复杂的响应式操作符，这将使您能够掌握可观察链。您将了解组合和条件操作符以及 Observables 如何相互交互。本章演示了不同的错误处理方法。

第六章，使用调度程序进行并发和并行处理，将指导您通过 RxJava 编写并发和并行程序的过程。这将通过 RxJava 调度程序来实现。将介绍调度程序的类型，您将了解何时以及为什么要使用每种调度程序。本章将向您介绍一种机制，向您展示如何避免和应用背压。

第七章，《测试您的 RxJava 应用程序》，将向您展示如何对 RxJava 应用程序进行单元测试。

第八章，《资源管理和扩展 RxJava》，将教您如何管理 RxJava 应用程序使用的数据源资源。我们将在这里编写自己的 Observable 操作符。

# 您需要为本书做好准备

为了运行示例，您需要：

+   已安装 Java 8，您可以从 Oracle 网站[`www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html`](http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html)下载

+   Gradle 构建项目—2.x，您可以从[`gradle.org/downloads`](https://gradle.org/downloads)下载

+   Eclipse 打开项目。您还需要 Eclipse 的 Gradle 插件，可以从 Eclipse MarketPlace 下载。当然，您也可以使用命令行和 Vim 或任何其他任意文本编辑器查看代码。

# 本书适合对象

如果您是一名懂得如何编写软件并希望学习如何将现有技能应用于响应式编程的 Java 开发人员，那么这本书适合您。

这本书对任何人都有帮助，无论是初学者、高级程序员，甚至是专家。您不需要具有 Java 8 的 lambda 和 stream 或 RxJava 的任何经验。

# 约定

在本书中，您将找到一些区分不同信息类型的文本样式。以下是一些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："我们可以通过使用`include`指令包含其他上下文。"

代码块设置如下：

```java
Observable
  .just('R', 'x', 'J', 'a', 'v', 'a')
  .subscribe(
    System.out::print,
    System.err::println,
    System.out::println
  );
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```java
Observable<Object> obs = Observable
 .interval(40L, TimeUnit.MILLISECONDS)
 .switchMap(v ->
 Observable
 .timer(0L, 10L, TimeUnit.MILLISECONDS)
 .map(u -> "Observable <" + (v + 1) + "> : " + (v + u)))
 );
subscribePrint(obs, "switchMap");

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中："这种类型的接口称为**函数接口**。"

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会以这种方式出现。

# 读者反馈

我们始终欢迎读者的反馈。请告诉我们您对本书的看法—您喜欢或不喜欢的地方。读者的反馈对我们很重要，因为它有助于我们开发出您真正能从中获益的标题。

要向我们发送一般反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在主题中提及书名。

如果您在某个专题上有专业知识，并且有兴趣撰写或为书籍做出贡献，请参阅我们的作者指南[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您是 Packt 书籍的自豪所有者，我们有一些事情可以帮助您充分利用您的购买。

## 下载示例代码

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中为您购买的所有 Packt Publishing 图书下载示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接将文件发送到您的电子邮件。

## 勘误

尽管我们已经尽一切努力确保内容的准确性，但错误是难免的。如果您在我们的书中发现错误——可能是文本或代码中的错误——我们将不胜感激，如果您能向我们报告。通过这样做，您可以帮助其他读者避免挫折，并帮助我们改进本书的后续版本。如果您发现任何勘误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书，点击**勘误提交表**链接，并输入您的勘误详情。一旦您的勘误经过验证，您的提交将被接受，并且勘误将被上传到我们的网站或添加到该书籍的勘误列表中的勘误部分。

要查看先前提交的勘误，请转到[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，并在搜索框中输入书名。所需信息将出现在**勘误**部分下。

## 盗版

互联网上盗版受版权保护的材料是所有媒体的持续问题。在 Packt，我们非常重视版权和许可的保护。如果您在互联网上发现我们作品的任何非法副本，请立即向我们提供位置地址或网站名称，以便我们采取补救措施。

请通过`<copyright@packtpub.com>`与我们联系，并提供涉嫌盗版材料的链接。

我们感谢您帮助保护我们的作者和我们为您提供有价值内容的能力。

## 问题

如果您对本书的任何方面有问题，可以通过`<questions@packtpub.com>`与我们联系，我们将尽力解决问题。


# 第一章：响应式编程简介

如今，“响应式编程”这个术语正处于流行之中。各种编程语言中都出现了库和框架。有关响应式编程的博客文章、文章和演示正在被创建。Facebook、SoundCloud、Microsoft 和 Netflix 等大公司正在支持和使用这个概念。因此，我们作为程序员开始思考。为什么人们对响应式编程如此兴奋？成为响应式意味着什么？它对我们的项目有帮助吗？我们应该学习如何使用它吗？

与此同时，Java 以其多线程、速度、可靠性和良好的可移植性而备受欢迎。它用于构建各种应用程序，从搜索引擎、数据库到在服务器集群上运行的复杂 Web 应用程序。但 Java 也有不好的声誉——仅使用内置工具编写并发和简单应用程序非常困难，而且在 Java 中编程需要编写大量样板代码。此外，如果需要是异步的（例如使用 futures），你很容易陷入“回调地狱”，这实际上对所有编程语言都成立。

换句话说，Java 很强大，你可以用它创建出色的应用程序，但这并不容易。好消息是，有一种方法可以改变这种情况，那就是使用响应式编程风格。

本书将介绍**RxJava**（[`github.com/ReactiveX/RxJava`](https://github.com/ReactiveX/RxJava)），这是响应式编程范式的开源 Java 实现。使用 RxJava 编写代码需要一种不同的思维方式，但它将使您能够使用简单的结构化代码片段创建复杂的逻辑。

在本章中，我们将涵盖：

+   响应式编程是什么

+   学习和使用这种编程风格的原因

+   设置 RxJava 并将其与熟悉的模式和结构进行比较

+   使用 RxJava 的一个简单例子

# 什么是响应式编程？

响应式编程是围绕变化的传播而展开的一种范式。换句话说，如果一个程序将修改其数据的所有变化传播给所有感兴趣的方，那么这个程序就可以被称为**响应式**。

微软 Excel 就是一个简单的例子。如果在单元格 A1 中设置一个数字，在单元格'B1'中设置另一个数字，并将单元格'C1'设置为`SUM(A1, B1)`；每当'A1'或'B1'发生变化时，'C1'将被更新为它们的和。

让我们称之为**响应式求和**。

将简单变量*c*分配为*a*和*b*变量的和与响应式求和方法之间有什么区别？

在普通的 Java 程序中，当我们改变'a'或'b'时，我们必须自己更新'c'。换句话说，由'a'和'b'表示的数据流的变化不会传播到'c'。下面通过源代码进行了说明：

```java
int a = 4;
int b = 5;
int c = a + b;
System.out.println(c); // 9

a = 6;
System.out.println(c);
// 9 again, but if 'c' was tracking the changes of 'a' and 'b',
// it would've been 6 + 5 = 11
```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接将文件发送到您的电子邮件。

这是对“响应式”意味着什么的非常简单的解释。当然，这个想法有各种实现，也有各种问题需要这些实现来解决。

# 为什么我们应该是响应式的？

我们回答这个问题最简单的方法是考虑我们在构建应用程序时的需求。

10-15 年前，网站经过维护或响应时间缓慢是正常的，但今天一切都应该 24/7 在线，并且应该以闪电般的速度响应；如果慢或宕机，用户会选择另一个服务。今天慢意味着无法使用或损坏。我们正在处理更大量的数据，需要快速提供和处理。

HTTP 故障在最近过去并不罕见，但现在，我们必须具有容错能力，并为用户提供可读和合理的消息更新。

过去，我们编写简单的桌面应用程序，但今天我们编写应该快速响应的 Web 应用程序。在大多数情况下，这些应用程序与大量远程服务进行通信。

这些是我们必须满足的新要求，如果我们希望我们的软件具有竞争力。换句话说，我们必须是：

+   模块化/动态：这样，我们将能够拥有 24/7 系统，因为模块可以下线并上线，而不会破坏或停止整个系统。此外，这有助于我们更好地构建随着规模扩大而管理其代码库的应用程序。

+   可扩展性：这样，我们将能够处理大量数据或大量用户请求。

+   容错：这样，系统将对其用户显示稳定。

+   响应性：这意味着快速和可用。

让我们考虑如何实现这一点：

+   如果我们的系统是*事件驱动*，我们可以变得模块化。我们可以将系统分解为多个微服务/组件/模块，它们将使用通知相互通信。这样，我们将对系统的数据流做出反应，这些数据流由通知表示。

+   可扩展意味着对不断增长的数据做出反应，对负载做出反应而不会崩溃。

+   对故障/错误的反应将使系统更具容错能力。

+   响应性意味着及时对用户活动做出反应。

如果应用程序是事件驱动的，它可以分解为多个自包含组件。这有助于我们变得更具可扩展性，因为我们可以随时添加新组件或删除旧组件，而不会停止或破坏系统。如果错误和故障传递到正确的组件，它可以将它们处理为通知，应用程序可以变得更具容错能力或弹性。因此，如果我们构建我们的系统为事件驱动，我们可以更容易地实现可扩展性和故障容忍性，而且可扩展、解耦和防错的应用程序对用户快速响应。

![为什么我们应该是反应式的？](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-rct-prog-java8/img/4305_01_01.jpg)

**Reactive Manifesto**（[`www.reactivemanifesto.org/`](http://www.reactivemanifesto.org/)）是一份文件，定义了我们之前提到的四个反应原则。每个反应系统都应该是消息驱动的（事件驱动）。这样，它可以变得松散耦合，因此可扩展和具有弹性（容错），这意味着它是可靠和响应的（请参见上图）。

请注意，Reactive Manifesto 描述了一个反应式系统，并不同于我们对反应式编程的定义。您可以构建一个消息驱动、具有弹性、可扩展和响应的应用程序，而无需使用反应式库或语言。

应用程序数据的更改可以使用通知进行建模，并且可以传播到正确的处理程序。因此，使用反应式编程编写应用程序是遵守宣言的最简单方法。

# 介绍 RxJava

要编写响应式程序，我们需要一个库或特定的编程语言，因为自己构建这样的东西是相当困难的任务。Java 并不是一个真正的响应式编程语言（它提供了一些工具，比如`java.util.Observable`类，但它们相当有限）。它是一种静态类型的面向对象的语言，我们需要编写大量样板代码来完成简单的事情（例如 POJOs）。但是在 Java 中有一些我们可以使用的响应式库。在这本书中，我们将使用 RxJava（由 Java 开源社区的人员开发，由 Netflix 指导）。

## 下载和设置 RxJava

你可以从 Github（[`github.com/ReactiveX/RxJava`](https://github.com/ReactiveX/RxJava)）下载并构建 RxJava。它不需要任何依赖，并支持 Java 8 的 lambda。它的 Javadoc 和 GitHub 维基页面提供的文档结构良好，是最好的之一。以下是如何查看项目并运行构建：

```java
$ git clone git@github.com:ReactiveX/RxJava.git
$ cd RxJava/
$ ./gradlew build
```

当然，你也可以下载预构建的 JAR。在这本书中，我们将使用 1.0.8 版本。

如果你使用 Maven，你可以将 RxJava 作为依赖项添加到你的`pom.xml`文件中：

```java
<dependency>
  <groupId>io.reactivex</groupId>
  <artifactId>rxjava</artifactId>
  <version>1.0.8</version>
</dependency>
```

或者，对于 Apache Ivy，将这个片段放入你的 Ivy 文件的依赖项中：

```java
<dependency org="io.reactivex" name="rxjava" rev="1.0.8" />
```

如果你使用 Gradle，你可以更新你的`build.gradle`文件的依赖项如下：

```java
dependencies {
  ...
  compile 'io.reactivex:rxjava:1.0.8'
  ...
}
```

### 注意

本书附带的代码示例和程序可以使用 Gradle 构建和测试。它可以从这个 Github 仓库下载：[`github.com/meddle0x53/learning-rxjava`](https://github.com/meddle0x53/learning-rxjava)。

现在，让我们来看看 RxJava 到底是什么。我们将从一些众所周知的东西开始，逐渐深入到这个库的秘密中。

## 比较迭代器模式和 RxJava Observable

作为 Java 程序员，你很可能听说过或使用过“迭代器”模式。这个想法很简单：一个“迭代器”实例用于遍历容器（集合/数据源/生成器），在需要时逐个拉取容器的元素，直到达到容器的末尾。以下是在 Java 中如何使用它的一个小例子：

```java
List<String> list = Arrays.asList("One", "Two", "Three", "Four", "Five"); // (1)

Iterator<String> iterator = list.iterator(); // (2)

while(iterator.hasNext()) { // 3
  // Prints elements (4)
  System.out.println(iterator.next());
}
```

每个`java.util.Collection`对象都是一个`Iterable`实例，这意味着它有`iterator()`方法。这个方法创建一个`Iterator`实例，它的源是集合。让我们看看前面的代码做了什么：

1.  我们创建一个包含五个字符串的新`List`实例。

1.  我们使用`iterator()`方法从这个`List`实例创建一个`Iterator`实例。

1.  `Iterator`接口有两个重要的方法：`hasNext()`和`next()`。`hasNext()`方法用于检查`Iterator`实例是否有更多元素可遍历。在这里，我们还没有开始遍历元素，所以它将返回`True`。当我们遍历这五个字符串时，它将返回`False`，程序将在`while`循环之后继续进行。

1.  前五次调用`Iterator`实例的`next()`方法时，它将按照它们在集合中插入的顺序返回元素。所以字符串将被打印出来。

在这个例子中，我们的程序使用`Iterator`实例从`List`实例中消耗项目。它拉取数据（这里用字符串表示），当前线程会阻塞，直到请求的数据准备好并接收到。所以，例如，如果`Iterator`实例在每次`next()`方法调用时向 web 服务器发送请求，我们程序的主线程将在等待每个响应到达时被阻塞。

RxJava 的构建块是可观察对象。`Observable`类（请注意，这不是 JDK 中附带的`java.util.Observable`类）是`Iterator`类的数学对偶，这基本上意味着它们就像同一枚硬币的两面。它具有产生值的基础集合或计算，可以被消费者消耗。但不同之处在于，消费者不像`Iterator`模式中那样从生产者“拉”这些值。恰恰相反；生产者通过通知将值“推送”给消费者。

这是相同程序的示例，但使用`Observable`实例编写：

```java
List<String> list = Arrays.asList("One", "Two", "Three", "Four", "Five"); // (1)

Observable<String> observable = Observable.from(list); // (2)

observable.subscribe(new Action1<String>() { // (3)
  @Override
  public void call(String element) {
    System.out.println(element); // Prints the element (4)
  }
});
```

以下是代码中发生的情况：

1.  我们以与上一个示例相同的方式创建字符串列表。

1.  然后，我们从列表中创建一个`Observable`实例，使用`from(Iterable<? extends T> iterable)`方法。此方法用于创建`Observable`的实例，它们将所有值同步地从`Iterable`实例（在我们的例子中是列表）逐个发送给它们的订阅者（消费者）。我们将在第三章中看看如何逐个将值发送给订阅者，*创建和连接 Observable、Observer 和 Subject*。

1.  在这里，我们可以订阅`Observable`实例。通过订阅，我们告诉 RxJava 我们对这个`Observable`实例感兴趣，并希望从中接收通知。我们使用实现`Action1`接口的匿名类进行订阅，通过定义一个单一方法`call(T)`。这个方法将由`Observable`实例每次有值准备推送时调用。始终创建新的`Action1`实例可能会显得太啰嗦，但 Java 8 解决了这种冗长。我们将在第二章中了解更多信息，*使用 Java 8 的函数构造*。

1.  因此，源列表中的每个字符串都将通过`call()`方法推送，并将被打印出来。

RxJava 的`Observable`类的实例行为有点像异步迭代器，它们自己通知其订阅者/消费者有下一个值。事实上，`Observable`类在经典的`Observer`模式（在 Java 中实现——参见`java.util.Observable`，参见《设计模式：可复用面向对象软件的元素》）中添加了`Iterable`类型中的两个可用的东西。

+   向消费者发出没有更多数据可用的信号的能力。我们可以附加一个订阅者来监听“`OnCompleted`”通知，而不是调用`hasNext()`方法。

+   信号订阅者发生错误的能力。我们可以将错误侦听器附加到`Observable`实例，而不是尝试捕获错误。

这些侦听器可以使用`subscribe(Action1<? super T>, Action1 <Throwable>, Action0)`方法附加。让我们通过添加错误和完成侦听器来扩展`Observable`实例示例：

```java
List<String> list = Arrays.asList("One", "Two", "Three", "Four", "Five");

Observable<String> observable = Observable.from(list);
observable.subscribe(new Action1<String>() {
  @Override
  public void call(String element) {
    System.out.println(element);
  }
},
new Action1<Throwable>() {
 @Override
 public void call(Throwable t) {
 System.err.println(t); // (1)
 }
},
new Action0() {
 @Override
 public void call() {
 System.out.println("We've finnished!"); // (2)
 }
});
```

新的东西在这里是：

1.  如果在处理元素时出现错误，`Observable`实例将通过此侦听器的`call(Throwable)`方法发送此错误。这类似于`Iterator`实例示例中的 try-catch 块。

1.  当一切都完成时，`Observable`实例将调用此`call()`方法。这类似于使用`hasNext()`方法来查看`Iterable`实例的遍历是否已经完成并打印“We've finished!”。

### 注意

此示例可在 GitHub 上查看，并可在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter01/ObservableVSIterator.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter01/ObservableVSIterator.java)上查看/下载。

我们看到了如何使用`Observable`实例，它们与我们熟悉的`Iterator`实例并没有太大的不同。这些`Observable`实例可以用于构建异步流，并将数据更新推送给它们的订阅者（它们可以有多个订阅者）。这是反应式编程范式的一种实现。数据被传播给所有感兴趣的方，即订阅者。

使用这样的流进行编码是反应式编程的更类似函数式的实现。当然，对此有正式的定义和复杂的术语，但这是最简单的解释。

订阅事件应该是熟悉的；例如，在 GUI 应用程序中点击按钮会触发一个事件，该事件会传播给订阅者—处理程序。但是，使用 RxJava，我们可以从任何地方创建数据流—文件输入、套接字、响应、变量、缓存、用户输入等等。此外，消费者可以被通知流已关闭，或者发生了错误。因此，通过使用这些流，我们的应用程序可以对失败做出反应。

总之，流是一系列持续的消息/事件，按照它们在实时处理中的顺序排序。它可以被看作是随着时间变化的值，这些变化可以被依赖它的订阅者（消费者）观察到。因此，回到 Excel 的例子，我们实际上用"反应式变量"或 RxJava 的`Observable`实例有效地替换了传统变量。

## 实现反应式求和

现在我们熟悉了`Observable`类和如何以反应式方式使用它编码的想法，我们准备实现在本章开头提到的反应式求和。

让我们看看我们的程序必须满足的要求：

+   它将是一个在终端中运行的应用程序。

+   一旦启动，它将一直运行，直到用户输入`exit`。

+   如果用户输入`a:<number>`，*a*收集器将更新为*<number>*。

+   如果用户输入`b:<number>`，*b*收集器将更新为*<number>*。

+   如果用户输入其他内容，将被跳过。

+   当*a*和*b*收集器都有初始值时，它们的和将自动计算并以*a + b = <sum>*的格式打印在标准输出上。在*a*或*b*的每次更改时，和将被更新并打印。

源代码包含了我们将在接下来的四章中详细讨论的功能。

第一段代码代表程序的主体：

```java
ConnectableObservable<String> input = from(System.in); // (1)

Observable<Double> a = varStream("a", input); (2)
Observable<Double> b = varStream("b", input);

ReactiveSum sum = new ReactiveSum(a, b); (3)

input.connect(); (4)
```

这里发生了很多新的事情：

1.  我们必须做的第一件事是创建一个代表标准输入流（`System.in`）的`Observable`实例。因此，我们使用`from(InputStream)`方法（实现将在下一个代码片段中呈现）从`System.in`创建一个`ConnectableObservable`变量。`ConnectableObservable`变量是一个`Observable`实例，只有在调用其`connect()`方法后才开始发出来自其源的事件。在第三章中详细了解它，*创建和连接 Observables、Observers 和 Subjects*。

1.  我们使用`varStream(String, Observable)`方法创建代表`a`和`b`值的两个`Observable`实例，我们将在后面进行详细讨论。这些值的源流是输入流。

1.  我们创建了一个`ReactiveSum`实例，依赖于`a`和`b`的值。

1.  现在，我们可以开始监听输入流了。

这段代码负责在程序中建立依赖关系并启动它。*a*和*b*的值依赖于用户输入，它们的和也依赖于它们。

现在让我们看看`from(InputStream)`方法的实现，它创建了一个带有`java.io.InputStream`源的`Observable`实例：

```java
static ConnectableObservable<String> from(final InputStream stream) {
  return from(new BufferedReader(new InputStreamReader(stream)));// (1)
}

static ConnectableObservable<String> from(final BufferedReader reader) {
  return Observable.create(new OnSubscribe<String>() { // (2)
    @Override
    public void call(Subscriber<? super String> subscriber) {
      if (subscriber.isUnsubscribed()) {  // (3)
        return;
      }
      try {
        String line;
        while(!subscriber.isUnsubscribed() &&
          (line = reader.readLine()) != null) { // (4)
            if (line == null || line.equals("exit")) { // (5)
              break;
            }
            subscriber.onNext(line); // (6)
          }
        }
        catch (IOException e) { // (7)
          subscriber.onError(e);
        }
        if (!subscriber.isUnsubscribed()) // (8)
        subscriber.onCompleted();
      }
    }
  }).publish(); // (9)
}
```

这是一段复杂的代码，让我们一步一步来看：

1.  这个方法的实现将它的`InputStream`参数转换为`BufferedReader`对象，并调用`from(BufferedReader)`方法。我们这样做是因为我们将使用字符串作为数据，并且使用`Reader`实例更容易。

1.  因此，实际的实现在第二个方法中。它返回一个`Observable`实例，使用`Observable.create(OnSubscribe)`方法创建。这个方法是我们在本书中将要经常使用的方法。它用于创建具有自定义行为的`Observable`实例。传递给它的`rx.Observable.OnSubscribe`接口有一个方法，`call(Subscriber)`。这个方法用于实现`Observable`实例的行为，因为传递给它的`Subscriber`实例可以用于向`Observable`实例的订阅者发出消息。订阅者是`Observable`实例的客户端，它消耗它的通知。在第三章中了解更多信息，*创建和连接 Observables、Observers 和 Subjects*。

1.  如果订阅者已经取消订阅了这个`Observable`实例，就不应该做任何事情。

1.  主要逻辑是监听用户输入，同时订阅者已经订阅。用户在终端输入的每一行都被视为一条消息。这是程序的主循环。

1.  如果用户输入单词`exit`并按下*Enter*，主循环将停止。

1.  否则，用户输入的消息将通过`onNext(T)`方法作为通知传递给`Observable`实例的订阅者。这样，我们将一切都传递给感兴趣的各方。他们的工作是过滤和转换原始消息。

1.  如果发生 IO 错误，订阅者将通过`onError(Throwable)`方法收到一个`OnError`通知。

1.  如果程序到达这里（通过跳出主循环），并且订阅者仍然订阅了`Observable`实例，将使用`onCompleted()`方法向订阅者发送一个`OnCompleted`通知。

1.  使用`publish()`方法，我们将新的`Observable`实例转换为`ConnectableObservable`实例。我们必须这样做，否则，对于对这个`Observable`实例的每次订阅，我们的逻辑将从头开始执行。在我们的情况下，我们希望只执行一次，并且所有订阅者都收到相同的通知；这可以通过使用`ConnectableObservable`实例来实现。在第三章中了解更多信息，*创建和连接 Observables、Observers 和 Subjects*。

这说明了将 Java 的 IO 流简化为`Observable`实例的方法。当然，使用这个主循环，程序的主线程将阻塞等待用户输入。可以使用正确的`Scheduler`实例将逻辑移动到另一个线程来防止这种情况发生。我们将在第六章中重新讨论这个话题，*使用调度程序进行并发和并行处理*。

现在，用户在终端输入的每一行都会被这个方法创建的`ConnectableObservable`实例传播为一个通知。现在是时候看看我们如何将代表总和收集器的值`Observable`实例连接到这个输入`Observable`实例了。这是`varStream(String, Observable)`方法的实现，它接受一个值的名称和源`Observable`实例，并返回代表这个值的`Observable`实例：

```java
public static Observable<Double> varStream(final String varName, Observable<String> input) {
  final Pattern pattern = Pattern.compile("\\^s*" + varName + "\\s*[:|=]\\s*(-?\\d+\\.?\\d*)$"); // (1)
  return input
  .map(new Func1<String, Matcher>() {
    public Matcher call(String str) {
      return pattern.matcher(str); // (2)
    }
  })
  .filter(new Func1<Matcher, Boolean>() {
    public Boolean call(Matcher matcher) {
      return matcher.matches() && matcher.group(1) != null; // (3)
    }
  })
  .map(new Func1<Matcher, Double>() {
    public Double call(Matcher matcher) {
      return Double.parseDouble(matcher.group(1)); // (4)
    }
  });
}
```

在这里调用的`map()`和`filter()`方法是 RxJava 提供的流畅 API 的一部分。它们可以在`Observable`实例上调用，创建一个依赖于这些方法的新的`Observable`实例，用于转换或过滤传入的数据。通过正确使用这些方法，您可以通过一系列步骤表达复杂的逻辑，以达到您的目标。在第四章中了解更多信息，*转换、过滤和累积您的数据*。让我们分析一下代码：

1.  我们的变量只对格式为`<var_name>: <value>`或`<var_name> = <value>`的消息感兴趣，因此我们将使用这个正则表达式来过滤和处理这些类型的消息。请记住，我们的输入`Observable`实例会发送用户写的每一行；我们的工作是以正确的方式处理它。

1.  使用我们从输入接收的消息，我们使用前面的正则表达式作为模式创建了一个`Matcher`实例。

1.  我们只通过与正则表达式匹配的数据。其他一切都被丢弃。

1.  这里要设置的值被提取为`Double`数值。

这就是值`a`和`b`如何通过双值流表示，随时间变化。现在我们可以实现它们的总和。我们将其实现为一个实现了`Observer`接口的类，因为我想向您展示订阅`Observable`实例的另一种方式——使用`Observer`接口。以下是代码：

```java
public static final class ReactiveSum implements Observer<Double> { // (1)
  private double sum;
  public ReactiveSum(Observable<Double> a, Observable<Double> b) {
    this.sum = 0;
    Observable.combineLatest(a, b, new Func2<Double, Double, Double>() { // (5)
      public Double call(Double a, Double b) {
        return a + b;
      }
    }).subscribe(this); // (6)
  }
  public void onCompleted() {
    System.out.println("Exiting last sum was : " + this.sum); // (4)
  }
  public void onError(Throwable e) {
    System.err.println("Got an error!"); // (3)
    e.printStackTrace();
  }
  public void onNext(Double sum) {
    this.sum = sum;
    System.out.println("update : a + b = " + sum); // (2)
  }
}
```

这是实际总和的实现，依赖于表示其收集器的两个`Observable`实例：

1.  这是一个`Observer`接口。`Observer`实例可以传递给`Observable`实例的`subscribe(Observer)`方法，并定义了三个方法，这些方法以三种类型的通知命名：`onNext(T)`、`onError(Throwable)`和`onCompleted`。在第三章中了解更多关于这个接口的信息，*创建和连接 Observables、Observers 和 Subjects*。

1.  在我们的`onNext(Double)`方法实现中，我们将总和设置为传入的值，并在标准输出中打印更新。

1.  如果我们遇到错误，我们只是打印它。

1.  当一切都完成时，我们用最终的总和向用户致以问候。

1.  我们使用`combineLatest(Observable, Observable, Func2)`方法实现总和。这个方法创建一个新的`Observable`实例。当传递给 combineLatest 的两个`Observable`实例中的任何一个接收到更新时，新的`Observable`实例将被更新。通过新的`Observable`实例发出的值是由第三个参数计算的——这个函数可以访问两个源序列的最新值。在我们的情况下，我们将这些值相加。只有当传递给该方法的两个`Observable`实例都至少发出一个值时，才会收到通知。因此，只有当`a`和`b`都有通知时，我们才会得到总和。在第五章中了解更多关于这个方法和其他组合器的信息，*组合器、条件和错误处理*。

1.  我们将我们的`Observer`实例订阅到组合的`Observable`实例上。

这是这个示例的输出可能看起来像的样本：

```java
Reacitve Sum. Type 'a: <number>' and 'b: <number>' to try it.
a:4
b:5
update : a + b = 9.0
a:6
update : a + b = 11.0

```

就是这样！我们使用数据流实现了我们的响应式总和。

### 注意

这个示例的源代码可以从这里下载并尝试：[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter01/ReactiveSumV1.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter01/ReactiveSumV1.java)。

# 总结

在本章中，我们已经了解了响应式原则以及学习和使用它们的原因。构建一个响应式应用并不难；它只需要将程序结构化为一系列小的声明式步骤。通过 RxJava，可以通过构建多个正确连接的异步流来实现这一点，从而在整个数据传输过程中转换数据。

本章介绍的两个例子乍一看可能有点复杂和令人困惑，但实际上它们非常简单。它们中有很多新东西，但在接下来的章节中将会详细解释一切。

如果您想阅读更多关于响应式编程的内容，请查看《在 Netflix API 中使用 RxJava 进行响应式编程》这篇精彩的文章，可在[`techblog.netflix.com/2013/02/rxjava-netflix-api.html`](http://techblog.netflix.com/2013/02/rxjava-netflix-api.html)上找到。另一篇介绍这一概念的精彩文章可以在这里找到：[`gist.github.com/staltz/868e7e9bc2a7b8c1f754`](https://gist.github.com/staltz/868e7e9bc2a7b8c1f754)。

这些是由 RxJava 的创造者之一 Ben Christensen 制作的有关响应式编程和 RX 的幻灯片：[`speakerdeck.com/benjchristensen/reactive-programming-with-rx-at-qconsf-2014`](https://speakerdeck.com/benjchristensen/reactive-programming-with-rx-at-qconsf-2014)。

在下一章中，我们将讨论一些关于*函数式编程*的概念及其在 Java 8 中的实现。这将为我们提供在接下来的章节中所需的基本思想，并帮助我们摆脱在编写响应式程序时的 Java 冗长性。


# 第二章：使用 Java 8 的函数式构造

函数式编程并不是一个新的想法；实际上，它相当古老。例如，**Lisp**是一种函数式语言，是当今常用编程语言中第二古老的语言。

函数式程序是使用可重用的纯函数（lambda）构建的。程序逻辑由小的声明性步骤组成，而不是复杂的算法。这是因为函数式程序最小化了状态的使用，这使得命令式程序复杂且难以重构/支持。

Java 8 带来了 lambda 表达式和将函数传递给函数的能力。有了它们，我们可以以更函数式的风格编码，并摆脱大量的样板代码。Java 8 带来的另一个新功能是流——与 RxJava 的可观察对象非常相似，但不是异步的。结合这些流和 lambda，我们能够创建更类似函数式的程序。

我们将熟悉这些新的构造，并看看它们如何与 RxJava 的抽象一起使用。通过使用 lambda，我们的程序将更简单，更容易跟踪，并且本章介绍的概念将有助于设计应用程序。

本章涵盖：

+   Java 8 中的 Lambda

+   使用 lambda 语法的第一个 RxJava 示例

+   纯函数和高阶函数是什么

# Java 8 中的 Lambda

Java 8 中最重要的变化是引入了 lambda 表达式。它们使编码更快，更清晰，并且可以使用函数式编程。

Java 是在 90 年代作为面向对象的编程语言创建的，其思想是一切都应该是一个对象。那时，面向对象编程是软件开发的主要范式。但是，最近，函数式编程因其适用于并发和事件驱动编程而变得越来越受欢迎。这并不意味着我们应该停止使用面向对象的语言编写代码。相反，最好的策略是将面向对象和函数式编程的元素混合在一起。将 lambda 添加到 Java 8 符合这个想法——Java 是一种面向对象的语言，但现在它有了 lambda，我们也能够使用函数式风格编码。

让我们详细看看这个新功能。

## 介绍新的语法和语义

为了介绍 lambda 表达式，我们需要看到它们的实际价值。这就是为什么本章将以一个不使用 lambda 表达式实现的示例开始，然后重新使用 lambda 表达式实现相同的示例。

还记得`Observable`类中的`map(Func1)`方法吗？让我们尝试为`java.util.List`集合实现类似的东西。当然，Java 不支持向现有类添加方法，因此实现将是一个接受列表和转换并返回包含转换元素的新列表的静态方法。为了将转换传递给方法，我们将需要一个表示它的方法的接口。

让我们来看看代码：

```java
interface Mapper<V, M> { // (1)
  M map(V value); // (2)
}

// (3)	
public static <V, M> List<M> map(List<V> list, Mapper<V, M> mapper) {
  List<M> mapped = new ArrayList<M>(list.size()); // (4)
  for (V v : list) {
    mapped.add(mapper.map(v)); // (5)
  }
  return mapped; // (6)
}
```

这里发生了什么？

1.  我们定义了一个名为`Mapper`的通用接口。

1.  它只有一个方法，`M map(V)`，它接收一个类型为`V`的值并将其转换为类型为`M`的值。

1.  静态方法`List<M> map(List<V>, Mapper<V, M>)`接受一个类型为`V`的元素列表和一个`Mapper`实现。使用这个`Mapper`实现的`map()`方法对源列表的每个元素进行转换，将列表转换为包含转换元素的新类型为`M`的列表。

1.  该实现创建一个新的空类型为`M`的列表，其大小与源列表相同。

1.  使用传递的`Mapper`实现转换源列表中的每个元素，并将其添加到新列表中。

1.  返回新列表。

在这个实现中，每当我们想通过转换另一个列表创建一个新列表时，我们都必须使用正确的转换来实现`Mapper`接口。直到 Java 8，将自定义逻辑传递给方法的正确方式正是这样——使用匿名类实例，实现给定的方法。

但让我们看看我们如何使用这个`List<M> map(List<V>, Mapper<V, M>)`方法：

```java
List<Integer> mapped = map(numbers, new Mapper<Integer, Integer>() {
  @Override
  public Integer map(Integer value) {
    return value * value; // actual mapping
  }
});
```

为了对列表应用映射，我们需要编写四行样板代码。实际的映射非常简单，只有其中一行。真正的问题在于，我们传递的不是一个操作，而是一个对象。这掩盖了这个程序的真正意图——传递一个从源列表的每个项目产生转换的操作，并在最后得到一个应用了变化的列表。

这是使用 Java 8 的新 lambda 语法进行的调用的样子：

```java
List<Integer> mapped = map(numbers, value -> value * value);
```

相当直接了当，不是吗？它只是起作用。我们不是传递一个对象并实现一个接口，而是传递一块代码，一个无名函数。

发生了什么？我们定义了一个任意的接口和一个任意的方法，但我们可以在接口的实例位置传递这个 lambda。在 Java 8 中，如果您定义了*只有一个抽象方法的接口*，并且创建了一个接收此类型接口参数的方法，那么您可以传递 lambda。如果接口的单个方法接受两个字符串类型的参数并返回整数值，那么 lambda 将必须由`->`之前的两个参数组成，并且为了返回整数，参数将被推断为字符串。

这种类型的接口称为**功能接口。**单个方法是抽象的而不是默认的非常重要。Java 8 中的另一件新事物是接口的默认方法：

```java
interface Program {
  default String fromChapter() {
    return "Two";
  }
}
```

默认方法在更改已经存在的接口时非常有用。当我们向它们添加默认方法时，实现它们的类不会中断。只有一个默认方法的接口不是功能性的；单个方法不应该是默认的。

Lambda 充当功能接口的实现。因此，可以将它们分配给接口类型的变量，如下所示：

```java
Mapper<Integer, Integer> square = (value) -> value * value;
```

我们可以重复使用 square 对象，因为它是`Mapper`接口的实现。

也许您已经注意到了，但在目前为止的例子中，lambda 表达式的参数没有类型。那是因为类型是被推断的。因此，这个表达式与前面的表达式完全相同：

```java
Mapper<Integer, Integer> square = (Integer value) -> value * value;
```

没有类型的 lambda 表达式的参数是如何工作的并不是魔术。Java 是一种静态类型语言，因此功能接口的单个方法的参数用于类型检查。

那么 lambda 表达式的主体呢？任何地方都没有`return`语句。事实证明，这两个例子完全相同：

```java
Mapper<Integer, Integer> square = (value) -> value * value;
// and
Mapper<Integer, Integer> square = (value) -> {
 return value * value;
};

```

第一个表达式只是第二个的简写形式。最好 lambda 只有一行代码。但是如果 lambda 表达式包含多行，定义它的唯一方法是使用第二种方法，就像这样：

```java
Mapper<Integer, Integer> square = (value) -> {
  System.out.println("Calculating the square of " + value);
  return value * value;
};
```

在底层，lambda 表达式不仅仅是匿名内部类的语法糖。它们被实现为在**Java 虚拟机**（**JVM**）内快速执行，因此如果您的代码只设计为与 Java 8+兼容，那么您应该绝对使用它们。它们的主要思想是以与数据传递相同的方式传递行为。这使得您的程序更易读。

与新语法相关的最后一件事是能够传递到方法并分配给已定义的函数和方法。让我们定义一个新的功能接口：

```java
interface Action<V> {
  void act(V value);
}
```

我们可以使用它来对列表中的每个值执行任意操作；例如，记录列表。以下是使用此接口的方法：

```java
public static <V> void act(List<V> list, Action<V> action) {
  for (V v : list) {
    action.act(v);
  }
}
```

这个方法类似于`map()`函数。它遍历列表并在每个元素上调用传递的动作的`act()`方法。让我们使用一个简单记录列表中元素的 lambda 来调用它：

```java
act(list, value -> System.out.println(value));
```

这很简单，但不是必需的，因为`println()`方法本身可以直接传递给`act()`方法。这样做如下：

```java
act(list, System.out::println);
```

### 注意

这些示例的代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter02/Java8LambdasSyntaxIntroduction.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter02/Java8LambdasSyntaxIntroduction.java)上查看/下载。

这是 Java 8 中的有效语法——每个方法都可以成为 lambda，并且可以分配给一个变量或传递给一个方法。所有这些都是有效的：

+   Book::makeBook // 类的静态方法

+   book::read // 实例的方法

+   Book::new // 类的构造函数

+   Book::read // 实例方法，但在没有使用实际实例的情况下引用。

现在我们已经揭示了 lambda 语法，我们将在 RxJava 示例中使用它，而不是匿名内部类。

## Java 8 和 RxJava 中的函数接口

Java 8 带有一个特殊的包，其中包含常见情况的函数接口。这个包是`java.util.function`，我们不会在本书中详细介绍它，但会介绍一些值得一提的接口：

+   `Consumer<T>`：这代表接受一个参数并返回空的函数。它的抽象方法是`void accept(T)`。例如，我们可以将`System.out::println`方法分配给一个变量，如下所示：

```java
Consumer<String> print = System.out::println;
```

+   `Function<T,R>`：这代表接受给定类型的一个参数并返回任意类型结果的函数。它的抽象方法是`R accept(T)`，可以用于映射。我们根本不需要`Mapper`接口！让我们看一下以下代码片段：

```java
Function<Integer, String> toStr = (value) -> (value + "!");
List<String> string = map(integers, toStr);
```

+   `Predicate<T>`：这代表只有一个参数并返回布尔结果的函数。它的抽象方法是`boolean test(T)`，可以用于过滤。让我们看一下以下代码：

```java
Predicate<Integer> odd = (value) -> value % 2 != 0;
```

还有许多类似的函数接口；例如，带有两个参数的函数，或者二元运算符。这又是一个带有两个参数的函数，但两个参数类型相同，并返回相同类型的结果。它们有助于在我们的代码中重用 lambda。

好处是 RxJava 与 lambda 兼容。这意味着我们传递给`subscribe`方法的动作实际上是函数接口！

RxJava 的函数接口在`rx.functions`包中。它们都扩展了一个基本的**标记** **接口**（没有方法的接口，用于类型检查），称为`Function`。此外，还有另一个标记接口，扩展了`Function`，称为`Action`。它用于标记消费者（返回空的函数）。

RxJava 有十一个`Action`接口：

```java
Action0 // Action with no parameters
Action1<T1> // Action with one parameter
Action2<T1,T2> // Action with two parameters
Action9<T1,T2,T3,T4,T5,T6,T7,T8,T9> // Action with nine parameters
ActionN // Action with arbitrary number of parameters
```

它们主要用于订阅(`Action1`和`Action0`)。我们在第一章中看到的`Observable.OnSubscribe<T>`参数（用于创建自定义可观察对象）也扩展了`Action`接口。

类似地，有十一个`Function`扩展器代表返回结果的函数。它们是`Func0<R>`，`Func1<T1, R>`... `Func9<T1,T2,T3,T4,T5,T6,T7,T8,T9,R>`和`FuncN<R>`。它们用于映射、过滤、组合和许多其他目的。

RxJava 中的每个操作符和订阅方法都适用于一个或多个这些接口。这意味着我们几乎可以在 RxJava 的任何地方使用 lambda 表达式代替匿名内部类。从这一点开始，我们所有的示例都将使用 lambda，以便更易读和有些函数式。

现在，让我们看一个使用 lambda 实现的大型 RxJava 示例。这是我们熟悉的响应式求和示例！

# 使用 lambda 实现响应式求和示例

因此，这次，我们的主要代码片段将与之前的相似：

```java
ConnectableObservable<String> input = CreateObservable.from(System.in);

Observable<Double> a = varStream("a", input);
Observable<Double> b = varStream("b", input);

reactiveSum(a, b); // The difference

input.connect();
```

唯一的区别是我们将采用更加功能性的方法来计算我们的总和，而不是保持相同的状态。我们不会实现`Observer`接口；相反，我们将传递 lambda 来订阅。这个解决方案更加清晰。

`CreateObservable.from(InputStream)`方法与我们之前使用的非常相似。我们将跳过它，看看`Observable<Double> varStream(String, Observable<String>)`方法，它创建了代表收集器的`Observable`实例：

```java
public static Observable<Double> varStream(
  final String name, Observable<String> input) {
    final Pattern pattern =     Pattern.compile(
      "\\s*" + name + "\\s*[:|=]\\s*(-?\\d+\\.?\\d*)$"
    );
    return input
    .map(pattern::matcher) // (1)
 .filter(m -> m.matches() && m.group(1) != null) // (2)
 .map(matcher -> matcher.group(1)) // (3)
 .map(Double::parseDouble); // (4)
  }
)
```

这个方法比以前使用的要短得多，看起来更简单。但从语义上讲，它是相同的。它创建了一个与源可观察对象连接的`Observable`实例，该源可观察对象产生任意字符串，如果字符串符合它期望的格式，它会提取出一个双精度数并发出这个数字。负责检查输入格式和提取数字的逻辑只有四行，由简单的 lambda 表示。让我们来看一下：

1.  我们映射一个 lambda，使用预期的模式和输入字符串创建一个`matcher`实例。

1.  使用`filter()`方法，只过滤正确格式的输入。

1.  使用`map()`操作符，我们从`matcher`实例中创建一个字符串，其中只包含我们需要的数字数据。

1.  再次使用`map()`操作符，将字符串转换为双精度数。

至于新的`void reactiveSum(Observable<Double>, Observable<Double>)`方法的实现，请使用以下代码：

```java
public static void reactiveSum(
  Observable<Double> a,
  Observable<Double> b) {
    Observable
      .combineLatest(a, b, (x, y) -> x + y) // (1)
 .subscribe( // (2)
 sum -> System.out.println("update : a + b = " + sum),
 error -> {
 System.out.println("Got an error!");
 error.printStackTrace();
 },
 () -> System.out.println("Exiting...")
 );
}
```

让我们看一下以下代码：

1.  再次使用`combineLatest()`方法，但这次第三个参数是一个简单的 lambda，实现了求和。

1.  `subscribe()`方法接受三个 lambda 表达式，当发生以下事件时触发：

+   总和改变了

+   有一个错误

+   程序即将完成

### 注意

此示例的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter02/ReactiveSumV2.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter02/ReactiveSumV2.java)上查看/下载。

使用 lambda 使一切变得更简单。看看前面的程序，我们可以看到大部分逻辑由小型独立函数组成，使用其他函数链接在一起。这就是我们所说的功能性，使用这样的小型可重用函数来表达我们的程序，这些函数接受其他函数并返回函数和数据抽象，使用函数链转换输入数据以产生所需的结果。但让我们深入研究这些函数。

# 纯函数和高阶函数

您不必记住本章介绍的大部分术语；重要的是要理解它们如何帮助我们编写简单但功能强大的程序。

RxJava 的方法融合了许多功能性思想，因此重要的是我们学会如何以更加功能性的方式思考，以便编写更好的响应式应用程序。

## 纯函数

**纯函数**是一个其返回值仅由其输入决定的函数，没有可观察的**副作用**。如果我们用相同的参数调用它*n*次，每次都会得到相同的结果。例如：

```java
Predicate<Integer> even = (number) -> number % 2 == 0;
int i = 50;
while((i--) > 0) {
  System.out.println("Is five even? - " + even.test(5));
}
```

每次，偶函数返回`False`，因为它*仅依赖于其输入*，而每次输入都是相同的，甚至不是。

纯函数的这个特性称为**幂等性**。幂等函数不依赖于时间，因此它们可以将连续数据视为无限数据流。这就是 RxJava（`Observable`实例）中表示不断变化的数据的方式。

### 注意

请注意，在这里，“幂等性”一词是以计算机科学的意义使用的。在计算中，幂等操作是指如果使用相同的输入参数多次调用它，它不会产生额外的效果；在数学中，幂等操作是指满足这个表达式的操作：*f(f(x)) = f(x)*。

纯函数*不会产生副作用*。例如：

```java
Predicate<Integer> impureEven = (number) -> {
  System.out.println("Printing here is side effect!");
  return number % 2 == 0;
};
```

这个函数不是纯的，因为每次调用它时都会在输出上打印一条消息。所以它做了两件事：它测试数字是否为偶数，并且作为副作用输出一条消息。副作用是函数可以产生的任何可能的可观察输出，例如触发事件、抛出异常和 I/O，与其返回值不同。副作用还会改变共享状态或可变参数。

想想看。如果你的大部分程序由纯函数组成，它将很容易扩展，并且可以并行运行部分，因为纯函数不会相互冲突，也不会改变共享状态。

在本节中值得一提的另一件事是**不可变性**。不可变对象是指不能改变其状态的对象。Java 中的`String`类就是一个很好的例子。`String`实例是不可变的；即使像`substring`这样的方法也会创建一个新的`String`实例，而不会修改调用它的实例。

如果我们将不可变数据传递给纯函数，我们可以确保每次使用这些数据调用它时，它都会返回相同的结果。对于**可变**对象，在编写并行程序时情况就不太一样了，因为一个线程可以改变对象的状态。在这种情况下，如果调用纯函数，它将返回不同的结果，因此不再是幂等的。

如果我们将数据存储在不可变对象中，并使用纯函数对其进行操作，在此过程中创建新的不可变对象，我们将不会受到意外并发问题的影响。不会有全局状态和可变状态；一切都将简单而可预测。

使用不可变对象是棘手的；对它们的每个操作都会创建新的实例，这可能会消耗内存。但有方法可以避免这种情况；例如，尽可能多地重用源不可变对象，或使不可变对象的生命周期尽可能短（因为生命周期短的对象对 GC 或缓存友好）。函数式程序应该设计为使用不可变的无状态数据。

复杂的程序不能只由纯函数组成，但只要可能，最好使用它们。在本章对*The Reactive Sum*的实现中，我们只传递了纯函数给`map()`、`filter()`和`combineLatest()`。

谈到`map()`和`filter()`函数，我们称它们为高阶函数。

## 高阶函数

至少有一个函数类型参数或返回函数的函数被称为**高阶函数**。当然，*高阶函数可以是纯的*。

这是一个接受函数参数的高阶函数的例子：

```java
public static <T, R> int highSum(
  Function<T, Integer> f1,
  Function<R, Integer> f2,
  T data1,
  R data2) {
    return f1.apply(data1) + f2.apply(data2);
  }
)
```

它需要两个类型为`T -> int/R -> int`的函数和一些数据来调用它们并对它们的结果求和。例如，我们可以这样做：

```java
highSum(v -> v * v, v -> v * v * v, 3, 2);
```

这里我们对三的平方和两的立方求和。

但高阶函数的理念是灵活的。例如，我们可以使用`highSum()`函数来完成完全不同的目的，比如对字符串求和，如下所示：

```java
Function<String, Integer> strToInt = s -> Integer.parseInt(s);

highSum(strToInt, strToInt, "4",  "5");
```

因此，高阶函数可以用于将相同的行为应用于不同类型的输入。

如果我们传递给`highSum()`函数的前两个参数是纯函数，那么它也将是一个纯函数。`strToInt`参数是一个纯函数，如果我们调用`highSum(strToInt, strToInt, "4", "5")`方法*n*次，它将返回相同的结果，并且不会产生副作用。

这是另一个高阶函数的例子：

```java
public static Function<String, String> greet(String greeting) {
  return (String name) -> greeting + " " + name + "!";
}
```

这是一个返回另一个函数的函数。它可以这样使用：

```java
System.out.println(greet("Hello").apply("world"));
// Prints 'Hellow world!'

System.out.println(greet("Goodbye").apply("cruel world"));
// Prints 'Goodbye cruel world!'

Function<String, String> howdy = greet("Howdy");

System.out.println(howdy.apply("Tanya"));
System.out.println(howdy.apply("Dali"));
// These two print 'Howdy Tanya!' and 'Howdy Dali'
```

### 注意

此示例的代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter02/PureAndHigherOrderFunctions.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter02/PureAndHigherOrderFunctions.java)找到。

这些函数可以用来实现具有共同点的不同行为。在面向对象编程中，我们定义类然后扩展它们，重载它们的方法。在函数式编程中，我们将高阶函数定义为接口，并使用不同的参数调用它们，从而产生不同的行为。

这些函数是*一等公民*；我们可以仅使用函数编写我们的逻辑，将它们链接在一起，并处理我们的数据，将其转换、过滤或累积成一个结果。

## RxJava 和函数式编程

纯函数和高阶函数等函数式概念对 RxJava 非常重要。RxJava 的`Observable`类是*流畅接口*的一种实现。这意味着它的大多数实例方法都返回一个`Observable`实例。例如：

```java
Observable mapped = observable.map(someFunction);
```

`map()`操作符返回一个新的`Observable`实例，发出经过转换的数据。诸如`map()`之类的操作符显然是高阶函数，我们可以向它们传递其他函数。因此，典型的 RxJava 程序由一系列操作符链接到一个`Observable`实例表示，多个*订阅者*可以订阅它。这些链接在一起的函数可以受益于本章涵盖的主题。我们可以向它们传递 lambda 而不是匿名接口实现（就像我们在*Reactive Sum*的第二个实现中看到的那样），并且我们应该尽可能使用不可变数据和纯函数。这样，我们的代码将会简单且安全。

# 总结

在本章中，我们已经了解了一些函数式编程原则和术语。我们学会了如何编写由小的纯函数动作组成的程序，使用高阶函数链接在一起。

随着函数式编程的日益流行，精通它的开发人员将在不久的将来需求量很大。这是因为它帮助我们轻松实现可伸缩性和并行性。而且，如果我们将响应式思想加入其中，它将变得更加吸引人。

这就是为什么我们将在接下来的章节中深入研究 RxJava 框架，学习如何将其用于我们的利益。我们将从`Observable`实例创建技术开始。这将使我们具备从任何东西创建`Observable`实例的技能，从而将几乎一切转变为函数式响应式程序。


# 第三章：创建和连接 Observables、Observers 和 Subjects

RxJava 的 `Observable` 实例是响应式应用程序的构建模块，这是 RxJava 的优势。如果我们有一个源 `Observable` 实例，我们可以将逻辑链接到它并订阅结果。我们只需要这个初始的 `Observable` 实例。

在浏览器或桌面应用程序中，用户输入已经被表示为我们可以处理并通过 `Observable` 实例转发的事件。但是将所有数据更改或操作转换为 `Observable` 实例会很好，而不仅仅是用户输入。例如，当我们从文件中读取数据时，将每一行读取或每个字节序列视为可以通过 `Observable` 实例发出的消息将会很好。

我们将详细了解如何将不同的数据源转换为 `Observable` 实例；无论它们是外部的（文件或用户输入）还是内部的（集合或标量）都无关紧要。此外，我们将了解各种类型的 `Observable` 实例，取决于它们的行为。另一个重要的是我们将学习如何何时取消订阅 `Observable` 实例以及如何使用订阅和 `Observer` 实例。此外，我们还将介绍 Subject 类型及其用法。

在本章中，我们将学习以下内容：

+   `Observable` 工厂方法——`just`、`from`、`create` 等

+   观察者和订阅者

+   热和冷 Observable；可连接的 Observable

+   主题是什么以及何时使用它们

+   `Observable` 创建

有很多种方法可以从不同的来源创建 `Observable` 实例。原则上，可以使用 `Observable.create(OnSubscribe<T>)` 方法创建 `Observable` 实例，但是有许多简单的方法，旨在让我们的生活更美好。让我们来看看其中一些。

# Observable.from 方法

`Observable.from` 方法可以从不同的 Java 结构创建 `Observable` 实例。例如：

```java
List<String> list = Arrays.asList(
  "blue", "red", "green", "yellow", "orange", "cyan", "purple"
);
Observable<String> listObservable = Observable.from(list);
listObservable.subscribe(System.out::println);
```

这段代码从 `List` 实例创建了一个 `Observable` 实例。当在 `Observable` 实例上调用 `subscribe` 方法时，源列表中包含的所有元素都将被发射到订阅方法中。对于每次调用 `subscribe()` 方法，整个集合都会从头开始逐个元素发射：

```java
listObservable.subscribe(
  color -> System.out.print(color + "|"),
  System.out::println,
  System.out::println
);
listObservable.subscribe(color -> System.out.print(color + "/"));
```

这将以不同的格式两次打印颜色。

这个版本的 `from` 方法的真正签名是 `final static <T> Observable<T> from(Iterable<? extends T> iterable)`。这意味着可以将实现 `Iterable` 接口的任何类的实例传递给这个方法。这些包括任何 Java 集合，例如：

```java
Path resources = Paths.get("src", "main", "resources");
try (DirectoryStream<Path> dStream =Files.newDirectoryStream(resources)) {
  Observable<Path> dirObservable = Observable.from(dStream);
  dirObservable.subscribe(System.out::println);
}
catch (IOException e) {
  e.printStackTrace();
}
```

这将把文件夹的内容转换为我们可以订阅的事件。这是可能的，因为 `DirectoryStream` 参数是一个 `Iterable` 实例。请注意，对于此 `Observable` 实例的每次调用 `subscribe` 方法，它的 `Iterable` 源的 `iterator()` 方法都会被调用以获取一个新的 `Iterator` 实例，用于从头开始遍历数据。使用此示例，第二次调用 `subscribe()` 方法时将抛出 `java.lang.IllegalStateException` 异常，因为 `DirectoryStream` 参数的 `iterator()` 方法只能被调用一次。

用于从数组创建 `Observable` 实例的 `from` 方法的另一个重载是 `public final static <T> Observable<T> from(T[] array)`，使用 `Observable` 实例的示例如下：

```java
Observable<Integer> arrayObservable = Observable.from(new Integer[] {3, 5, 8});
  arrayObservable.subscribe(System.out::println);
```

`Observable.from()` 方法非常有用，可以从集合或数组创建 `Observable` 实例。但是有些情况下，我们需要从单个对象创建 `Observable` 实例；对于这些情况，可以使用 `Observable.just()` 方法。

### 注意

使用`Observable.from()`方法的示例的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter03/CreatingObservablesWithFrom.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter03/CreatingObservablesWithFrom.java)中查看和下载。

# Observable.just 方法

`just()`方法将其参数作为`OnNext`通知发出，然后发出`OnCompleted`通知。

例如，一个字母：

```java
Observable.just('S').subscribe(System.out::println);
```

或者一系列字母：

```java
Observable
  .just('R', 'x', 'J', 'a', 'v', 'a')
  .subscribe(
    System.out::print,
    System.err::println,
    System.out::println
  );
```

第一段代码打印`S`和一个换行，第二段代码打印字母并在完成时添加一个换行。该方法允许通过响应式手段观察最多九个任意值（相同类型的对象）。例如，假设我们有这个简单的`User`类：

```java
public static class User {
  private final String forename;
  private final String lastname;
  public User(String forename, String lastname) {
    this.forename = forename;
    this.lastname = lastname;
  }
  public String getForename() {
    return this.forename;
  }
  public String getLastname() {
    return this.lastname;
  }
}
```

我们可以这样打印`User`实例的全名：

```java
Observable
  .just(new User("Dali", "Bali"))
  .map(u -> u.getForename() + " " + u.getLastname())
  .subscribe(System.out::println);
```

这并不是非常实用，但展示了将数据放入`Observable`实例上下文并利用`map()`方法的方法。一切都可以成为一个事件。

还有一些更方便的工厂方法，可在各种情况下使用。让我们在下一节中看看它们。

### 注意

`Observable.just()`方法示例的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter03/CreatingObservablesUsingJust.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter03/CreatingObservablesUsingJust.java)中查看/下载。

# 其他 Observable 工厂方法

在这里，我们将检查一些可以与转换操作符（如 flatMap）或组合操作符（如`.zip`文件）结合使用的方法（有关更多信息，请参见下一章）。

为了检查它们的结果，我们将使用以下方法创建订阅：

```java
void subscribePrint(Observable<T> observable, String name) {
  observable.subscribe(
    (v) -> System.out.println(name + " : " + v),
    (e) -> {
      System.err.println("Error from " + name + ":");
      System.err.println(e.getMessage());
    },
    () -> System.out.println(name + " ended!")
  );
}
```

前面方法的想法是*订阅*一个`Observable`实例并用名称标记它。在*OnNext*时，它打印带有名称前缀的值；在*OnError*时，它与名称一起打印错误；在*OnCompleted*时，它打印带有名称前缀的`'ended!'`。这有助于我们调试结果。

### 注意

前面方法的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/4a2598aa0835235e6ef3bc3371a3c19896161628/src/main/java/com/packtpub/reactive/common/Helpers.java#L25`](https://github.com/meddle0x53/learning-rxjava/blob/4a2598aa0835235e6ef3bc3371a3c19896161628/src/main/java/com/packtpub/reactive/common/Helpers.java#L25)找到。

以下是介绍新工厂方法的代码：

```java
subscribePrint(
  Observable.interval(500L, TimeUnit.MILLISECONDS),
  "Interval Observable"
);
subscribePrint(
  Observable.timer(0L, 1L, TimeUnit.SECONDS),
  "Timed Interval Observable"
);
subscribePrint(
  Observable.timer(1L, TimeUnit.SECONDS),
  "Timer Observable"
);

subscribePrint(
  Observable.error(new Exception("Test Error!")),
  "Error Observable"
);
subscribePrint(Observable.empty(), "Empty Observable");
subscribePrint(Observable.never(), "Never Observable");
subscribePrint(Observable.range(1, 3), "Range Observable");
Thread.sleep(2000L);
```

以下是代码中发生的情况：

+   `Observable<Long> Observable.interval(long, TimeUnit, [Scheduler])`：此方法创建一个`Observable`实例，将以给定间隔发出顺序数字。它可用于实现周期性轮询，或通过仅忽略发出的数字并发出有用消息来实现连续状态记录。该方法的特殊之处在于，默认情况下在*计算线程*上运行。我们可以通过向方法传递第三个参数——`Scheduler`实例（有关`Scheduler`实例的更多信息，请参见第六章, *使用调度程序进行并发和并行处理*）来更改这一点。

+   `Observable<Long> Observable.timer(long, long, TimeUnit, [Scheduler])`：`interval()`方法仅在等待指定时间间隔后开始发出数字。如果我们想要告诉它在何时开始工作，可以使用此`timer()`方法。它的第一个参数是开始时间，第二个和第三个是间隔设置。同样，默认情况下在*计算线程*上执行，同样，这是可配置的。

+   `Observable<Long> Observable.timer(long, TimeUnit, [Scheduler])`：这个在*计算线程*（默认情况下）上在一定时间后只发出输出`'0'`。之后，它发出一个*completed*通知。

+   `<T> Observable<T> Observable.error(Throwable)`：这只会将传递给它的错误作为*OnError*通知发出。这类似于经典的命令式 Java 世界中的`throw`关键字。

+   `<T> Observable<T> Observable.empty()`：这个不发出任何项目，但立即发出一个`OnCompleted`通知。

+   `<T> Observable<T> Observable.never()`：这个什么都不做。它不向其`Observer`实例发送任何通知，甚至`OnCompleted`通知也不发送。

+   `Observable<Integer>` `Observable.range(int, int, [Scheduler])`：此方法从传递的第一个参数开始发送顺序数字。第二个参数是发射的数量。

这个程序将打印以下输出：

```java
Timed Interval Observable : 0
Error from Error Observable:
Test Error!
Range Observable : 1
Range Observable : 2
Range Observable : 3
Range Observable ended!
Empty Observable ended!
Interval Observable : 0
Interval Observable : 1
Timed Interval Observable : 1
Timer Observable : 0
Timer Observable ended!
Interval Observable : 2
Interval Observable : 3
Timed Interval Observable : 2

```

正如你所看到的，`interval Observable`实例不会发送*OnCompleted*通知。程序在两秒后结束，`interval Observable`实例在 500 毫秒后开始发出，每 500 毫秒发出一次；因此，它发出了三个*OnNext*通知。`timed interval Observable`实例在创建后立即开始发出，每秒发出一次；因此，我们从中得到了两个通知。

### 注意

前面示例的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter03/CreatingObservablesUsingVariousFactoryMethods.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter03/CreatingObservablesUsingVariousFactoryMethods.java)上查看/下载。

所有这些方法都是使用`Observable.create()`方法实现的。

# Observable.create 方法

让我们首先看一下该方法的签名：

```java
public final static <T> Observable<T> create(OnSubscribe<T>)
```

它接受一个`OnSubscribe`类型的参数。这个接口扩展了`Action1<Subscriber<? super T>>`接口；换句话说，这种类型只有一个方法，接受一个`Subscriber<T>`类型的参数并返回空。每次调用`Observable.subscribe()`方法时，都会调用此函数。它的参数，`Subscriber`类的一个实例，实际上是观察者，订阅`Observable`实例（这里，`Subscriber`类和 Observer 接口扮演相同的角色）。我们将在本章后面讨论它们。我们可以在其上调用`onNext()`、`onError()`和`onCompleted()`方法，实现我们自己的自定义行为。

通过一个例子更容易理解。让我们实现`Observable.from(Iterabale<T>)`方法的一个简单版本：

```java
<T> Observable<T> fromIterable(final Iterable<T> iterable) {
  return Observable.create(new OnSubscribe<T>() {
    @Override
    public void call(Subscriber<? super T> subscriber) {
      try {
        Iterator<T> iterator = iterable.iterator(); // (1)
        while (iterator.hasNext()) { // (2)
          subscriber.onNext(iterator.next());
        }
        subscriber.onCompleted(); // (3)
      }
      catch (Exception e) {
        subscriber.onError(e); // (4)
      }
    }
  });
}
```

该方法以一个`Iterable<T>`参数作为参数，并返回一个`Observable<T>`参数。行为如下：

1.  当一个`Observer/Subscriber`实例订阅生成的`Observable`实例时，会从`Iterable`源中检索一个`Iterator`实例。`Subscriber`类实际上实现了`Observer`接口。它是一个抽象类，`on*`方法不是由它实现的。

1.  当有元素时，它们作为`OnNext`通知被发送。

1.  当所有元素都被发出时，将发送一个`OnCompleted`通知。

1.  如果在任何时候发生错误，将会发送一个`OnError`通知与错误。

这是`Observable.from(Iterable<T>)`方法行为的一个非常简单和天真的实现。第一章和第二章中描述的 Reactive Sum 是`Observable.create`方法的另一个例子（由`CreateObservable.from()`使用）。

但正如我们所看到的，传递给`create()`方法的逻辑是在`Observable.subscribe()`方法在`Observable`实例上被调用时触发的。到目前为止，我们一直在创建`Observable`实例并使用这种方法*订阅*它们。现在是时候仔细看一下了。

# 订阅和取消订阅

Observable.subscribe()方法有许多重载，如下所示：

+   `subscribe()`: 这个方法忽略来自 Observable 实例的所有发射，并且如果有 OnError 通知，则抛出一个 OnErrorNotImplementedException 异常。这可以用来触发`OnSubscribe.call`行为。

+   `subscribe(Action1<? super T>)`: 这只订阅`onNext()`方法触发的更新。它忽略`OnCompleted`通知，并且如果有`OnError`通知，则抛出一个 OnErrorNotImplementedException 异常。这不是真正的生产代码的好选择，因为很难保证不会抛出错误。

+   `subscribe(Action1<? super T>, Action1<Throwable>)`: 这与前一个方法相同，但如果有`OnError`通知，则调用第二个参数。

+   `subscribe(Action1<? super T>,Action1<Throwable>, Action0)`: 这与前一个方法相同，但第三个参数在`OnCompleted`通知时被调用。

+   `subscribe(Observer<? super T>)`: 这使用其 Observer 参数的`onNext/onError/onCompleted`方法来观察 Observable 实例发出的通知。我们在第一章中实现"响应式求和"时使用了这个方法。

+   `subscribe(Subscriber<? super T>)`: 这与前一个方法相同，但使用 Observer 接口的 Subscriber 实现来观察通知。Subscriber 类提供了高级功能，如取消订阅（取消）和背压（流量控制）。实际上，所有前面的方法都调用这个方法；这就是为什么我们从现在开始谈论`Observable.subscribe`时将引用它。该方法确保传递的 Subscriber 实例看到一个 Observable 实例，符合以下**Rx contract**：

> *"发送到 Observer 接口实例的消息遵循以下语法：*
> 
> *onNext* (onCompleted | onError)?*
> 
> *这种语法允许可观察序列向 Subscriber 发送任意数量（0 个或更多个）的`OnNext()`方法消息，可选地跟随单个成功（`onCompleted`）或失败（`onError`）消息。指示可观察序列已完成的单个消息确保可观察序列的消费者可以确定地建立安全执行清理操作。单个失败进一步确保可以维护对多个可观察序列进行操作的操作符的中止语义。*

- RxJava 的 JavaDoc 的一部分。

这是通过在传递的 Subscriber 实例周围使用一个包装器——SafeSubscriber 来内部完成的。

+   `unsafeSubscribe(Subscriber<? super T>)`: 这与前一个方法相同，但没有**Rx contract**保护。它旨在帮助实现自定义操作符（参见第八章，“资源管理和扩展 RxJava”），而不会增加`subscribe()`方法的额外开销；在一般代码中使用这种方法观察 Observable 实例是不鼓励的。

所有这些方法返回 Subscription 类型的结果，可以用于从 Observable 实例发出的通知中*取消订阅*。取消订阅通常会清理与订阅相关的内部资源；例如，如果我们使用`Observable.create()`方法实现一个 HTTP 请求，并希望在特定时间取消它，或者我们有一个发射无限序列的数字/单词/任意数据的 Observable 实例，并希望停止它。

Subscription 接口有两个方法：

+   `void unsubscribe()`: 这用于*取消订阅*。

+   `boolean isUnsubscribed()`: 这用于检查 Subscription 实例是否已经*取消订阅*。

传递给`Observable.create()`方法的`OnSubscribe()`方法的`Subscriber`类的实例实现了`Subscription`接口。因此，在编写`Observable`实例的行为时，可以进行*取消订阅*和检查`Subscriber`是否已订阅。让我们更新我们的`Observable<T> fromIterable(Iterable<T>)`方法的实现以对*取消订阅*做出反应：

```java
<T> Observable<T> fromIterable(final Iterable<T> iterable) {
  return Observable.create(new OnSubscribe<T>() {
    @Override
    public void call(Subscriber<? super T> subscriber) {
      try {
        Iterator<T> iterator = iterable.iterator();
        while (iterator.hasNext()) {
          if (subscriber.isUnsubscribed()) {
 return;
 }
          subscriber.onNext(iterator.next());
        }
        if (!subscriber.isUnsubscribed()) {
 subscriber.onCompleted();
 }
 }
 catch (Exception e) {
 if (!subscriber.isUnsubscribed()) {
 subscriber.onError(e);
 }
 }
    }
  });
}
```

新的地方在于`Subscription.isUnsubscribed()`方法用于确定是否应终止数据发射。我们在每次迭代时检查`Subscriber`是否已*取消订阅*，因为它可以随时*取消订阅*，之后我们将不需要再发出任何内容。在发出所有内容之后，如果 Subscriber 已经*取消订阅*，则会跳过`onCompleted()`方法。如果有异常，则只有在`Subscriber`实例仍然*订阅*时才会作为`OnError`通知发出。

让我们看看*取消订阅*是如何工作的：

```java
Path path = Paths.get("src", "main", "resources", "lorem_big.txt"); // (1)
List<String> data = Files.readAllLines(path);
Observable<String> observable = fromIterable(data).subscribeOn(Schedulers.computation()); // (2)
Subscription subscription = subscribePrint(observable, "File");// (3)
System.out.println("Before unsubscribe!");
System.out.println("-------------------");
subscription.unsubscribe(); // (4)
System.out.println("-------------------");
System.out.println("After unsubscribe!");
```

以下是这个例子中发生的事情：

1.  数据源是一个巨大的文件，因为我们需要一些需要一些时间来迭代的东西。

1.  `Observable`实例的所有订阅将在另一个*线程*上进行，因为我们希望在主线程上*取消订阅*。

1.  在本章中定义的`subscribePrint()`方法被使用，但已修改为返回`Subscription`。

1.  订阅用于从`Observable`实例*取消订阅*，因此整个文件不会被打印，并且会显示*取消订阅*执行的标记。

输出将类似于这样：

```java
File : Donec facilisis sollicitudin est non molestie.
File : Integer nec magna ac ex rhoncus imperdiet.
Before unsubscribe!
-------------------
File : Nullam pharetra iaculis sem.
-------------------
After unsubscribe!

```

大部分文件内容被跳过。请注意，可能会在*取消订阅*后立即发出某些内容；例如，如果`Subscriber`实例在检查*取消订阅*后立即*取消订阅*，并且程序已经执行`if`语句的主体，则会发出内容。

### 注意

前面示例的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter03/ObservableCreateExample.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter03/ObservableCreateExample.java)中下载/查看。

还要注意的一点是，`Subscriber`实例有一个`void add(Subscription s)`方法。当`Subscriber`*取消订阅*时，传递给它的每个订阅将自动*取消订阅*。这样，我们可以向`Subscriber`实例添加额外的操作；例如，在*取消订阅*时应执行的操作（类似于 Java 中的 try-finally 结构）。这就是*取消订阅*的工作原理。在第八章中，我们将处理资源管理。我们将学习如何通过`Subscription`包装器将`Observable`实例附加到`Subscriber`实例，并且调用*取消订阅*将释放任何分配的资源。

在本章中，我们将讨论与订阅行为相关的下一个主题。我们将谈论热和冷的`Observable`实例。

# 热和冷的 Observable 实例

查看使用`Observable.create()`、`Observable.just()`和`Observable.from()`方法实现的先前示例时，我们可以说在有人订阅它们之前，它们是不活动的，不会发出任何内容。但是，每次有人订阅时，它们就开始发出它们的通知。例如，如果我们对`Observable.from(Iterable)`对象进行三次订阅，`Iterable`实例将被迭代*三*次。像这样行为的`Observable`实例被称为冷的 Observable 实例。

在本章中我们一直在使用的所有工厂方法返回冷的 Observables。冷的 Observables 按需产生通知，并且对于每个 Subscriber，它们产生*独立*的通知。

有些`Observable`实例在开始发出通知时，无论是否有订阅，都会继续发出通知，直到完成。所有订阅者都会收到相同的通知，默认情况下，当一个订阅者*订阅*时，它不会收到之前发出的通知。这些是热 Observable 实例。

我们可以说，冷 Observables 为每个订阅者生成通知，而热 Observables 始终在运行，向所有订阅者广播通知。把热 Observable 想象成一个广播电台。此刻收听它的所有听众都在听同一首歌。冷 Observable 就像一张音乐 CD。许多人可以购买并独立听取它。

正如我们提到的，本书中有很多使用冷 Observables 的例子。那么热 Observable 实例呢？如果你还记得我们在第一章中实现'响应式求和'时，我们有一个`Observable`实例，它会发出用户在标准输入流中输入的每一行。这个是热的，并且我们从中派生了两个`Observable`实例，一个用于收集器`a`，一个用于`b`。它们接收相同的输入行，并且只过滤出它们感兴趣的行。这个输入`Observable`实例是使用一种特殊类型的`Observable`实现的，称为`ConnectableObservable`。

## ConnectableObservable 类

这些`Observable`实例在调用它们的`connect()`方法之前是不活跃的。之后，它们就变成了热 Observables。可以通过调用其`publish()`方法从任何`Observable`实例创建`ConnectableObservable`实例。换句话说，`publish()`方法可以将任何冷 Observable 转换为热 Observable。让我们看一个例子：

```java
Observable<Long> interval = Observable.interval(100L, TimeUnit.MILLISECONDS);
ConnectableObservable<Long> published = interval.publish();
Subscription sub1 = subscribePrint(published, "First");
Subscription sub2 = subscribePrint(published, "Second");
published.connect();
Subscription sub3 = null;
try {
  Thread.sleep(500L);
  sub3 = subscribePrint(published, "Third");
  Thread.sleep(500L);
}
catch (InterruptedException e) {}
sub1.unsubscribe();
sub2.unsubscribe();
sub3.unsubscribe();
```

在调用`connect()`方法之前什么都不会发生。之后，我们将看到相同的顺序数字输出两次——每个订阅者一次。第三个订阅者将加入其他两个，打印在第一个 500 毫秒后发出的数字，但它不会打印其订阅之前发出的数字。

如果我们想要在我们的订阅之前接收*所有*已发出的通知，然后继续接收即将到来的通知，可以通过调用`replay()`方法而不是`publish()`方法来实现。它从源`Observable`实例创建一个`ConnectableObservable`实例，有一个小变化：所有订阅者在订阅时都会收到*所有*通知（之前的通知将按顺序同步到达）。

有一种方法可以激活`Observable`实例，使其在不调用`connect()`方法的情况下变为热 Observable。它可以在*第一次订阅*时激活，并在每个`Subscriber`实例*取消订阅*时停用。可以通过在`ConnectableObservable`实例上调用`refCount()`方法（方法的名称来自'引用计数'；它计算订阅到由它创建的`Observable`实例的`Subscriber`实例数量）从`ConnectableObservable`实例创建这样的`Observable`实例。以下是使用`refCount()`方法实现的前面的例子：

```java
Observable<Long> refCount = interval.publish().refCount();
Subscription sub1 = subscribePrint(refCount, "First");
Subscription sub2 = subscribePrint(refCount, "Second");
try {
  Thread.sleep(300L);
}
catch (InterruptedException e) {}
sub1.unsubscribe();
sub2.unsubscribe();
Subscription sub3 = subscribePrint(refCount, "Third");
try {
  Thread.sleep(300L);
}
catch (InterruptedException e) { }
sub3.unsubscribe();
```

`sub2` *取消订阅*后，`Observable`实例将停用。如果此后有人*订阅*它，它将从头开始发出序列。这就是`sub3`的情况。还有一个`share()`方法，它是`publish().refCount()`调用的别名。

### 注意

前面例子的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter03/UsingConnectableObservables.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter03/UsingConnectableObservables.java)上查看/下载。

还有一种创建热 Observable 的方法：使用`Subject`实例。我们将在本章的下一节和最后一节介绍它们。

# Subject 实例

`Subject`实例既是`Observable`实例又是`Observer`实例。与`Observable`实例一样，它们可以有多个`Observer`实例，接收相同的通知。这就是为什么它们可以用来将冷的`Observable`实例转换为热的实例。与`Observer`实例一样，它们让我们访问它们的`onNext()`、`onError()`或`onCompleted()`方法。

让我们看一下使用`Subject`实例实现前面的热间隔示例：

```java
Observable<Long> interval = Observable.interval(100L, TimeUnit.MILLISECONDS); // (1)
Subject<Long, Long> publishSubject = PublishSubject.create(); // (2)
interval.subscribe(publishSubject);
// (3)
Subscription sub1 = subscribePrint(publishSubject, "First");
Subscription sub2 = subscribePrint(publishSubject, "Second");
Subscription sub3 = null;
try {
  Thread.sleep(300L);
  publishSubject.onNext(555L); // (4)
  sub3 = subscribePrint(publishSubject, "Third"); // (5)
  Thread.sleep(500L);
}
catch (InterruptedException e) {}
sub1.unsubscribe(); // (6)
sub2.unsubscribe();
sub3.unsubscribe();
```

现在示例略有不同：

1.  间隔`Observable`实例的创建方式与以前相同。

1.  在这里，我们创建了一个`PublishSubject`实例 - 一个`Subject`实例，只向订阅后由源`Observable`实例发出的项目发出。这种行为类似于使用`publish()`方法创建的`ConnectableObservable`实例。新的`Subject`实例订阅了由间隔工厂方法创建的间隔`Observable`实例，这是可能的，因为`Subject`类实现了`Observer`接口。还要注意，`Subject`签名有两种泛型类型 - 一种是`Subject`实例将接收的通知类型，另一种是它将发出的通知类型。`PublishSubject`类的输入和输出通知类型相同。

请注意，可以创建一个`PublishSubject`实例而不订阅源`Observable`实例。它只会发出传递给其`onNext()`和`onError()`方法的通知，并在调用其`onCompleted()`方法时完成。

1.  我们可以订阅`Subject`实例；毕竟它是一个`Observable`实例。

1.  我们可以随时发出自定义通知。它将广播给主题的所有订阅者。我们甚至可以调用`onCompleted()`方法并关闭通知流。

1.  第三个订阅者只会收到订阅后发出的通知。

1.  当一切都取消订阅时，`Subject`实例将继续发出。

### 注意

此示例的源代码可在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter03/SubjectsDemonstration.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter03/SubjectsDemonstration.java)上查看/下载。

RxJava 有四种类型的主题：

+   `PublishSubject`：这是我们在前面的示例中看到的，行为类似于使用`publish()`方法创建的`ConnectableObservable`。

+   `ReplaySubject`：这会向任何观察者发出源`Observable`实例发出的所有项目，无论观察者何时订阅。因此，它的行为类似于使用`replay()`方法创建的`ConnectableObservable`。`ReplaySubject`类有许多工厂方法。默认的工厂方法会缓存所有内容；请记住这一点，因为它可能会占用内存。有用于使用大小限制和/或时间限制缓冲区创建它的工厂方法。与`PublishSubject`类一样，这个可以在没有源`Observable`实例的情况下使用。使用其`onNext()`、`onError()`和`onCompleted()`方法发出的所有通知都将发送给每个订阅者，即使在调用`on*`方法后订阅。

+   `BehaviorSubject`：当观察者订阅它时，它会发出源`Observable`实例最近发出的项目（如果尚未发出任何项目，则发出种子/默认值），然后继续发出源`Observable`实例后来发出的任何其他项目。`BehaviorSubject`类几乎与具有缓冲区大小为一的`ReplaySubjects`类相似。`BehaviorSubject`类可用于实现有状态的响应实例 - 一个响应属性。再次强调，不需要源`Observable`实例。

+   `AsyncSubject`：这会发出源`Observable`实例发出的最后一个值（仅此一个），并且只有在源`Observable`实例完成后才会发出。如果源`Observable`实例没有发出任何值，`AsyncSubject`实例也会在不发出任何值的情况下完成。这在 RxJava 的世界中有点像*promise*。不需要源`Observable`实例；可以通过调用`on*`方法将值、错误或`OnCompleted`通知传递给它。

使用主题可能看起来是解决各种问题的一种很酷的方式，但你应该避免使用它们。或者，至少要在返回`Observable`类型的结果的方法中实现它们和它们的行为。

`Subject`实例的危险在于它们提供了`onNext()`，`onError()`和`onCompleted()`方法的访问权限，你的逻辑可能会变得混乱（它们需要遵循本章前面引用的 Rx 合同）。它们很容易被滥用。

在需要从冷 Observable 创建热 Observable 时，选择使用`ConnecatableObservable`实例（即通过`publish()`方法）而不是`Subject`。

但让我们看一个`Subject`实例的一个很好的用法——前面提到的*反应性属性*。同样，我们将实现*'The Reactive Sum'*，但这次会有很大不同。以下是定义它的类：

```java
public class ReactiveSum { // (1)
  private BehaviorSubject<Double> a = BehaviorSubject.create(0.0);
 private BehaviorSubject<Double> b = BehaviorSubject.create(0.0);
 private BehaviorSubject<Double> c = BehaviorSubject.create(0.0);
  public ReactiveSum() { // (2)
    Observable.combineLatest(a, b, (x, y) -> x + y).subscribe(c);
  }
  public double getA() { // (3)
    return a.getValue();
  }
  public void setA(double a) {
    this.a.onNext(a);
  }
  public double getB() {
    return b.getValue();
  }
  public void setB(double b) {
    this.b.onNext(b);
  }
  public double getC() { // (4)
    return c.getValue();
  }
  public Observable<Double> obsC() {
    return c.asObservable();
  }
}
```

这个类有三个双精度属性：两个可设置的属性`a`和`b`，以及它们的*和*，`c`。当`a`或`b`改变时，`c`会*自动更新*为它们的和。我们可以使用一种特殊的方法来跟踪`c`的变化。那它是如何工作的呢？

1.  `ReactiveSum`是一个普通的 Java 类，定义了三个`BehaviorSubject<Double>`类型的私有字段，表示变量`a`，`b`和`c`，默认值为零。

1.  在构造函数中，我们订阅`c`依赖于`a`和`b`，并且等于它们的和，再次使用`combineLatest()`方法。

1.  属性`a`和`b`有 getter 和 setter。getter 返回它们当前的值——最后接收到的值。setter 将传递的值*发出*到它们的`Subject`实例，使其成为最后一个。

### 注意

`BehaviorSubject`参数的`getValue()`方法用于检索它。它在 RxJava 1.0.5 中可用。

1.  属性`c`是只读的，所以它只有一个 getter，但可以被监听。这可以通过`obsC()`方法来实现，它将其作为`Observable`实例返回。记住，当你使用主题时，要始终将它们封装在类型或方法中，并将可观察对象返回给外部世界。

这个`ReactiveSum`类可以这样使用：

```java
ReactiveSum sum = new ReactiveSum();
subscribePrint(sum.obsC(), "Sum");
sum.setA(5);
sum.setB(4);
```

这将输出以下内容：

```java
Sum : 0.0
Sum : 5.0
Sum : 9.0

```

第一个值在`subscribe` `()`方法上*发出*（记住`BehaviorSubject`实例总是在订阅时*发出*它们的最后一个值），其他两个将在设置`a`或`b`时自动*发出*。

### 注意

前面示例的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter03/ReactiveSumV3.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter03/ReactiveSumV3.java)上查看/下载。

*反应性属性*可用于实现绑定和计数器，因此它们对于桌面或浏览器应用程序非常有用。但这个例子远离了任何功能范式。

# 总结

在本章中，我们学习了许多创建不同类型的`Observable`实例和其他相关实例（`Observer`，`Subscriber`，`Subscription`和`Subject`）的方法。我们已经从计时器，值，集合和文件等外部来源创建了它们。利用这些知识作为基础，我们可以开始通过对它们进行操作来构建逻辑。这里介绍的许多工厂方法将在接下来的章节中再次出现。例如，我们将使用`Observable.create`方法构建不同的行为。

在下一章中，我们将介绍各种**操作符**，这将赋予我们使用`Observable`实例编写真正逻辑的能力。我们已经提到了其中一些，比如`map()`和`filter()`，但现在是时候深入研究它们了。


# 第四章：转换、过滤和累积您的数据

现在我们有了从各种来源数据创建`Observable`实例的手段，是时候围绕这些实例构建编程逻辑了。我们将介绍基本的响应式操作符，用于逐步计算（处理数据的响应式方式）。

我们将从转换开始，使用著名的`flatMap()`和`map()`操作符，以及一些不太常见的转换操作符。之后，我们将学习如何使用`filter()`操作符过滤我们的数据，跳过元素，仅在给定时间位置接收元素。本章还将涵盖使用`scan`操作符累积数据。大多数这些操作符将使用*大理石图示*进行演示。

本章涵盖以下主题：

+   大理石图示和映射转换的介绍

+   过滤您的数据

+   使用`scan`操作符累积值

# Observable 转换

我们在一些先前的示例中使用了`map()`操作符。将传入的值转换为其他内容的**高阶函数**称为**转换**。可以在`Observable`实例上调用的高阶函数，从中产生新的`Observable`实例的操作符称为操作符。**转换操作符**以某种方式转换从源`Observable`实例发出的元素。

为了理解不同的操作符是如何工作的，我们将使用称为**大理石图示**的图片。例如，这个描述了`map`操作符：

![Observable 转换](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-rct-prog-java8/img/4305_04_01.jpg)

图示中心的矩形代表操作符（函数）。它将其输入（圆圈）转换为其他东西（三角形）。矩形上方的箭头代表源`Observable`实例，上面的彩色圆圈代表时间发出的`OnNext` *通知*，末端的垂直线是`OnCompleted` *通知*。矩形下方的箭头是具有其转换元素的`Observable`实例的输出。

因此，`map()`操作符确切地做到了这一点：它将源的每个'*next*'值转换为通过传递给它的函数定义的其他内容。这里有一个小例子：

```java
Observable<String> mapped = Observable
  .just(2, 3, 5, 8)
  .map(v -> v * 3)
  .map(v -> (v % 2 == 0) ? "even" : "odd");
subscribePrint(mapped, "map");
```

第一个`map()`操作符将源发出的每个数字转换为它本身乘以三。第二个`map()`操作符将每个乘数转换为一个字符串。如果数字是偶数，则字符串是'`even`'，否则是'`odd`'。

使用`map()`操作符，我们可以将每个发出的值转换为一个新值。还有更强大的转换操作符，看起来类似于`map()`操作符，但具有自己的用途和目的。让我们来看看它们。

## 使用各种 flatMap 操作符进行转换

`flatMap`操作符就像`map()`操作符，但有两个不同之处：

+   `flatMap`操作符的参数不是接收将值转换为任意类型值的函数，而是始终将值或值序列转换为`Observable`实例的形式。

+   它合并了由这些结果`Observable`实例发出的值。这意味着它不是将`Observable`实例作为值发出，而是发出它们的通知。

这是它的大理石图示：

![使用各种 flatMap 操作符进行转换](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-rct-prog-java8/img/4305_04_02.jpg)

正如我们所看到的，源`Observable`实例的每个值都被转换为一个`Observable`实例，最终，所有这些*派生 Observable*的值都由结果`Observable`实例发出。请注意，结果`Observable`实例可能以交错的方式甚至无序地发出派生`Observable`实例的值。

`flatMap`运算符对于分叉逻辑非常有用。例如，如果一个`Observable`实例表示文件系统文件夹并从中发出文件，我们可以使用`flatMap`运算符将每个文件对象转换为一个`Observable`实例，并对这些*文件 observables*应用一些操作。结果将是这些操作的摘要。以下是一个从文件夹中读取一些文件并将它们转储到标准输出的示例：

```java
Observable<Path> listFolder(Path dir, String glob) { // (1)
  return Observable.<Path>create(subscriber -> {
    try {
      DirectoryStream<Path> stream = Files.newDirectoryStream(dir, glob);
      subscriber.add(Subscriptions.create(() -> {
        try {
          stream.close();
        }
        catch (IOException e) {
          e.printStackTrace();
        }
      }));
      Observable.<Path>from(stream).subscribe(subscriber);
    }
    catch (DirectoryIteratorException ex) {
      subscriber.onError(ex);
    }
    catch (IOException ioe) {
      subscriber.onError(ioe);
    }
  });
}
Observable<String> from(final Path path) { // (2)
  return Observable.<String>create(subscriber -> {
    try {
      BufferedReader reader = Files.newBufferedReader(path);
      subscriber.add(Subscriptions.create(() -> {
        try {
          reader.close();
        }
        catch (IOException e) {
          e.printStackTrace();
        }
      }));
      String line = null;
      while ((line = reader.readLine()) != null && !subscriber.isUnsubscribed()) {
        subscriber.onNext(line);
      }
      if (!subscriber.isUnsubscribed()) {
        subscriber.onCompleted();
      }
    }
    catch (IOException ioe) {
      if (!subscriber.isUnsubscribed()) {
        subscriber.onError(ioe);
      }
    }
  });
}
Observable<String> fsObs = listFolder(
  Paths.get("src", "main", "resources"), "{lorem.txt,letters.txt}"
).flatMap(path -> from(path)); // (3)
subscribePrint(fsObs, "FS"); // (4)
```

这段代码介绍了处理文件夹和文件的两种方法。我们将简要介绍它们以及在这个`flatMap`示例中如何使用它们：

1.  第一个方法`listFolder()`接受一个`Path`变量形式的文件夹和一个`glob`表达式。它返回一个代表这个文件夹的`Observable`实例。这个`Observable`实例发出符合`glob`表达式的所有文件作为`Path`对象。

该方法使用了`Observable.create()`和`Observable.from()`运算符。这个实现的主要思想是，如果发生异常，它应该被处理并由生成的`Observable`实例发出。

注意使用`Subscriber.add()`运算符将一个新的`Subscription`实例添加到订阅者，使用`Subscriptions.create()`运算符创建。这个方法使用一个动作创建一个`Subscription`实例。当`Subscription`实例被*取消订阅*时，这个动作将被执行，这意味着在这种情况下`Subscriber`实例被*取消订阅*。因此，这类似于将`stream`的关闭放在最终块中。

1.  这个示例介绍的另一种方法是`Observable<String> from(Path)`。

它逐行读取位于`path`实例中的文件并将行作为`OnNext()` *通知*发出。该方法在`Subscription`实例上使用`Subscriber.add()`运算符来关闭到文件的`stream`。

1.  使用`flatMap`的示例从文件夹创建了一个`Observable`实例，使用`listFolder()`运算符，它发出两个`Path`参数到文件。对于每个文件使用`flatMap()`运算符，我们创建了一个`Observable`实例，使用`from(Path)`运算符，它将文件内容作为行发出。

1.  前述链的结果将是两个文件内容，打印在标准输出上。如果我们对每个*文件路径 Observable*使用`Scheduler`实例（参见第六章, *使用调度程序进行并发和并行处理*），内容将会*混乱*，因为`flatMap`运算符会交错合并`Observable`实例的通知。

### 注意

介绍`Observable<String> from(final Path path)`方法的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/724eadf5b0db988b185f8d86006d772286037625/src/main/java/com/packtpub/reactive/common/CreateObservable.java#L61`](https://github.com/meddle0x53/learning-rxjava/blob/724eadf5b0db988b185f8d86006d772286037625/src/main/java/com/packtpub/reactive/common/CreateObservable.java#L61)找到。

包含`Observable<Path> listFolder(Path dir, String glob)`方法的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/724eadf5b0db988b185f8d86006d772286037625/src/main/java/com/packtpub/reactive/common/CreateObservable.java#L128`](https://github.com/meddle0x53/learning-rxjava/blob/724eadf5b0db988b185f8d86006d772286037625/src/main/java/com/packtpub/reactive/common/CreateObservable.java#L128)上查看/下载。

使用`flatMap`运算符的示例可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter04/FlatMapAndFiles.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter04/FlatMapAndFiles.java)上查看/下载。

`flatMap`操作符有多个重载。例如，有一个接受三个函数的重载——一个用于`OnNext`，一个用于`OnError`，一个用于`OnComleted`。它还将*错误*或*完成*事件转换为`Observable`实例，如果有`OnError`或`OnCompleted`事件，则它们的`Observable`实例转换将合并到生成的`Observable`实例中，然后是一个`OnCompleted` *通知*。这是一个例子：

```java
Observable<Integer> flatMapped = Observable
  .just(-1, 0, 1)
  .map(v -> 2 / v)
  .flatMap(
 v -> Observable.just(v),
 e -> Observable.just(0),
 () -> Observable.just(42)
 );
subscribePrint(flatMapped, "flatMap");
```

这将输出`-2(2/-1)`和`0`（因为`2/0`引发了错误）。由于*错误*，`1`不会被发出，也不会到达`flatMap`操作符。

另一个有趣的重载是`Observable<R> flatMap(Func1<T, Observable<U>>, Func2<T, U, R>)`。这是它的弹珠图：

![各种 flatMap 操作符的转换](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-rct-prog-java8/img/4305_04_03.jpg)

这个操作符将源`Observable`实例的项目与由这些源项目触发的`Observable`实例的项目组合，并调用用户提供的函数，该函数使用原始和派生项目的对。然后`Observable`实例将发出此函数的结果。这是一个例子：

```java
Observable<Integer> flatMapped = Observable
.just(5, 432)
.flatMap(
 v -> Observable.range(v, 2),
 (x, y) -> x + y);
subscribePrint(flatMapped, "flatMap");
```

输出是：

```java
flatMap : 10
flatMap : 11
flatMap : 864
flatMap : 865
flatMap ended!

```

这是因为源`Observable`实例发出的第一个元素是`5`，`flatMap`操作符使用`range()`操作符将其转换为`Observable`实例，该实例发出`5`和`6`。但是这个`flatMap`操作符并不止于此；对于这个范围`Observable`实例发出的每个项目，它都应用第二个函数，第一个参数是原始项目（`5`），第二个参数是范围发出的项目。所以我们有*5 + 5*，然后*5 + 6*。对于源`Observable`实例发出的第二个项目也是一样：`432`。它被转换为*432 + 432 = 864*和*432 + 433 = 865*。

当所有派生项都需要访问其源项时，这种重载是有用的，并且通常可以避免使用某种**元组**或**对**类，从而节省内存和库依赖。在前面的文件示例中，我们可以在每个输出行之前添加文件的名称：

```java
CreateObservable.listFolder(
  Paths.get("src", "main", "resources"),
  "{lorem.txt,letters.txt}"
).flatMap(
 path -> CreateObservable.from(path),
 (path, line) -> path.getFileName() + " : " + line
);
```

`flatMapIterable`操作符不以 lambda 作为参数，该 lambda 以任意值作为参数并返回`Observable`实例。相反，传递给它的 lambda 以任意值作为参数并返回`Iterable`实例。所有这些`Iterable`实例都被展平为由生成的`Observable`实例发出的值。让我们看一下以下代码片段：

```java
Observable<?> fIterableMapped = Observable
.just(
  Arrays.asList(2, 4),
  Arrays.asList("two", "four"),
)
.flatMapIterable(l -> l);
```

这个简单的例子合并了源`Observable`实例发出的两个列表，结果发出了四个项目。值得一提的是，调用`flatMapIterable(list -> list)`等同于调用`flatMap(l → Observable.from(l))`。

`flatMap`操作符的另一种形式是`concatMap`操作符。它的行为与原始的`flatMap`操作符相同，只是它连接而不是合并生成的`Observable`实例，以生成自己的序列。以下弹珠图显示了它的工作原理：

![各种 flatMap 操作符的转换](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-rct-prog-java8/img/4305_04_04.jpg)

来自不同*派生 Observable*的项目不会交错，就像`flatMap`操作符一样。`flatMap`和`concatMap`操作符之间的一个重要区别是，`flatMap`操作符并行使用内部`Observable`实例，而`concatMap`操作符一次只订阅一个`Observable`实例。

类似于`flatMap`的最后一个操作符是`switchMap`。它的弹珠图看起来像这样：

![各种 flatMap 操作符的转换](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-rct-prog-java8/img/4305_04_05.jpg)

它的操作方式类似于`flatMap`操作符，不同之处在于每当源`Observable`实例发出新项时，它就会停止镜像先前发出的项生成的`Observable`实例，并且只开始镜像当前的`Observable`实例。换句话说，当下一个`Observable`实例开始发出其项时，它会在内部取消订阅当前的*派生*`Observable`实例。这是一个例子：

```java
Observable<Object> obs = Observable
.interval(40L, TimeUnit.MILLISECONDS)
.switchMap(v ->
 Observable
 .timer(0L, 10L, TimeUnit.MILLISECONDS)
 .map(u -> "Observable <" + (v + 1) + "> : " + (v + u)))
);
subscribePrint(obs, "switchMap");
```

源`Observable`实例使用`Observable.interval()`操作符每 40 毫秒发出一个连续的数字（从零开始）。使用`switchMap`操作符，为每个数字创建一个发出另一个数字序列的新`Observable`实例。这个次要数字序列从传递给`switchMap`操作符的源数字开始（通过使用`map()`操作符将源数字与每个发出的数字相加来实现）。因此，每 40 毫秒，都会发出一个新的数字序列（每个数字间隔 10 毫秒）。

结果输出如下：

```java
switchMap : Observable <1> : 0
switchMap : Observable <1> : 1
switchMap : Observable <1> : 2
switchMap : Observable <1> : 3
switchMap : Observable <2> : 1
switchMap : Observable <2> : 2
switchMap : Observable <2> : 3
switchMap : Observable <2> : 4
switchMap : Observable <3> : 2
switchMap : Observable <3> : 3
switchMap : Observable <3> : 4
switchMap : Observable <3> : 5
switchMap : Observable <3> : 6
switchMap : Observable <4> : 3
.................

```

### 注意

所有映射示例的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter04/MappingExamples.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter04/MappingExamples.java)下载/查看。

## 分组项目

可以按特定属性或键对项目进行分组。

首先，我们来看一下`groupBy()`操作符，这是一个将源`Observable`实例分成多个`Observable`实例的方法。这些`Observable`实例根据分组函数发出源的一些项。

`groupBy()`操作符返回一个发出`Observable`实例的`Observable`实例。这些`Observable`实例很特殊；它们是`GroupedObservable`类型的，您可以使用`getKey()`方法检索它们的分组键。一旦使用`groupBy()`操作符，不同的组可以以不同或相同的方式处理。

请注意，当`groupBy()`操作符创建发出`GroupedObservables`实例的可观察对象时，每个实例都会缓冲其项。因此，如果我们忽略其中任何一个，这个缓冲区将会造成潜在的内存泄漏。

`groupBy()`操作符的弹珠图如下：

![分组项目](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-rct-prog-java8/img/4305_04_06.jpg)

这里，项目的形式被用作分组的共同特征。为了更好地理解这个方法的思想，我们可以看看这个例子：

```java
List<String> albums = Arrays.asList(
  "The Piper at the Gates of Dawn",
  "A Saucerful of Secrets",
  "More", "Ummagumma",	"Atom Heart Mother",
  "Meddle", "Obscured by Clouds",
  "The Dark Side of the Moon",
  "Wish You Were Here", "Animals", "The Wall"
);
Observable
  .from(albums)
  .groupBy(album -> album.split(" ").length)
  .subscribe(obs ->
    subscribePrint(obs, obs.getKey() + " word(s)")
  );
```

该示例发出了一些 Pink Floyd 的专辑标题，并根据其中包含的单词数进行分组。例如，`Meddle`和`More`在键为`1`的同一组中，`A Saucerful of Secrets`和`Wish You Were Here`都在键为`4`的组中。所有这些组都由`GroupedObservable`实例表示，因此我们可以在源`Observable`实例的`subscribe()`调用中订阅它们。不同的组根据它们的键打印不同的标签。这个小程序的输出如下：

```java
7 word(s) : The Piper at the Gates of Dawn
4 word(s) : A Saucerful of Secrets
1 word(s) : More
1 word(s) : Ummagumma
3 word(s) : Atom Heart Mother
1 word(s) : Meddle
3 word(s) : Obscured by Clouds
6 word(s) : The Dark Side of the Moon
4 word(s) : Wish You Were Here
1 word(s) : Animals
2 word(s) : The Wall

```

发出的项目的顺序是相同的，但它们是由不同的`GroupedObservable`实例发出的。此外，所有`GroupedObservable`实例在源完成后都会完成。

`groupBy()`操作符还有另一个重载，它接受第二个转换函数，以某种方式转换组中的每个项目。这是一个例子：

```java
Observable
.from(albums)
.groupBy(
 album -> album.replaceAll("[^mM]", "").length(),
 album -> album.replaceAll("[mM]", "*")
)
.subscribe(
  obs -> subscribePrint(obs, obs.getKey()+" occurences of 'm'")
);
```

专辑标题按其中字母`m`的出现次数进行分组。文本被转换成所有字母出现的地方都被替换为`*`。输出如下：

```java
0 occurences of 'm' : The Piper at the Gates of Dawn
0 occurences of 'm' : A Saucerful of Secrets
1 occurences of 'm' : *ore
4 occurences of 'm' : U**agu**a
2 occurences of 'm' : Ato* Heart *other
1 occurences of 'm' : *eddle
0 occurences of 'm' : Obscured by Clouds
1 occurences of 'm' : The Dark Side of the *oon
0 occurences of 'm' : Wish You Were Here
1 occurences of 'm' : Ani*als
0 occurences of 'm' : The Wall

```

### 注意

使用`Observable.groupBy()`操作符的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter04/UsingGroupBy.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter04/UsingGroupBy.java)找到。

## 其他有用的转换操作符

还有一些其他值得一提的*转换*。例如，有`cast()`操作符，它是`map(v -> someClass.cast(v))`的快捷方式。

```java
List<Number> list = Arrays.asList(1, 2, 3);
Observable<Integer> iObs = Observable
  .from(list)
  .cast(Integer.class);
```

这里的初始`Observable`实例发出`Number`类型的值，但它们实际上是`Integer`实例，所以我们可以使用`cast()`操作符将它们表示为`Integer`实例。

另一个有用的操作符是`timestamp()`操作符。它通过将每个发出的值转换为`Timestamped<T>`类的实例来为其添加*时间戳*。例如，如果我们想要记录`Observable`的输出，这将非常有用。

```java
List<Number> list = Arrays.asList(3, 2);
Observable<Timestamped<Number>> timestamp = Observable
  .from(list)
  .timestamp();
subscribePrint(timestamp, "Timestamps");
```

在这个例子中，每个数字都被时间戳标记。同样，可以使用`map()`操作符很容易地实现。前面例子的输出如下：

```java
Timestamps : Timestamped(timestampMillis = 1431184924388, value = 1)
Timestamps : Timestamped(timestampMillis = 1431184924394, value = 2)
Timestamps : Timestamped(timestampMillis = 1431184924394, value = 3)

```

另一个类似的操作符是`timeInterval`操作符，但它将一个值转换为`TimeInterval<T>`实例。`TimeInterval<T>`实例表示`Observable`发出的项目以及自上一个项目发出以来经过的时间量，或者（如果没有上一个项目）自订阅以来经过的时间量。这可以用于生成统计信息，例如：

```java
Observable<TimeInterval<Long>> timeInterval = Observable
  .timer(0L, 150L, TimeUnit.MILLISECONDS)
  .timeInterval();
subscribePrint(timeInterval, "Time intervals");
```

这将输出类似于这样的内容：

```java
Time intervals : TimeInterval [intervalInMilliseconds=13, value=0]
Time intervals : TimeInterval [intervalInMilliseconds=142, value=1]
Time intervals : TimeInterval [intervalInMilliseconds=149, value=2]
...................................................................

```

我们可以看到不同的值大约在 150 毫秒左右发出，这是应该的。

`timeInterval`和`timestamp`操作符都在*immediate*调度程序上工作（参见第六章，“使用调度程序进行并发和并行处理”），它们都以毫秒为单位保留其时间信息。

### 注意

前面示例的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter04/VariousTransformationsDemonstration.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter04/VariousTransformationsDemonstration.java)找到。

# 过滤数据

在第一章的响应式求和示例中，我们根据特殊模式过滤用户输入。例如，模式是* a：<number>*。通常只从数据流中过滤出有趣的数据。例如，仅从所有按键按下事件中过滤出*<enter>*按键按下事件，或者仅从文件中包含给定表达式的行中过滤出行。这就是为什么不仅能够转换我们的数据，还能够学会如何过滤它是很重要的。

RxJava 中有许多过滤操作符。其中最重要的是`filter()`。它的弹珠图非常简单，如下所示：

![过滤数据](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-rct-prog-java8/img/4305_04_07.jpg)

它显示`filter()`操作符通过某些属性过滤数据。在图中，它是元素的形式：它只过滤圆圈。像所有其他操作符一样，`filter()`从源创建一个新的`Observable`实例。这个`Observable`实例只发出符合`filter()`操作符定义的条件的项目。以下代码片段说明了这一点：

```java
Observable<Integer> numbers = Observable
  .just(1, 13, 32, 45, 21, 8, 98, 103, 55);
Observable<Integer> filter = numbers
  .filter(n -> n % 2 == 0);
subscribePrint(filter, "Filter");
```

这将仅输出*偶数*（`32`，`8`和`98`），因为满足过滤条件。

`filter()`操作符根据用户定义的函数过滤元素。还有一些其他过滤操作符。为了理解它们，让我们看一些简单的例子：

```java
Observable<Integer> numbers = Observable
  .just(1, 13, 32, 45, 21, 8, 98, 103, 55);
Observable<String> words = Observable
  .just(
    "One", "of", "the", "few", "of",
    "the", "crew", "crew"
  );
Observable<?> various = Observable
  .from(Arrays.asList("1", 2, 3.0, 4, 5L));
```

我们定义了三个`Observable`实例来用于我们的示例。第一个发出九个数字。第二个逐个发出句子中的所有单词。第三个发出不同类型的元素——字符串、整数、双精度和长整型。

```java
subscribePrint(numbers.takeLast(4), "Last 4");
```

`takeLast()`操作符返回一个新的`Observable`实例，只从源`Observable`实例中发出最后的*N*个项目，只有当它完成时。这个方法有一些重载。例如，有一个可以在指定的时间窗口内发出源的最后*N*个或更少的项目。另一个可以接收一个`Scheduler`实例，以便在另一个线程上执行。

在这个例子中，只有`Observable`实例的最后四个项目将被过滤和输出：

```java
Last 4 : 8
Last 4 : 98
Last 4 : 103
Last 4 : 55
Last 4 ended!

```

让我们来看下面的代码片段：

```java
subscribePrint(numbers.last(), "Last");
```

由`last()`操作符创建的`Observable`实例，在源`Observable`实例完成时只输出*最后一个项目*。如果源没有发出项目，将会发出`NoSuchElementException`异常作为`OnError()` *通知*。它有一个重载，接收一个类型为`T->Boolean`的谓词参数。因此，它只发出源发出的最后一个符合谓词定义的条件的项目。在这个例子中，输出将如下所示：

```java
Last : 55
Last ended!

```

`takeLastBuffer()`方法的行为与`takeLast()`方法类似，但它创建的`Observable`实例只发出一个包含源的最后*N*个项目的`List`实例：

```java
subscribePrint(
  numbers.takeLastBuffer(4), "Last buffer"
);
```

它有类似的重载。这里的输出如下：

```java
Last buffer : [8, 98, 103, 55]
Last buffer ended!

```

`lastOrDefault()`操作符的行为与`last()`操作符相似，并且具有谓词的相同重载：

```java
subscribePrint(
  numbers.lastOrDefault(200), "Last or default"
);
subscribePrint(
  Observable.empty().lastOrDefault(200), "Last or default"
);
```

然而，如果源没有发出任何东西，`lastOrDefault()`操作符会发出默认值而不是`OnError` *通知*。这个例子的输出如下：

```java
Last or default : 55
Last or default ended!
Last or default : 200
Last or default ended!

```

`skipLast()`操作符是`takeLast()`方法的完全相反；它在完成时发出除了源的最后*N*个项目之外的所有内容：

```java
subscribePrint(numbers.skipLast(4), "Skip last 4");
```

它有类似的重载。这个例子的输出如下：

```java
Skip last 4 : 1
Skip last 4 : 13

```

`skip()`方法与`skipLast()`方法相同，但是跳过前*N*个项目而不是最后一个：

```java
subscribePrint(numbers.skip(4), "Skip 4");
```

这意味着示例的输出如下：

```java
Skip 4 : 21
Skip 4 : 8
Skip 4 : 98
Skip 4 : 103
Skip 4 : 55
Skip 4 ended!

```

`take()`操作符类似于`takeLast()`操作符，但是它发出源的前*N*个项目，而不是最后的*N*个项目。

```java
subscribePrint(numbers.take(4), "First 4");
```

这是一个常用的操作符，比`takeLast()`操作符更便宜，因为`takeLast()`操作符会缓冲其项目并等待源完成。这个操作符不会缓冲其项目，而是在接收到它们时发出它们。它非常适用于限制无限的`Observable`实例。前面例子的输出如下：

```java
First 4 : 1
First 4 : 13
First 4 : 32
First 4 : 45
First 4 ended!

```

让我们来看下面的代码片段：

```java
subscribePrint(numbers.first(), "First");
```

`first()`操作符类似于`last()`操作符，但只发出源发出的第一个项目。如果没有第一个项目，它会发出相同的`OnError` *通知*。它的谓词形式有一个别名——`takeFirst()`操作符。还有一个`firstOrDefault()`操作符形式。这个例子的输出很清楚：

```java
First : 1
First ended!

```

让我们来看下面的代码片段：

```java
subscribePrint(numbers.elementAt(5), "At 5");
```

`elementAt()`操作符类似于`first()`和`last()`操作符，但没有谓词形式。不过有一个`elementAtOrDefault()`形式。它只发出源`Observable`实例发出的项目序列中指定索引处的元素。这个例子输出如下：

```java
At 5 : 8
At 5 ended!

```

让我们来看下面的代码片段：

```java
subscribePrint(words.distinct(), "Distinct");
```

由`distinct()`操作符产生的`Observable`实例发出源的项目，排除重复的项目。有一个重载可以接收一个函数，返回一个用于决定一个项目是否与另一个项目不同的键或哈希码值：

```java
Distinct : One
Distinct : of
Distinct : the
Distinct : few
Distinct : crew
Distinct ended!

```

```java
subscribePrint(
  words.distinctUntilChanged(), "Distinct until changed"
);
```

`distinctUntilChanged()`操作符类似于`distinct()`方法，但它返回的`Observable`实例会发出源`Observable`实例发出的所有与它们的直接前导不同的项目。因此，在这个例子中，它将发出除了最后一个`crew`之外的每个单词。

```java
subscribePrint( // (13)
  various.ofType(Integer.class), "Only integers"
);
```

`ofType()`操作符创建一个只发出给定类型源发出的项目的`Observable`实例。它基本上是这个调用的快捷方式：`filter(v -> Class.isInstance(v))`。在这个例子中，输出将如下所示：

```java
Only integers : 2
Only integers : 4
Only integers ended!

```

### 注意

所有这些示例的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter04/FilteringExamples.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter04/FilteringExamples.java)上查看/下载。

这些是 RxJava 提供的最常用的*过滤*操作符。我们将在以后的示例中经常使用其中的一些。

在本章中，我们将要看的`last`操作符是一个转换操作符，但有点特殊。它可以使用先前累积的状态！让我们了解更多。

# 累积数据

`scan(Func2)`操作符接受一个带有两个参数的函数作为参数。它的结果是一个`Observable`实例。通过`scan()`方法的结果发出的第一个项目是源`Observable`实例的第一个项目。发出的第二个项目是通过将传递给`scan()`方法的函数应用于结果`Observable`实例之前发出的项目和源`Observable`实例发出的第二个项目来创建的。通过`scan()`方法结果发出的第三个项目是通过将传递给`scan()`方法的函数应用于之前发出的项目和源`Observable`实例发出的第三个项目来创建的。这种模式继续下去，以创建`scan()`方法创建的`Observable`实例发出的序列的其余部分。传递给`scan()`方法的函数称为**累加器**。

让我们来看一下`scan(Func2)`方法的弹珠图：

![累积数据](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-rct-prog-java8/img/4305_04_08.jpg)

`scan()`方法发出的项目可以使用累积状态生成。在图中，圆圈在三角形中累积，然后这个三角形圆圈在正方形中累积。

这意味着我们可以发出一系列整数的总和，例如：

```java
Observable<Integer> scan = Observable
  .range(1, 10)
  .scan((p, v) -> p + v);
subscribePrint(scan, "Sum");
subscribePrint(scan.last(), "Final sum");
```

第一个*订阅*将输出所有的发射：*1, 3 (1+2), 6 (3 + 3), 10 (6 + 4) .. 55*。但在大多数情况下，我们只对最后发出的项目感兴趣——最终总和。我们可以使用一个只发出最后一个元素的`Observable`实例，使用`last()`过滤操作符。值得一提的是，还有一个`reduce(Func2)`操作符，是`scan(Func2).last()`的别名。

`scan()`操作符有一个重载，可以与*seed/initial*参数一起使用。在这种情况下，传递给`scan(T, Func2)`操作符的函数被应用于源发出的第一个项目和这个*seed*参数。

```java
Observable<String> file = CreateObservable.from(
  Paths.get("src", "main", "resources", "letters.txt")
);
scan = file.scan(0, (p, v) -> p + 1);
subscribePrint(scan.last(), "wc -l");
```

这个示例计算文件中的行数。文件`Observable`实例逐行发出指定路径文件的行。我们使用`scan(T, Func2)`操作符，初始值为`0`，通过在每行上累加计数来计算行数。

我们将用一个示例来结束本章，其中使用了本章介绍的许多操作符。让我们来看一下：

```java
Observable<String> file = CreateObservable.from(
  Paths.get("src", "main", "resources", "operators.txt")
);
Observable<String> multy = file
  .flatMap(line -> Observable.from(line.split("\\."))) // (1)
  .map(String::trim) // (2)
  .map(sentence -> sentence.split(" ")) // (3)
  .filter(array -> array.length > 0) // (4)
  .map(array -> array[0]) // (5)
  .distinct() // (6)
  .groupBy(word -> word.contains("'")) //(7)
  .flatMap(observable -> observable.getKey() ? observable : // (8)
    observable.map(Introspector::decapitalize))
  .map(String::trim) // (9)
  .filter(word -> !word.isEmpty()) // (10)
  .scan((current, word) -> current + " " + word) // (11)
  .last() // (12)
  .map(sentence -> sentence + "."); // (13)
subscribePrint(multy, "Multiple operators"); // (14)
```

这段代码使用了许多操作符来过滤并组装隐藏在文件中的句子。文件由一个`Observable`实例表示，它逐行发出其中包含的所有行。

1.  我们不只想对不同的行进行操作；我们想发出文件中包含的所有句子。因此，我们使用`flatMap`操作符创建一个逐句发出文件句子的`Observable`实例（由`dot`确定）。

1.  我们使用`map()`操作符修剪这些句子。它可能包含一些前导或尾随空格。

1.  我们希望对句子中包含的不同单词进行操作，因此我们使用`map()`操作符和`String::split`参数将它们转换为单词数组。

1.  我们不关心空句子（如果有的话），所以我们使用`filter()`操作符将它们过滤掉。

1.  我们只需要句子中的第一个单词，所以我们使用`map()`操作符来获取它们。生成的`Observable`实例会发出文件中每个句子的第一个单词。

1.  我们不需要重复的单词，所以我们使用`distinct()`操作符来摆脱它们。

1.  现在我们想以某种方式分支我们的逻辑，使一些单词被不同对待。所以我们使用`groupBy()`操作符和一个`Boolean`键将我们的单词分成两个`Observable`实例。选择的单词的键是`True`，其他的是`False`。

1.  使用`flatMap`操作符，我们连接我们分开的单词，但只有选择的单词（带有`True`键）保持不变。其余的被*小写*。

1.  我们使用`map()`操作符去除所有不同单词的前导/尾随空格。

1.  我们使用`filter()`操作符来过滤掉空的句子。

1.  使用`scan()`操作符，我们用空格作为分隔符连接单词。

1.  使用`last()`操作符，我们的结果`Observable`实例将只发出最后的连接，包含所有单词。

1.  最后一次调用`map()`操作符，通过添加句点从我们连接的单词中创建一个句子。

1.  如果我们输出这个`Observable`实例发出的单个项目，我们将得到一个由初始文件中所有句子的第一个单词组成的句子（跳过重复的单词）！

输出如下：

```java
Multiple operators : I'm the one who will become RX.
Multiple operators ended!

```

### 注意

上述示例可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter04/VariousTransformationsDemonstration.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter04/VariousTransformationsDemonstration.java)找到。

# 总结

本章结尾的示例演示了我们迄今为止学到的内容。我们可以通过链接`Observable`实例并使用各种操作符来编写复杂的逻辑。我们可以使用`map()`或`flatMap()`操作符来转换传入的数据，并可以使用`groupBy()`或`filter()`操作符或不同的`flatMap()`操作符来分支逻辑。我们可以再次使用`flatMap()`操作符将这些分支连接起来。我们可以借助不同的过滤器选择数据的部分，并使用`scan()`操作符累积数据。使用所有这些操作符，我们可以以可读且简单的方式编写相当不错的程序。程序的复杂性不会影响代码的复杂性。

下一步是学习如何以更直接的方式组合我们逻辑的分支。我们还将学习如何组合来自不同来源的数据。所以让我们继续下一章吧！
