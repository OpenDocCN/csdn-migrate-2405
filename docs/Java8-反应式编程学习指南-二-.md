# Java8 反应式编程学习指南（二）

> 原文：[`zh.annas-archive.org/md5/A4E30A017482EBE61466A691985993DC`](https://zh.annas-archive.org/md5/A4E30A017482EBE61466A691985993DC)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：组合器，条件和错误处理

我们编写的大多数程序都处理来自不同来源的数据。这些来源既可以是外部的（文件、数据库、服务器等）也可以是内部的（不同的集合或相同外部来源的分支）。有许多情况下，我们希望这些来源以某种方式相互依赖。定义这些依赖关系是构建我们的程序的必要步骤。本章的目的是介绍能够实现这一点的`Observable`操作符。

我们在第一章和第二章中看到了组合的`Observable`实例的例子。我们的“响应式求和”程序有一个外部数据源——用户输入，但它根据自定义格式分成了两个内部数据源。我们看到了如何使用`filter()`操作符而不是过程式的`if-else`构造。后来，我们借助组合器将这些数据流合并成一个。

我们将学习如何在`Observable`实例链中对错误做出反应。记住，能够对失败做出反应使我们的程序具有弹性。

在本章中，我们将涵盖：

+   使用操作符（如`combineLatest()`、`merge()`、`concat()`和`zip()`）组合`Observable`实例

+   使用条件操作符（如`takeUntil()`、`skipUntil()`和`amb()`）在`Observable`实例之间创建依赖关系

+   使用`retry()`、`onErrorResumeNext()`和`onErrorReturn()`等操作符进行错误处理

# 组合 Observable 实例

我们首先来看一下`zip(Observable, Observable, <Observable>..., Func)`操作符，它可以使用*组合*函数*组合*两个或多个`Observable`实例。

## zip 操作符

传递给`zip`操作符的函数的参数数量与传递给`zip()`方法的`Observable`实例的数量一样多。当所有这些`Observable`实例至少发出一项时，将使用每个`Observable`实例首次发出的参数值调用该函数。其结果将是通过`zip()`方法创建的`Observable`实例的第一项。由这个`Observable`实例发出的第二项将是源`Observable`实例的第二项的组合（使用`zip()`方法的函数参数计算）。即使其中一个源`Observable`实例已经发出了三项或更多项，它的第二项也会被使用。结果的`Observable`实例总是发出与源`Observable`实例相同数量的项，它发出最少的项然后完成。

这种行为在下面的弹珠图中可以更清楚地看到：

![zip 操作符](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-rct-prog-java8/img/4305_05_01.jpg)

这是一个非常简单的使用`zip()`方法的例子：

```java
Observable<Integer> zip = Observable
.zip(
 Observable.just(1, 3, 4),
 Observable.just(5, 2, 6),
 (a, b) -> a + b
);
subscribePrint(zip, "Simple zip");
```

这个例子类似于弹珠图，并输出相同的结果。由`zip()`方法创建的`Observable`实例发出的第一项是在所有源至少发出一项之后发出的。这意味着即使其中一个源发出了所有的项，结果也只会在所有其他源发出项时才会被发出。

现在，如果你还记得来自第三章的`interval()`操作符，它能够创建一个`Observable`实例，每`<n>`毫秒发出一个顺序数字。如果你想要发出一系列任意对象，可以通过使用`zip()`方法结合`interval()`和`from()`或`just()`方法来实现。让我们看一个例子：

```java
Observable<String> timedZip = Observable
.zip(
 Observable.from(Arrays.asList("Z", "I", "P", "P")),
 Observable.interval(300L, TimeUnit.MILLISECONDS),
 (value, i) -> value
);
subscribePrint(timedZip, "Timed zip");
```

这将在 300 毫秒后输出`Z`，在另外 300 毫秒后输出`I`，在相同的间隔后输出`P`，并在另外 300 毫秒后输出另一个`P`。之后，`timedZip` `Observable`实例将完成。这是因为通过`interval()`方法创建的源`Observable`实例每 300 毫秒发出一个元素，并确定了`timedZip`参数发射的速度。

`zip()`方法也有一个实例方法版本。该操作符称为`zipWith()`。以下是一个类似的示例，但使用了`zipWith()`操作符：

```java
Observable<String> timedZip = Observable
.from(Arrays.asList("Z", "I", "P", "P"))
.zipWith(
 Observable.interval(300L, TimeUnit.MILLISECONDS),
 (value, skip) -> value
);
subscribePrint(timedZip, "Timed zip");
```

接下来，我们将了解在实现“反应式求和”时在第一章中首次看到的*组合器*，*反应式编程简介*。

## combineLatest 操作符

`combineLatest()`操作符具有与`zip()`操作符相同的参数和重载，但行为有些不同。它创建的`Observable`实例在每个源至少有一个时立即发出第一个项目，取每个源的最后一个。之后，它创建的`Observable`实例在任何源`Observable`实例发出项目时发出项目。`combineLatest()`操作符发出的项目数量完全取决于发出的项目顺序，因为在每个源至少有一个之前，单个源可能会发出多个项目。它的弹珠图看起来像这样：

![The combineLatest operator](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-rct-prog-java8/img/4305_05_02.jpg)

在上图中，由组合的`Observable`实例发出的项目的颜色与触发它们发出的项目的颜色相同。

在接下来的几个示例中，将使用由`interval()`和`zipWith()`方法创建的三个源`Observable`实例：

```java
Observable<String> greetings = Observable
.just("Hello", "Hi", "Howdy", "Zdravei", "Yo", "Good to see ya")
.zipWith(
  Observable.interval(1L, TimeUnit.SECONDS),
  this::onlyFirstArg
);
Observable<String> names = Observable
.just("Meddle", "Tanya", "Dali", "Joshua")
.zipWith(
  Observable.interval(1500L, TimeUnit.MILLISECONDS),
  this::onlyFirstArg
);
Observable<String> punctuation = Observable
.just(".", "?", "!", "!!!", "...")
.zipWith(
  Observable.interval(1100L, TimeUnit.MILLISECONDS),
  this::onlyFirstArg
);
```

这是用于压缩的函数：

```java
public <T, R> T onlyFirstArg(T arg1, R arg2) {
  return arg1;
}
```

这是在关于`zip()`方法的部分中看到的在发射之间插入延迟的相同方法。这三个`Observable`实例可以用来比较不同的组合方法。包含问候的`Observable`实例每秒发出一次，包含名称的实例每 1.5 秒发出一次，包含标点符号的实例每 1.1 秒发出一次。

使用`combineLatest()`操作符，我们可以这样组合它们：

```java
Observable<String> combined = Observable
.combineLatest(
 greetings, names, punctuation,
 (greeting, name, puntuation) ->
 greeting + " " + name + puntuation)
;
subscribePrint(combined, "Sentences");
```

这将组合不同源的项目成句。第一句将在一秒半后发出，因为所有源都必须发出某些内容，以便组合的`Observable`实例开始发出。这句话将是`'Hello Meddle.'`。下一句将在任何源发出内容时立即发出。这将在订阅后两秒后发生，因为问候`Observable`实例每秒发出一次；它将发出`'Hi'`，这将使组合的`Observable`实例发出`'Hi Meddle.'`。当经过 2.2 秒时，标点`Observable`实例将发出`'?'`，所以我们将有另一句话——`'Hi Meddle?'`。这将持续到所有源完成为止。

当我们需要计算或通知依赖的任何数据源发生更改时，`combineLatest()`操作符非常有用。下一个方法更简单；它只是合并其源的发射，*交错*它们的过程。

## 合并操作符

当我们想要从多个源获取数据作为一个流时，我们可以使用`merge()`操作符。例如，我们可以有许多`Observable`实例从不同的`log`文件中发出数据。我们不关心当前发射的数据来自哪个`log`文件，我们只想看到所有的日志。

`merge()`操作符的图表非常简单：

![The merge operator](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-rct-prog-java8/img/4305_05_03.jpg)

每个项目都在其原始发射时间发出，源无关紧要。使用前一节介绍的三个`Observable`实例的示例如下：

```java
Observable<String> merged = Observable
  .merge(greetings, names, punctuation);
subscribePrint(merged, "Words");
```

它只会发出不同的单词/标点符号。第一个发出的单词将来自问候`Observable`实例，在订阅后一秒钟发出（因为问候每秒发出一次）`'Hello'`；然后在 100 毫秒后发出`'.'`，因为标点`Observable`实例每 1.1 秒发出一次。在订阅后 400 毫秒，也就是一秒半后，将发出`'Meddle'`。接下来是问候`'Hi'`。发射将继续进行，直到最耗时的源`Observable`实例完成。

值得一提的是，如果任何源发出`OnError`通知，`merge Observable`实例也会发出*error*并随之完成。有一种`merge()`操作符的形式，延迟发出错误，直到所有无错误的源`Observable`实例都完成。它被称为`mergeDelayError()`。

如果我们想以这样的方式组合我们的源，使它们的项目不会在时间上交错，并且第一个传递的源的发射优先于下一个源，我们将使用本章介绍的最后一个组合器——`concat()`操作符。

## 连接运算符

这本书的所有章节都在不同的文件中。我们想要将所有这些文件的内容连接成一个大文件，代表整本书。我们可以为每个章节文件创建一个`Observable`实例，使用我们之前创建的`from(Path)`方法，然后我们可以使用这些`Observable`实例作为源，使用`concat()`操作符将它们按正确的顺序连接成一个`Observable`实例。如果我们订阅这个`Observable`实例，并使用一个将所有内容写入文件的方法，最终我们将得到我们的书文件。

请注意，`conact()`操作符不适用于无限的`Observable`实例。它将发出第一个的通知，但会阻塞其他的。`merge()`和`concat()`操作符之间的主要区别在于，`merge()`同时订阅所有源`Observable`实例，而`concat()`在任何时候只有一个订阅。

`concat()`操作符的弹珠图如下：

![连接运算符](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-rct-prog-java8/img/4305_05_04.jpg)

以下是连接前面示例中的三个`Observable`实例的示例：

```java
Observable<String> concat = Observable
  .concat(greetings, names, punctuation);
subscribePrint(concat, "Concat");
```

这将每秒一个地输出所有的问候，然后每秒半输出名字，最后每 1.1 秒输出标点符号。在问候和名字之间将有 1.5 秒的间隔。

有一个操作符，类似于`concat()`操作符，称为`startWith()`。它将项目前置到`Observable`实例，并具有重载，可以接受一个、两个、三个等等，最多九个值，以及`Iterable`实例或另一个`Observable`实例。使用接受另一个`Observable`实例作为参数的重载，我们可以模拟`concat()`操作符。以下是前面示例在以下代码中的实现：

```java
Observable<String> concat = punctuation
  .startWith(names)
 .startWith(greetings);
subscribePrint(concat, "Concatenated");
```

问候`Observable`实例被前置到名字之前，这个结果被前置到标点的`Observable`实例，创建了与前面示例中相同的连接源的`Observable`实例。

### 注意

本章中前面和所有之前示例的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter05/CombiningObservables.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter05/CombiningObservables.java)找到。

`startWith()`操作符的良好使用是与`combineLatest()`操作符一起使用。如果你记得我们*'Reactive Sum'*示例的初始实现，你必须输入`a`和`b`的值才能计算初始和。但是假设我们修改和的构造方式如下：

```java
Observable.combineLatest(
  a.startWith(0.0),
  b.startWith(0.0),
  (x, y) -> x + y
);
```

即使用户还没有输入任何内容，我们将有一个初始总和为`0.0`的情况，以及用户第一次输入`a`但尚未给`b`赋值的情况，这种情况下我们不会看到总和发生。

与`merge()`操作符一样，`concat()`操作符也有一个实例形式——`concatWith()`操作符。

在本章的这一部分，我们看到了如何组合不同的`Observable`实例。但是组合并不是`Observable`实例之间唯一的交互。它们可以相互依赖或管理彼此。有一种方法可以让一个或多个`Observable`实例创建条件，改变其他`Observable`实例的行为。这是通过条件操作符来实现的。

# 条件操作符

可以使一个`Observable`实例在另一个发出之前不开始发出，或者只在另一个不发出任何内容时才发出。这些`Observable`实例能够在给定条件下发出项目，并且这些条件是使用*条件*操作符应用到它们上的。在本节中，我们将看一些 RxJava 提供的*条件*操作符。

## amb 操作符

`amb()`操作符有多个重载，可以接受从两个到九个源`Observable`实例，或者是一个包含`Observable`实例的`Iterable`实例。它会发出首先开始发出的源`Observable`实例的项目。无论是`OnError`、`OnCompleted`通知还是数据，都不重要。它的图表看起来像这样：

![amb 操作符](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-rct-prog-java8/img/4305_05_05.jpg)

这个操作符也有一个实例形式。它被称为`ambWith()`，可以在一个`Observable`实例上调用，作为参数传入另一个`Observable`实例。

这个*条件*操作符适用于从多个类似数据源中读取数据。订阅者不需要关心数据的来源。它可以用于实现简单的缓存，例如。这里有一个小例子，展示了它的使用方法：

```java
Observable<String> words = Observable.just("Some", "Other");
Observable<Long> interval = Observable
  .interval(500L, TimeUnit.MILLISECONDS)
  .take(2);
subscribePrint(Observable.amb(words, interval), "Amb 1");
Random r = new Random();
Observable<String> source1 = Observable
  .just("data from source 1")
  .delay(r.nextInt(1000), TimeUnit.MILLISECONDS);
Observable<String> source2 = Observable
  .just("data from source 2")
  .delay(r.nextInt(1000), TimeUnit.MILLISECONDS);
subscribePrint(Observable.amb(source1, source2), "Amb 2");
```

第一个`amb()`操作符将发出*words* `Observable`实例的项目，因为*interval* `Observable`实例需要等待半秒钟才能发出，而*words*会立即开始发出。

第二个`amb Observable`实例的发射将是随机决定的。如果第一个源`Observable`实例在第二个之前发出数据，那么`amb Observable`实例将会发出相同的数据，但如果第二个源先发出，那么`amb Observable`实例将发出它的数据。

## takeUntil()、takeWhile()、skipUntil()和 skipWhile()条件操作符

我们在上一章中看到了类似的操作符。`take(int)`操作符仅过滤了前*n*个项目。这些操作符也过滤项目，但是*基于条件*。`takeUntil()`操作符接受另一个`Observable`实例，直到这个其他`Observable`实例发出，源的项目才会被发出；之后，由`takeUntil()`操作符创建的`Observable`实例将完成。让我们看一个使用这些操作符的例子：

```java
Observable<String> words = Observable // (1)
  .just("one", "way", "or", "another", "I'll", "learn", "RxJava")
  .zipWith(
    Observable.interval(200L, TimeUnit.MILLISECONDS),
    (x, y) -> x
  );
Observable<Long> interval = Observable
  .interval(500L, TimeUnit.MILLISECONDS);
subscribePrint(words.takeUntil(interval), "takeUntil"); // (2)
subscribePrint( // (3)
  words.takeWhile(word -> word.length() > 2), "takeWhile"
);
subscribePrint(words.skipUntil(interval), "skipUntil"); // (4)
```

让我们看一下以下解释：

1.  在这些例子中，我们将使用*words*和*interval* `Observable`实例。*words* `Observable`实例每 200 毫秒发出一个单词，而*interval* `Observable`每半秒发出一次。

1.  如前所述，`takeUntil()`操作符的这种重载将在`interval Observable`发出之前发出单词。因此，`one`和`way`将被发出，因为下一个单词`or`应该在订阅后的 600 毫秒后发出，而`interval Observable`在第 500 毫秒时发出。

1.  在这里，`takeWhile()`运算符对`words Observable`设置了条件。它只会在有包含两个以上字母的单词时发出。因为`'or'`有两个字母，所以它不会被发出，之后的所有单词也会被跳过。`takeUntil()`运算符有一个类似的重载，但它只会发出包含少于三个字母的单词。没有`takeWhile(Observable)`运算符重载，因为它本质上是`zip()`运算符：只有在另一个发出时才发出。

1.  `skip*`运算符类似于`take*`运算符。不同之处在于它们在满足条件之前/之后不会发出。在这个例子中，单词`one`和`way`被跳过，因为它们在订阅的 500 毫秒之前被发出，而`interval Observable`在 500 毫秒时开始发出。单词`'or'`和之后的所有单词都被发出。

这些*条件*运算符可以用于在 GUI 应用程序中显示加载动画。代码可能是这样的：

```java
loadingAnimationObservable.takeUntil(requestObservable);
```

在每次发出`loadingAnimationObservable`变量时，都会向用户显示一些短暂的动画。当请求返回时，动画将不再显示。这是程序逻辑的另一种分支方式。

## `defaultIfEmpty()`运算符

`defaultIfEmpty()`运算符的想法是，如果未知的源为空，就返回一些有用的东西。例如，如果远程源没有新内容，我们将使用本地存储的信息。

这是一个简单的例子：

```java
Observable<Object> test = Observable
  .empty()
  .defaultIfEmpty(5);
subscribePrint(test, "defaultIfEmpty");
```

当然，这将输出`5`并完成。

### 注意

`amb()`，`take*`，`skip*`和`defaultIfEmpty()`运算符示例的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter05/Conditionals.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter05/Conditionals.java)找到。

到目前为止，我们已经转换、过滤和组合了数据。但是*错误*呢？我们的应用程序随时可能进入错误状态。是的，我们可以订阅`Observable`实例发出的*错误*，但这将终止我们的逻辑。在`subscribe`方法中，我们已经超出了操作链。如果我们想要在`Observable`实例链内部对*错误*做出反应，并尝试阻止终止怎么办？有一些运算符可以帮助我们做到这一点，我们将在下一节中对它们进行检查。

# 处理错误

在处理 RxJava 中的*错误*时，您应该意识到它们会终止`Observable`的操作链。就像处理常规的过程代码一样，一旦进入 catch 块，就无法返回到抛出异常的代码。但是您可以执行一些备用逻辑，并在程序失败时使用它。`return*`，`retry*`和`resume*`运算符做了类似的事情。

## 返回和恢复运算符

`onErrorReturn`运算符可用于防止调用`Subscriber`实例的`onError`。相反，它将发出最后一个项目并完成。这是一个例子：

```java
Observable<String> numbers = Observable
  .just("1", "2", "three", "4", "5")
  .map(Integer::parseInt)
  .onErrorReturn(e -> -1);
  subscribePrint(numbers, "Error returned");
```

`Integer::parseInt`方法将成功地将字符串`1`和`2`转换为`Integer`值，但在`three`上会失败，并引发`NumberFormatException`异常。此异常将传递给`onErrorReturn()`方法，它将返回数字-`1`。`numbers Observable`实例将发出数字-`1`并完成。因此输出将是`1`，`2`，`-1`，`OnCompleted`通知。

这很好，但有时我们会希望在发生异常时切换到另一个 Observable 操作链。为此，我们可以使用`onExceptionResumeNext()`运算符，它在发生`Exception`时返回一个备用的`Observable`实例，用于替换源实例。以下是修改后使用它的代码：

```java
Observable<Integer> defaultOnError =
  Observable.just(5, 4, 3, 2, 1);
Observable<String> numbers = Observable
  .just("1", "2", "three", "4", "5")
  .map(Integer::parseInt)
  .onExceptionResumeNext(defaultOnError);
  subscribePrint(numbers, "Exception resumed");
```

现在这将输出`1`、`2`、`5`、`4`、`3`、`2`、`1`、`OnCompleted`通知，因为在`'three'`引发异常后，传递给`onExceptionResumeNext()`方法的`defaultOnError Observable`实例将开始发出，替换所有`Subscriber`方法的源`Observable`实例。

还有一个非常类似于`onExceptionResumeNext()`的`resuming()`操作符。它被称为`onErrorResumeNext()`。它可以替换前面示例中的`onExceptionResumeNext()`操作符，结果将是相同的。不过这两个操作符之间有两个区别。

首先，`onErrorResumeNext()`操作符有一个额外的重载，它接受一个 lambda 表达式，返回`Observable`实例（类似于`onErrorReturn()`方法）。其次，它将对每种错误做出反应。`onExceptionResumeNext()`方法只对`Exception`类及其子类的实例做出反应。

```java
Observable<String> numbers = Observable
  .just("1", "2", "three", "4", "5")
  .doOnNext(number -> {
    assert !number.equals("three");
  }
  .map(Integer::parseInt)
  .onErrorResumeNext(defaultOnError);
  subscribePrint(numbers, "Error resumed");
```

在这个示例中，结果将与前一个示例相同`(1, 2, 5, 4, 3, 2, 1, OnCompleted notification b)`；*断言错误*并不重要。但是如果我们使用了`onExceptionResumeNext()`操作符，错误将作为`OnError` *notification*到达`subscribePrint`方法。

在这个示例中使用的`doOnNext()`操作符是一个*副作用生成器*。它不会改变被调用的`Observable`实例发出的项目。它可以用于日志记录、缓存、断言或添加额外的逻辑。还有`doOnError()`和`doOnCompleted()`操作符。此外，还有一个`finallyDo()`操作符，当出现错误或`Observable`实例完成时，它会执行传递给它的函数。

## 重试技术

重试是一种重要的技术。当一个`Observable`实例从不确定的来源（例如远程服务器）发出数据时，一个网络问题可能会终止整个应用程序。在*错误*上重试可以在这种情况下拯救我们。

将`retry()`操作符插入`Observable`操作链中意味着如果发生*错误*，订阅者将重新订阅源`Observable`实例，并从链的开头尝试一切。如果再次出现*错误*，一切将再次重新开始。没有参数的`retry()`操作符会无限重试。还有一个重载的`retry(int)`方法，它接受最大允许的重试尝试次数。

为了演示`retry()`方法，我们将使用以下特殊行为：

```java
class FooException extends RuntimeException {
  public FooException() {
    super("Foo!");
  }
}

class BooException extends RuntimeException {
  public BooException() {
    super("Boo!");
  }
}
class ErrorEmitter implements OnSubscribe<Integer> {
  private int throwAnErrorCounter = 5;
  @Override
  public void call(Subscriber<? super Integer> subscriber) {
    subscriber.onNext(1);
    subscriber.onNext(2);
    if (throwAnErrorCounter > 4) {
      throwAnErrorCounter--;
      subscriber.onError(new FooException());
      return;
    }
    if (throwAnErrorCounter > 0) {
      throwAnErrorCounter--;
      subscriber.onError(new BooException());
      return;
    }
    subscriber.onNext(3);
    subscriber.onNext(4);
    subscriber.onCompleted();
    }
  }
}
```

可以将一个`ErrorEmitter`实例传递给`Observable.create()`方法。如果`throwAnErrorCounter`字段的值大于四，就会发送一个`FooException`异常；如果大于零，就会发送一个`BooException`异常；如果小于或等于零，就会发送一些事件并正常完成。

现在让我们来看一下使用`retry()`操作符的示例：

```java
subscribePrint(Observable.create(new ErrorEmitter()).retry(), "Retry");
```

因为`throwAnErrorCounter`字段的初始值是五，它将重试`五`次，当计数器变为零时，`Observable`实例将*完成*。结果将是`1`、`2`、`1`、`2`、`1`、`2`、`1`、`2`、`1`、`2`、`1`、`2`、`3`、`4`、`OnCompleted`通知。

`retry()`操作符可用于重试一组次数（或无限次）。它甚至有一个重载，接受一个带有两个参数的函数——目前的重试次数和`Throwable`实例的原因。如果这个函数返回`True`，`Observable`实例将重新订阅。这是一种编写自定义重试逻辑的方法。但是延迟重试呢？例如，每秒重试一次？有一个特殊的操作符能够处理非常复杂的*重试逻辑*，那就是`retryWhen()`操作符。让我们来看一个使用它以及之前提到的`retry(predicate)`操作符的示例：

```java
Observable<Integer> when = Observable.create(new ErrorEmitter())
  .retryWhen(attempts -> {
 return attempts.flatMap(error -> {
 if (error instanceof FooException) {
 System.err.println("Delaying...");
 return Observable.timer(1L, TimeUnit.SECONDS);
 }
 return Observable.error(error);
 });
 })
  .retry((attempts, error) -> {
 return (error instanceof BooException) && attempts < 3;
 });
subscribePrint(when, "retryWhen");
```

当`retryWhen()`操作符返回一个发出`OnError()`或`OnCompleted()`通知的`Observable`实例时，通知被传播，如果没有其他*retry/resume*，则调用订阅者的`onError()`或`onCompleted()`方法。否则，订阅者将重新订阅源 observable。

在这个例子中，如果`Exception`是`FooException`，`retryWhen()`操作符返回一个在一秒后发出的`Observable`实例。这就是我们如何实现带有延迟的重试。如果`Exception`不是`FooException`，它将传播到下一个`retry(predicate)`操作符。它可以检查*error*的类型和尝试次数，并决定是否应该传播错误或重试源。

在这个例子中，我们将获得一个延迟的重试，从`retry(predicate)`方法获得三次重试，第五次尝试时，订阅者将收到一个`OnError`通知，带有一个`BooException`异常。

### 注意

`retry`/`resume`/`return`示例的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter05/HandlingErrors.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter05/HandlingErrors.java)找到。

本章的最后一节留给了一个更复杂的例子。我们将利用我们迄今为止的知识创建一个对远程 HTTP API 的请求，并处理结果，将其输出给用户。

# 一个 HTTP 客户端示例

让我们使用 RxJava 通过*username*检索有关 GitHub 用户存储库的信息。我们将使用先前用于将信息输出到系统输出的`subscribePrint()`函数。程序的想法是显示用户的所有公共存储库，这些存储库不是分叉。程序的主要部分如下所示：

```java
String username = "meddle0x53";
Observable<Map> resp = githubUserInfoRequest(client, username);
subscribePrint(
  resp
  .map(json ->
    json.get("name") + "(" + json.get("language") + ")"),
  "Json"
);
```

这个程序使用了我的用户名（可以很容易地改为使用作为参数传递的*username*）来检索其公共存储库的信息。它打印出每个存储库的名称以及其中使用的主要编程语言。存储库由从传入的 JSON 文件生成的`Map`实例表示，因此我们可以从中读取存储库属性。

这些 JSON `Map`实例是由`githubUserInfoRequest(client, username)`方法创建的`Observable`实例发出的。client 参数是 Apache 的`HttpAsyncClient`类的一个实例。客户端能够执行异步 HTTP 请求，并且还有一个名为`RxApacheHttp`的额外的 RxJava 模块，它为我们提供了 RxJava 和 Apache HTTP 之间的绑定。我们将在我们的 HTTP 请求实现中使用它；你可以在[`github.com/ReactiveX/RxApacheHttp`](https://github.com/ReactiveX/RxApacheHttp)找到它。

### 提示

还有许多其他的 RxJava 项目，放在[`github.com/ReactiveX`](https://github.com/ReactiveX)。其中一些非常有用。例如，我们在本书中实现的大多数`from(Stream/Reader/File)`方法在`RxJavaString`模块中有更好的实现。

下一步是实现`githubUserInfoRequest(HttpAsyncClient, String)`方法：

```java
Observable<Map> githubUserInfoRequest(HttpAsyncClient client, String githubUser) {
  if (githubUser == null) { // (1)
    return Observable.<Map>error(
      new NullPointerException("Github user must not be null!")
    );
  }
  String url = "https://api.github.com/users/" + githubUser + "/repos";
  return requestJson(client, url) // (2)
  .filter(json -> json.containsKey("git_url")) // (3)
  .filter(json -> json.get("fork").equals(false));
}
```

这个方法也相当简单。

1.  首先，我们需要有一个 GitHub 的*username*来执行我们的请求，所以我们对它进行一些检查。它不应该是`null`。如果是`null`，我们将返回一个发出*error*的`Observable`实例，发出带有`NullPointerException`异常的`OnError`通知。我们的打印订阅函数将把它显示给用户。

1.  为了实际进行 HTTP 请求，我们将使用另一个具有签名`requestJson(HttpAsyncClient, String)`的方法。它返回发出 JSON 的`Map`实例的`Observable`实例。

1.  如果用户不是真正的 GitHub 用户，或者我们已经超过了 GitHub API 的限制，GitHub 会向我们发送一个 JSON 消息。这就是为什么我们需要检查我们得到的 JSON 是否包含存储库数据或其他内容。表示存储库的 JSON 具有`git_url`键。我们使用这个键来过滤只表示 GitHub 存储库的 JSON。

1.  我们只需要非分叉存储库；这就是为什么我们要对它们进行过滤。

这再次非常容易理解。到目前为止，我们的逻辑中只使用了`map()`和`filter()`运算符，没有什么特别的。让我们看一下实际的 HTTP 请求实现：

```java
Observable<Map> requestJson(HttpAsyncClient client, String url) {
  Observable<String> rawResponse = ObservableHttp
 .createGet(url, client)
 .toObservable() // (1)
  .flatMap(resp -> resp.getContent() // (2)
    .map(bytes -> new String(
      bytes,  java.nio.charset.StandardCharsets.UTF_8
    ))
  )
  .retry(5) // (3)
  .cast(String.class) // (4)
  .map(String::trim)
  .doOnNext(resp -> getCache(url).clear()); // (5)
```

1.  `ObservableHttp`类来自`RxApacheHttp`模块。它为我们执行异步 HTTP 请求，使用 Apache 的`HttpClient`实例。`createGet(url, client)`方法返回一个实例，可以使用`toObservable()`方法转换为实际的`Observable`实例。我们在这里就是这样做的。

1.  当这个`Observable`实例接收到 HTTP 响应时，它将作为`ObservableHttpResponse`实例发出。这个实例有一个`getContent()`方法，它返回一个`Observable<byte[]>`对象，表示响应为*字节序列*。我们使用简单的`map()`运算符将这些*字节数组*转换为`String`对象。现在我们有一个由`String`对象表示的 JSON 响应。

1.  如果连接到 GitHub 出现问题，我们将*重试*五次。

1.  由于 Java 的类型系统，将其转换为`String`是必要的。此外，我们使用`trim()`方法从响应中删除任何尾随/前导空格。

1.  我们清除了此 URL 的缓存信息。我们使用一个简单的内存中的 Map 实例从 URL 到 JSON 数据缓存实现，以便不重复多次发出相同的请求。我们如何填充这个缓存？我们很快就会在下面的代码中看到。让我们来看一下：

```java
  // (6)
  Observable<String> objects = rawResponse
    .filter(data -> data.startsWith("{"))
    .map(data -> "[" + data + "]");
  Observable<String> arrays = rawResponse
    .filter(data -> data.startsWith("["));
  Observable<Map> response = arrays
 .ambWith(objects) // (7)
    .map(data -> { // (8)
      return new Gson().fromJson(data, List.class);
    })
    .flatMapIterable(list -> list) // (9)
    .cast(Map.class)
    .doOnNext(json -> getCache(url).add(json)); // (10)
  return Observable.amb(fromCache(url), response); // (11)
}
```

1.  响应可以是 JSON 数组或 JSON 对象；我们在这里使用`filter()`运算符来分支我们的逻辑。将 JSON 对象转换为 JSON 数组，以便稍后使用通用逻辑。

1.  使用`ambWith()`运算符，我们将使用从两个`Observable`实例中发出数据的那个，并将结果视为 JSON 数组。我们将有数组或对象 JSON，最终结果只是一个作为`String`对象发出 JSON 数组的`Observable`实例。

1.  我们使用 Google 的 JSON 库将这个`String`对象转换为实际的 Map 实例列表。

1.  `flatMapIterable()`运算符将发出`List`实例的`Observable`实例扁平化为发出其内容的实例，即表示 JSON 的多个 Map 实例。

1.  所有这些 Map 实例都被添加到内存中的缓存中。

1.  使用`amb()`运算符，我们实现了回退到缓存的机制。如果缓存包含数据，它将首先发出，这些数据将被使用。

我们有一个使用`Observable`实例实现的 HTTP 数据检索的真实示例！这个请求的输出看起来像这样：

```java
Json : of-presentation-14(JavaScript)
Json : portable-vim(null)
Json : pro.js(JavaScript)
Json : tmangr(Ruby)
Json : todomvc-proact(JavaScript)
Json : vimconfig(VimL)
Json : vimify(Ruby)
Json ended!

```

### 注意

上述示例的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter05/HttpRequestsExample.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter05/HttpRequestsExample.java)找到。

# 摘要

在本章中，我们学习了如何组合`Observable`实例，如何在它们之间创建依赖关系，以及如何对错误做出反应。正如我们在最后的例子中看到的，我们现在能够使用只有`Observable`实例和它们的运算符来创建相当复杂的逻辑。再加上互联网上可用的 RxJava 模块，我们几乎可以将每个数据源转换为`Observable`实例。

下一步是掌握调度器。它们将为我们提供处理多线程的能力，同时在编码时使用这种响应式编程风格。Java 以其并发性而闻名；现在是时候将语言的这些能力添加到我们的`Observable`链中，以并行方式执行多个 HTTP 请求（例如）。我们将学习的另一件新事情是如何对我们的数据进行**缓冲**、**节流**和**去抖动**，这些技术与实时数据流息息相关。


# 第六章：使用调度程序进行并发和并行处理

现代处理器具有多个核心，并且能够同时更快地处理许多耗时操作。Java 并发 API（包括线程等）使这成为可能。

RxJava 的`Observable`链似乎很适合线程。如果我们可以在后台*订阅*我们的源并进行所有的转换、组合和过滤，然后在一切都完成时将结果传递给主线程，那将是很棒的。是的，这听起来很美好，但是 RxJava 默认是单线程的。这意味着，在大多数情况下，当在`Observable`实例上调用`subscribe`方法时，当前线程会阻塞直到所有内容被发出。（这对于由`interval`或`timer`工厂方法创建的`Observable`实例并不成立，例如。）这是一件好事，因为处理线程并不那么容易。它们很强大，但它们需要彼此同步；例如，当一个依赖于另一个的结果时。

在多线程环境中最难管理的事情之一是线程之间的共享数据。一个线程可以从数据源中读取，而另一个线程正在修改它，这导致不同版本的相同数据被不同的线程使用。如果`Observable`链构造得当，就没有共享状态。这意味着同步并不那么复杂。

在本章中，我们将讨论并行执行事务，并了解并发意味着什么。此外，我们将学习一些处理我们的`Observable`实例发出太多项目的情况的技术（这在多线程环境中并不罕见）。本章涵盖的主题如下：

+   使用`Scheduler`实例实现*并发*

+   使用`Observable`实例的**缓冲**、**节流**和**去抖动**

# RxJava 的调度程序

调度程序是 RxJava 实现并发的方式。它们负责为我们创建和管理线程（在内部依赖于 Java 的线程池设施）。我们不会涉及 Java 的并发 API 及其怪癖和复杂性。我们一直在使用调度程序，隐式地使用定时器和间隔，但是现在是掌握它们的时候了。

让我们回顾一下我们在第三章中介绍的`Observable.interval`工厂方法，*创建和连接 Observables、Observers 和 Subjects*。正如我们之前看到的，RxJava 默认情况下是*单线程*的，所以在大多数情况下，在`Observable`实例上调用`subscribe`方法会阻塞当前线程。但是`interval Observable`实例并非如此。如果我们查看`Observable<Long> interval(long interval, TimeUnit unit)`方法的 JavaDoc，我们会看到它说，由它创建的`Observable`实例在一个叫做“计算调度程序”的东西上运行。

为了检查`interval`方法的行为（以及本章中的其他内容），我们将需要一个强大的调试工具。这就是为什么我们在本章中要做的第一件事。

## 调试 Observables 和它们的调度程序

在上一章中，我们介绍了`doOnNext()`操作符，它可以用于直接从`Observable`链中记录发出的项目。我们提到了`doOnError()`和`doOnCompleted()`操作符。但是有一个结合了所有三者的操作符——`doOnEach()`操作符。我们可以从中记录所有内容，因为它接收所有发出的通知，而不管它们的类型。我们可以将它放在操作符链的中间，并使用它来记录状态。它接受一个`Notification -> void`函数。

这是一个返回`lambda`结果的高阶*debug*函数的源代码，它能够记录使用传递的描述标记的`Observable`实例的发射：

```java
<T> Action1<Notification<? super T>> debug(
  String description, String offset
) {
  AtomicReference<String> nextOffset = new AtomicReference<String>(">");
  return (Notification<? super T> notification) -> {
    switch (notification.getKind()) {
    case OnNext:
      System.out.println(
        Thread.currentThread().getName() +
        "|" + description + ": " + offset +
        nextOffset.get() + notification.getValue()
      );
      break;
    case OnError:
      System.err.println(
        Thread.currentThread().getName() +
        "|" + description + ": " + offset +
        nextOffset.get() + " X " + notification.getThrowable()
      );
      break;
    case OnCompleted:
      System.out.println(
        Thread.currentThread().getName() +
        "|" + description + ": " + offset +
        nextOffset.get() + "|"
      );
    default:
      break;
    }
    nextOffset.getAndUpdate(p -> "-" + p);
  };
}
```

根据传递的*description*和*offset*，返回的方法记录每个通知。然而，重要的是，在一切之前记录当前活动线程的名称。`<value>`标记*OnNext 通知*；`X`标记*OnError 通知*；`|`标记*OnCompleted 通知*，`nextOffset`变量用于显示时间上的值。

这是使用这个新方法的一个例子：

```java
Observable
  .range(5, 5)
  .doOnEach(debug("Test", ""))
  .subscribe();
```

这个例子将生成五个连续的数字，从数字五开始。我们通过调用我们的`debug(String, String)`方法传递给`doOnEach()`操作符来记录`range()`方法调用之后的一切。通过不带参数的订阅调用，这个小链将被触发。输出如下：

```java
main|Test: >5
main|Test: ->6
main|Test: -->7
main|Test: --->8
main|Test: ---->9
main|Test: ----->|

```

首先记录的是当前线程的名称（主线程），然后是传递给`debug()`方法的`Observable`实例的描述，之后是一个冒号和破折号形成的箭头，表示时间。最后是通知类型的符号——对于值本身是值，对于完成是`|`。

让我们定义`debug()`辅助方法的一个重载，这样我们就不需要传递第二个参数给它，如果不需要额外的偏移量：

```java
<T> Action1<Notification<? super T>> debug(String description) {
  return debug(description, "");
}
```

### 注意

前面方法的代码可以在以下链接查看/下载：[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/common/Helpers.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/common/Helpers.java)。

现在我们准备调试由间隔方法创建的`Observable`实例发生了什么！

## 间隔 Observable 及其默认调度程序

让我们来看下面的例子：

```java
Observable
  .take(5)
  .interval(500L, TimeUnit.MILLISECONDS)
  .doOnEach(debug("Default interval"))
  .subscribe();
```

这创建了一个`interval Observable`实例，每隔半秒发出一次。我们使用`take()`方法只获取前五个*通知*并完成。我们将使用我们的`debug()`辅助方法记录由间隔方法创建的`Observable`实例发出的值，并使用`subscribe()`调用来触发逻辑。输出应该如下所示：

```java
RxComputationThreadPool-1|Default interval: >0
RxComputationThreadPool-1|Default interval: ->1
RxComputationThreadPool-1|Default interval: -->2
RxComputationThreadPool-1|Default interval: --->3
RxComputationThreadPool-1|Default interval: ---->4

```

这里应该都很熟悉，除了`Observable`实例执行的线程！这个线程不是*主*线程。看起来它是由 RxJava 管理的可重用`Thread`实例池创建的，根据它的名称（`RxComputationThreadPool-1`）。

如果你还记得，`Observable.interval`工厂方法有以下重载：

```java
Observable<Long> interval(long, TimeUnit, Scheduler)
```

这意味着我们可以指定它将在哪个调度程序上运行。之前提到过，只有两个参数的重载在*computation*调度程序上运行。所以，现在让我们尝试传递另一个调度程序，看看会发生什么：

```java
Observable
  .take(5)
  .interval(500L, TimeUnit.MILLISECONDS, Schedulers.immediate())
  .doOnEach(debug("Imediate interval"))
  .subscribe();
```

这与以前相同，但有一点不同。我们传递了一个名为*immediate*的调度程序。这样做的想法是立即在当前运行的线程上执行工作。结果如下：

```java
main|Imediate interval: >0
main|Imediate interval: ->1
main|Imediate interval: -->2
main|Imediate interval: --->3
main|Imediate interval: ---->4

```

通过指定这个调度程序，我们使`interval Observable`实例在当前*主*线程上运行。

### 注意

前面例子的源代码可以在以下链接找到：[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter06/IntervalAndSchedulers.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter06/IntervalAndSchedulers.java)。

借助调度程序的帮助，我们可以指示我们的操作符在特定线程上运行或使用特定的线程池。

我们刚刚讨论的一切都导致了这样的结论：调度程序会生成新的线程，或者重用已经生成的线程，*操作*是`Observable`实例链的一部分，会在这些线程上执行。因此，我们可以通过仅使用它们来实现并发（操作同时进行）。

为了拥有*多线程*逻辑，我们只需要学习这两件事：

+   我们可以选择的调度程序类型

+   如何在任意`Observable`链的*操作*中使用这些调度程序

## 调度程序的类型

有几种专门用于某种类型操作的`schedulers`。为了更多地了解它们，让我们看一下`Scheduler`类。

事实证明这个类非常简单。它只有两个方法，如下所示：

+   `long now()`

+   `abstract Worker createWorker()`

第一个返回当前时间的毫秒数，第二个创建一个`Worker`实例。这些`Worker`实例用于在单个线程或事件循环上执行操作（取决于实现）。使用`Worker`的`schedule*`方法来安排执行操作。`Worker`类实现了`Subscription`接口，因此它有一个`unsubscribe()`方法。*取消订阅*`Worker`会*取消排队*的所有未完成工作，并允许资源清理。

我们可以使用工作线程在`Observable`上下文之外执行调度。对于每种`Scheduler`类型，我们可以做到以下几点：

```java
scheduler.createWorker().schedule(Action0);
```

这将安排传递的操作并执行它。在大多数情况下，这个方法不应该直接用于调度工作，我们只需选择正确的调度程序并在其上安排操作即可。为了了解它们的作用，我们可以使用这个方法来检查各种可用的调度程序类型。

让我们定义一个测试方法：

```java
void schedule(Scheduler scheduler, int numberOfSubTasks, boolean onTheSameWorker) {
  List<Integer> list = new ArrayList<>(0);
  AtomicInteger current = new AtomicInteger(0);
  Random random = new Random();
  Worker worker = scheduler.createWorker();
  Action0 addWork = () -> {
    synchronized (current) {
      System.out.println("  Add : " + Thread.currentThread().getName() + " " + current.get());
      list.add(random.nextInt(current.get()));
      System.out.println("  End add : " + Thread.currentThread().getName() + " " + current.get());
    }
  };
  Action0 removeWork = () -> {
    synchronized (current) {
      if (!list.isEmpty()) {
        System.out.println("  Remove : " + Thread.currentThread().getName());
        list.remove(0);
        System.out.println("  End remove : " + Thread.currentThread().getName());
      }
    }
  };
  Action0 work = () -> {
    System.out.println(Thread.currentThread().getName());
    for (int i = 1; i <= numberOfSubTasks; i++) {
      current.set(i);
      System.out.println("Begin add!");
      if (onTheSameWorker) {
        worker.schedule(addWork);
      }
      else {
 scheduler.createWorker().schedule(addWork);
      }
      System.out.println("End add!");
    }
    while (!list.isEmpty()) {
      System.out.println("Begin remove!");
    if (onTheSameWorker) {
 worker.schedule(removeWork);
    }
    else {
 scheduler.createWorker().schedule(removeWork);
    }
    System.out.println("End remove!");
  };
  worker.schedule(work);
}
```

该方法使用传递的`Scheduler`实例来执行一些工作。有一个选项可以指定它是否应该为每个任务使用相同的`Worker`实例，或者为每个子任务生成一个新的`Worker`实例。基本上，虚拟工作包括用随机数填充列表，然后逐个删除这些数字。每个*添加操作*和*删除操作*都是通过传递的`Scheduler`实例创建的工作线程作为子任务进行调度的。在每个子任务之前和之后，当前线程和一些额外信息都被记录下来。

### 提示

在现实世界的场景中，一旦所有工作都完成了，我们应该始终调用`worker.unsubscribe()`方法。

转向预定义的`Scheduler`实例。它们可以通过`Schedulers`类中包含的一组静态方法来获取。我们将使用之前定义的调试方法来检查它们的行为，以了解它们的差异和用处。

### `Schedulers.immediate`调度程序

`Schedulers.immediate`调度程序在此时此刻执行工作。当一个操作传递给它的工作线程的`schedule(Action0)`方法时，它就会被调用。假设我们用它来运行我们的测试方法，就像这样：

```java
schedule(Schedulers.immediate(), 2, false);
schedule(Schedulers.immediate(), 2, true);
```

在这两种情况下，结果看起来都是这样的：

```java
main
Begin add!
 Add : main 1
 End add : main 1
End add!
Begin add!
 Add : main 2
 End add : main 2
End add!
Begin remove!
 Remove : main
 End remove : main
End remove!
Begin remove!
 Remove : main
 End remove : main
End remove!

```

换句话说，一切都在调用线程上执行——主线程上，没有任何并行操作。

这个调度程序可以用来在前台执行`interval()`和`timer()`等方法。

### `Schedulers.trampoline`调度程序

通过`Schedulers.trampoline`方法检索到的调度程序会在当前`线程`上*排队*子任务。排队的工作会在当前正在进行的工作完成后执行。假设我们要运行这个：

```java
schedule(Schedulers.trampoline(), 2, false);
schedule(Schedulers.trampoline(), 2, true);
```

在第一种情况下，结果将与立即调度程序相同，因为所有任务都是在它们自己的`Worker`实例中执行的，因此每个工作线程只有一个任务要排队执行。但是当我们使用相同的`Worker`实例来调度每个子任务时，我们会得到这样的结果：

```java
main
Begin add!
End add!
Begin add!
End add!
 Add : main 2
 End add : main 2
 Add : main 2
 End add : main 2

```

换句话说，它将首先执行整个主要操作，然后执行子任务；因此，`List`实例将被填充（子任务已入队），但永远不会被清空。这是因为在执行主任务时，`List`实例仍然为空，并且`while`循环没有被触发。

### 注意

*trampoline*调度程序可用于在递归运行多个任务时避免`StackOverflowError`异常。例如，假设一个任务完成后调用自身执行一些新工作。在单线程环境中，这将导致由于递归而导致堆栈溢出；但是，如果我们使用*trampoline*调度程序，它将序列化所有已安排的活动，并且堆栈深度将保持正常。但是，*trampoline*调度程序通常比*immediate*调度程序慢。因此，使用正确的调度程序取决于用例。

### Schedulers.newThread 调度程序

此调度程序为每个新的`Worker`实例创建一个*new* `Thread`实例（确切地说是单线程的`ScheduledThreadPoolExecutor`实例）。此外，每个工作人员通过其`schedule()`方法排队接收到的操作，就像*trampoline*调度程序一样。让我们看看以下代码：

```java
schedule(Schedulers.newThread(), 2, true);
```

它将具有与*trampoline*相同的行为，但将在新的`thread:`中运行：

```java
RxNewThreadScheduler-1
Begin add!
End add!
Begin add!
End add!
  Add : RxNewThreadScheduler-1 2
  End add : RxNewThreadScheduler-1 2
  Add : RxNewThreadScheduler-1 2
  End add : RxNewThreadScheduler-1 2
```

相反，如果我们像这样调用测试方法：

```java
schedule(Schedulers.newThread(), 2, false);
```

这将为每个*子任务*生成一个新的`Thread`实例，其输出类似于这样：

```java
RxNewThreadScheduler-1
Begin add!
End add!
Begin add!
  Add : RxNewThreadScheduler-2 1
  End add : RxNewThreadScheduler-2 2
End add!
Begin remove!
  Add : RxNewThreadScheduler-3 2
  End add : RxNewThreadScheduler-3 2
End remove!
Begin remove!
End remove!
Begin remove!
  Remove : RxNewThreadScheduler-5
  End remove : RxNewThreadScheduler-5
  Remove : RxNewThreadScheduler-4
  End remove : RxNewThreadScheduler-4
End remove!
```

通过使用*new thread* `Scheduler`实例，您可以执行后台任务。

### 注意

这里非常重要的要求是，其工作人员需要*取消订阅*以避免泄漏线程和操作系统资源。请注意，每次创建新线程都是昂贵的，因此在大多数情况下，应使用*computation*和*IO* `Scheduler`实例。

### Schedulers.computation 调度程序

计算调度程序与*new thread*调度程序非常相似，但它考虑了运行它的机器的处理器/核心数量，并使用可以重用有限数量线程的线程池。每个新的`Worker`实例在其中一个`Thread`实例上安排顺序操作。如果线程当前未被使用，并且它是活动的，则它们将被排队以便稍后执行。

如果我们使用相同的`Worker`实例，我们将只是将所有操作排队到其线程上，并且结果将与使用一个`Worker`实例调度，使用*new thread* `Scheduler`实例相同。

我的机器有四个核心。假设我像这样调用测试方法：

```java
schedule(Schedulers.computation(), 5, false);
```

我会得到类似于这样的输出：

```java
RxComputationThreadPool-1
Begin add!
  Add : RxComputationThreadPool-2 1
  End add : RxComputationThreadPool-2 1
End add!
Begin add!
End add!
Begin add!
  Add : RxComputationThreadPool-3 3
  End add : RxComputationThreadPool-3 3
End add!
Begin add!
  Add : RxComputationThreadPool-4 4
End add!
Begin add!
  End add : RxComputationThreadPool-4 4
End add!
Begin remove!
End remove!
Begin remove!
  Add : RxComputationThreadPool-2 5
  End add : RxComputationThreadPool-2 5
End remove!
Begin remove!
End remove!
Begin remove!
End remove!
Begin remove!
End remove!
Begin remove!
End remove!
Begin remove!
End remove!
Begin remove!
End remove!
Begin remove!
  Remove : RxComputationThreadPool-3
End remove!
Begin remove!
  End remove : RxComputationThreadPool-3
  Remove : RxComputationThreadPool-2
End remove!
Begin remove!
  End remove : RxComputationThreadPool-2
End remove!
Begin remove!
  Remove : RxComputationThreadPool-2
End remove!
Begin remove!
End remove!
Begin remove!
End remove!
Begin remove!
End remove!
Begin remove!
  End remove : RxComputationThreadPool-2
End remove!
  Remove : RxComputationThreadPool-2
Begin remove!
  End remove : RxComputationThreadPool-2
End remove!
  Add : RxComputationThreadPool-1 5
  End add : RxComputationThreadPool-1 5
  Remove : RxComputationThreadPool-1
  End remove : RxComputationThreadPool-1
```

所有内容都是使用来自池中的四个`Thread`实例执行的（请注意，有一种方法可以将`Thread`实例的数量限制为少于可用处理器数量）。

*computation* `Scheduler`实例是执行后台工作 - 计算或处理的最佳选择，因此它的名称。您可以将其用于应该在后台运行且不是*IO*相关或阻塞操作的所有内容。

### Schedulers.io 调度程序

输入输出（IO）调度程序使用`ScheduledExecutorService`实例从*线程池*中检索线程以供其工作人员使用。未使用的线程将被缓存并根据需要重用。如果需要，它可以生成任意数量的线程。

同样，如果我们只使用一个`Worker`实例运行我们的示例，操作将被排队到其线程上，并且其行为将与*computation*和*new thread*调度程序相同。

假设我们使用多个`Worker`实例运行它，如下所示：

```java
schedule(Schedulers.io(), 2, false);
```

它将根据需要从其*池*生成`Thread`实例。结果如下：

```java
RxCachedThreadScheduler-1
Begin add!
End add!
Begin add!
 Add : RxCachedThreadScheduler-2 2
 End add : RxCachedThreadScheduler-2 2
End add!
Begin remove!
 Add : RxCachedThreadScheduler-3 2
 End add : RxCachedThreadScheduler-3 2
End remove!
Begin remove!
 Remove : RxCachedThreadScheduler-4
 End remove : RxCachedThreadScheduler-4
End remove!
Begin remove!
End remove!
Begin remove!
 Remove : RxCachedThreadScheduler-6
 End remove : RxCachedThreadScheduler-6
End remove!

```

*IO*调度程序专用于阻塞*IO 操作*。用于向服务器发出请求，从文件和套接字读取以及其他类似的阻塞任务。请注意，其线程池是无界的；如果其工作人员未取消订阅，则池将无限增长。

### 注意

所有前述代码的源代码位于[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter06/SchedulersTypes.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter06/SchedulersTypes.java)。

### Schedulers.from(Executor)方法

这可以用来创建一个自定义的`Scheduler`实例。如果没有预定义的调度程序适合您，可以使用这个方法，将它传递给`java.util.concurrent.Executor`实例，以实现您需要的行为。

现在我们已经了解了预定义的`Scheduler`实例应该如何使用，是时候看看如何将它们与我们的`Observable`序列集成了。

## 组合 Observable 和调度程序

为了在其他线程上执行我们的可观察逻辑，我们可以使用调度程序。有两个特殊的操作符，它们接收`Scheduler`作为参数，并生成`Observable`实例，能够在与当前线程不同的`Thread`实例上执行操作。

### Observable<T> subscribeOn(Scheduler)方法

`subscribeOn()`方法创建一个`Observable`实例，其`subscribe`方法会导致订阅在从传递的调度程序中检索到的线程上发生。例如，我们有这样的：

```java
Observable<Integer> range = Observable
  .range(20, 4)
  .doOnEach(debug("Source"));
range.subscribe();

System.out.println("Hey!");
```

我们将得到以下输出：

```java
main|Source: >20
main|Source: ->21
main|Source: -->22
main|Source: --->23
main|Source: -------->|
Hey!

```

这是正常的；调用`subscribe`方法会在主线程上执行可观察逻辑，只有在所有这些都完成之后，我们才会看到`'Hey!'`。

让我们修改代码看起来像这样：

```java
CountDownLatch latch = new CountDownLatch(1);
Observable<Integer> range = Observable
  .range(20, 4)
  .doOnEach(debug("Source"))
  .subscribeOn(Schedulers.computation())
  .finallyDo(() -> latch.countDown());
range.subscribe();
System.out.println("Hey!");
latch.await();
```

输出变成了以下内容：

```java
Hey!
RxComputationThreadPool-1|Source: >20
RxComputationThreadPool-1|Source: ->21
RxComputationThreadPool-1|Source: -->22
RxComputationThreadPool-1|Source: --->23
RxComputationThreadPool-1|Source:--------->|

```

这意味着*调用者*线程不会阻塞首先打印`'Hey!'`或在数字之间，所有`Observable`实例的可观察逻辑都在*计算*线程上执行。这样，您可以使用任何您喜欢的调度程序来决定在哪里执行工作。

在这里，我们需要提到`subscribeOn()`方法的一些重要内容。如果您在整个链中多次调用它，就像这样：

```java
CountDownLatch latch = new CountDownLatch(1);
Observable<Integer> range = Observable
  .range(20, 3)
  .doOnEach(debug("Source"))
  .subscribeOn(Schedulers.computation());
Observable<Character> chars = range
  .map(n -> n + 48)
  .map(n -> Character.toChars(n))
  .subscribeOn(Schedulers.io())
  .map(c -> c[0])
  .subscribeOn(Schedulers.newThread())
  .doOnEach(debug("Chars ", "    "))
  .finallyDo(() -> latch.countDown());
chars.subscribe();
latch.await();
```

调用它时*最接近*链的开头很重要。在这里，我们首先在*计算*调度程序上*订阅*，然后在*IO*调度程序上，然后在*新线程*调度程序上，但我们的代码将在*计算*调度程序上执行，因为这在链中*首先*指定。

```java
RxComputationThreadPool-1|Source: >20
RxComputationThreadPool-1|Chars :     >D
RxComputationThreadPool-1|Source: ->21
RxComputationThreadPool-1|Chars :     ->E
RxComputationThreadPool-1|Source: -->22
RxComputationThreadPool-1|Chars :     -->F
RxComputationThreadPool-1|Source: --->|
RxComputationThreadPool-1|Chars :     --->|

```

总之，在生成`Observable`实例的方法中不要指定调度程序；将这个选择留给方法的调用者。或者，使您的方法接收`Scheduler`实例作为参数；例如`Observable.interval`方法。

### 注意

`subscribeOn()`操作符可用于在订阅时阻塞调用者线程的`Observable`实例。在这些源上使用`subscribeOn()`方法让调用者线程与`Observable`实例逻辑并发进行。

那么另一个操作符呢，它帮助我们在其他线程上执行工作呢？

### Observable<T> observeOn(Scheduler)操作符

`observeOn()`操作符类似于`subscribeOn()`操作符，但它不是在传递的`Scheduler`实例上执行整个链，而是从其在其中的位置开始执行链的一部分。通过一个例子最容易理解这一点。让我们使用稍微修改过的前一个例子：

```java
CountDownLatch latch = new CountDownLatch(1);
Observable<Integer> range = Observable
  .range(20, 3)
  .doOnEach(debug("Source"));
Observable<Character> chars = range
  .map(n -> n + 48)
  .doOnEach(debug("+48 ", "    "))
  .map(n -> Character.toChars(n))
  .map(c -> c[0])
  .observeOn(Schedulers.computation())
  .doOnEach(debug("Chars ", "    "))
  .finallyDo(() -> latch.countDown());
chars.subscribe();
System.out.println("Hey!");
latch.await();
```

在这里，我们告诉`Observable`链在订阅后在*主*线程上执行，直到它到达`observeOn()`操作符。在这一点上，它被移动到*计算*调度程序上。这样的输出类似于以下内容：

```java
main|Source: >20
main|+48 :     >68
main|Source: ->21
main|+48 :     ->69
main|Source: -->22
main|+48 :     -->70
RxComputationThreadPool-3|Chars :     >D
RxComputationThreadPool-3|Chars :     ->E
RxComputationThreadPool-3|Chars :     -->F
main|Source: --->|
main|+48 :    --->|
Hey!
RxComputationThreadPool-3|Chars :    --->|

```

正如我们所看到的，调用操作符之前的链部分会阻塞*主*线程，阻止打印`Hey!`。然而，在所有通知通过`observeOn()`操作符之后，`'Hey!'`被打印出来，执行继续在*计算*线程上进行。

如果我们将`observeOn()`操作符移到`Observable`链上，更大部分的逻辑将使用*计算*调度程序执行。

当然，`observeOn()`操作符可以与`subscribeOn()`操作符一起使用。这样，链的一部分可以在一个线程上执行，而其余部分可以在另一个线程上执行（在大多数情况下）。如果你编写客户端应用程序，这是特别有用的，因为通常这些应用程序在一个*事件排队*线程上运行。你可以使用`subscribeOn()`/`observeOn()`操作符使用*IO*调度程序从文件/服务器读取数据，然后在*事件*线程上观察结果。

### 提示

有一个 RxJava 的 Android 模块没有在本书中涵盖，但它受到了很多关注。你可以在这里了解更多信息：[`github.com/ReactiveX/RxJava/wiki/The-RxJava-Android-Module`](https://github.com/ReactiveX/RxJava/wiki/The-RxJava-Android-Module)。

如果你是 Android 开发人员，不要错过它！

**Swing**和**JavaFx**也有类似的模块。

让我们看一个使用`subscribeOn()`和`observeOn()`操作符的示例：

```java
CountDownLatch latch = new CountDownLatch(1);
Observable<Integer> range = Observable
  .range(20, 3)
  .subscribeOn(Schedulers.newThread())
  .doOnEach(debug("Source"));
Observable<Character> chars = range
  .observeOn(Schedulers.io())
  .map(n -> n + 48)
  .doOnEach(debug("+48 ", "    "))
  .observeOn(Schedulers.computation())
  .map(n -> Character.toChars(n))
  .map(c -> c[0])
  .doOnEach(debug("Chars ", "    "))
  .finallyDo(() -> latch.countDown());
chars.subscribe();
latch.await();
```

在这里，我们在链的开头使用了一个`subsribeOn()`操作符的调用（实际上，放在哪里都无所谓，因为它是对该操作符的唯一调用），以及两个`observeOn()`操作符的调用。执行此代码的结果如下：

```java
RxNewThreadScheduler-1|Source: >20
RxNewThreadScheduler-1|Source: ->21
RxNewThreadScheduler-1|Source: -->22
RxNewThreadScheduler-1|Source: --->|
RxCachedThreadScheduler-1|+48 :     >68
RxCachedThreadScheduler-1|+48 :     ->69
RxCachedThreadScheduler-1|+48 :     -->70
RxComputationThreadPool-3|Chars :     >D
RxCachedThreadScheduler-1|+48 :     --->|
RxComputationThreadPool-3|Chars :     ->E
RxComputationThreadPool-3|Chars :     -->F
RxComputationThreadPool-3|Chars :     --->|

```

我们可以看到链通过了三个线程。如果我们使用更多元素，一些代码将看起来是*并行*执行的。结论是，使用`observeOn()`操作符，我们可以多次更改线程；使用`subscribeOn()`操作符，我们可以一次性进行此操作—*订阅*。

### 注意

使用`observeOn()`/`subscribeOn()`操作符的上述示例的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter06/SubscribeOnAndObserveOn.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter06/SubscribeOnAndObserveOn.java)找到。

使用这两个操作符，我们可以让`Observable`实例和*多线程*一起工作。但是*并发*并不真正意味着我们可以*并行*执行任务。它意味着我们的程序有多个线程，可以独立地取得一些进展。真正的*并行*是当我们的程序以最大限度利用主机机器的 CPU（核心）并且其线程实际上同时运行时。

到目前为止，我们的所有示例都只是将链逻辑移动到其他线程上。尽管有些示例确实在*并行*中执行了部分操作，但真正的*并行*示例看起来是不同的。

## 并行

我们只能通过使用我们已经知道的操作符来实现*并行*。想想`flatMap()`操作符；它为源发出的每个项目创建一个`Observable`实例。如果我们在这些`Observable`实例上使用`subscribeOn()`操作符和`Scheduler`实例，每个实例将在新的`Worker`实例上*调度*，并且它们将*并行*工作（如果主机机器允许）。这是一个例子：

```java
Observable<Integer> range = Observable
  .range(20, 5)
  .flatMap(n -> Observable
    .range(n, 3)
    .subscribeOn(Schedulers.computation())
    .doOnEach(debug("Source"))
  );
range.subscribe();
```

这段代码的输出如下：

```java
RxComputationThreadPool-3|Source: >23
RxComputationThreadPool-4|Source: >20
RxComputationThreadPool-2|Source: >22
RxComputationThreadPool-3|Source: ->24
RxComputationThreadPool-1|Source: >21
RxComputationThreadPool-2|Source: ->23
RxComputationThreadPool-3|Source: -->25
RxComputationThreadPool-3|Source: --->|
RxComputationThreadPool-4|Source: ->21
RxComputationThreadPool-4|Source: -->22
RxComputationThreadPool-4|Source: --->|
RxComputationThreadPool-2|Source: -->24
RxComputationThreadPool-2|Source: --->|
RxComputationThreadPool-1|Source: ->22
RxComputationThreadPool-1|Source: -->23
RxComputationThreadPool-1|Source: --->|
RxComputationThreadPool-4|Source: >24
RxComputationThreadPool-4|Source: ->25
RxComputationThreadPool-4|Source: -->26
RxComputationThreadPool-4|Source: --->|

```

我们可以通过线程的名称看出，通过`flatMap()`操作符定义的`Observable`实例是在*并行*中执行的。这确实是这种情况——四个线程正在使用我的处理器的四个核心。

我将提供另一个示例，这次是对远程服务器进行*并行*请求。我们将使用前一章中定义的`requestJson()`方法。思路是这样的：

1.  我们将检索 GitHub 用户的关注者信息（在本例中，我们将使用我的帐户）。

1.  对于每个关注者，我们将得到其个人资料的 URL。

1.  我们将以*并行*方式请求关注者的个人资料。

1.  我们将打印关注者的数量以及他们的关注者数量。

让我们看看这是如何实现的：

```java
Observable<Map> response = CreateObservable.requestJson(
  client,
  "https://api.github.com/users/meddle0x53/followers"
); // (1)
response
  .map(followerJson -> followerJson.get("url")) // (2)
  .cast(String.class)
  .flatMap(profileUrl -> CreateObservable
    .requestJson(client, profileUrl)
    .subscribeOn(Schedulers.io()) // (3)
    .filter(res -> res.containsKey("followers"))
    .map(json ->  // (4)
      json.get("login") +  " : " +
      json.get("followers"))
  )
  .doOnNext(follower -> System.out.println(follower)) // (5)
  .count() // (6)
  .subscribe(sum -> System.out.println("meddle0x53 : " + sum));
```

在上述代码中发生了什么：

1.  首先，我们对我的用户的关注者数据进行请求。

1.  请求以*JSON*字符串形式返回关注者，这些字符串被转换为`Map`对象（请参阅`requestJson`方法的实现）。从每个*JSON*文件中，读取表示关注者个人资料的 URL。

1.  对每个 URL 执行一个新的请求。请求在*IO*线程上*并行*运行，因为我们使用了与前面示例相同的技术。值得一提的是，`flatMap()`运算符有一个重载，它接受一个`maxConcurrent`整数参数。我们可以使用它来限制并发请求。

1.  获取关注者的用户数据后，生成他/她的关注者的信息。

1.  这些信息作为副作用打印出来。

1.  使用`count()`运算符来计算我的关注者数量（这与`scan(0.0, (sum, element) -> sum + 1).last()`调用相同）。然后我们打印它们。打印的数据顺序不能保证与遍历关注者的顺序相同。

### 注意

前面示例的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter06/ParallelRequestsExample.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter06/ParallelRequestsExample.java)找到。

这就是*并发*和*并行*的全部内容。一切都很简单，但功能强大。有一些规则（例如使用`Subscribers.io`实例进行阻塞操作，使用*计算*实例进行后台任务等），您必须遵循以确保没有任何问题，即使是*多线程*的可观察链操作。

使用这种*并行*技术很可能会使`Observable`实例链中涌入大量数据，这是一个问题。这就是为什么我们必须处理它。在本章的其余部分，我们将学习如何处理来自*上游*可观察链操作的太多元素。

# 缓冲、节流和去抖动

这里有一个有趣的例子：

```java
Path path = Paths.get("src", "main", "resources");
Observable<String> data = CreateObservable
  .listFolder(path, "*")
  .flatMap(file -> {
    if (!Files.isDirectory(file)) {
      return CreateObservable
    .from(file)
    .subscribeOn(Schedulers.io());
  }
  return Observable.empty();
});
subscribePrint(data, "Too many lines");
```

这将遍历文件夹中的所有文件，并且如果它们本身不是文件夹，则会并行读取它们。例如，当我运行它时，文件夹中有五个文本文件，其中一个文件相当大。在使用我们的`subscribePrint()`方法打印这些文件的内容时，我们得到了类似于这样的内容：

```java
Too many lines : Morbi nec nulla ipsum.
Too many lines : Proin eu tellus tortor.
Too many lines : Lorem ipsum dolor sit am
Error from Too many lines:
rx.exceptions.MissingBackpressureException
Too many lines : Vivamus non vulputate tellus, at faucibus nunc.
Too many lines : Ut tristique, orci eu
Too many lines : Aliquam egestas malesuada mi vitae semper.
Too many lines : Nam vitae consectetur risus, vitae congue risus.
Too many lines : Donec facilisis sollicitudin est non molestie.
 rx.internal.util.RxRingBuffer.onNext(RxRingBuffer.java:349)
 rx.internal.operators.OperatorMerge$InnerSubscriber.enqueue(OperatorMerge.java:721)
 rx.internal.operators.OperatorMerge$InnerSubscriber.emit(OperatorMerge.java:698)
 rx.internal.operators.OperatorMerge$InnerSubscriber.onNext(OperatorMerge.java:586)
 rx.internal.operators.OperatorSubscribeOn$1$1$1.onNext(OperatorSubscribeOn.java:76)

```

输出被裁剪了，但重要的是我们得到了`MissingBackpressureException`异常。

读取每个文件的线程正在尝试将它们的数据推送到`merge()`运算符（`flatMap()`运算符实现为`merge(map(func))`）。该运算符正在努力处理大量数据，因此它将尝试通知过度生产的`Observable`实例减速（通知上游无法处理数据量的能力称为*背压*）。问题在于它们没有实现这样的机制（*背压*），因此会遇到`MissingBackpressureException`异常。

通过在上游可观察对象中实现*背压*，使用其中一个特殊的`onBackpressure*`方法或尝试通过将大量传入的项目打包成更小的发射集来避免它。这种打包是通过*缓冲*、*丢弃*一些传入的项目、*节流*（使用时间间隔或事件进行缓冲）和*去抖动*（使用项目发射之间的间隔进行缓冲）来完成的。

让我们检查其中一些。

## 节流

使用这种机制，我们可以调节`Observable`实例的发射速率。我们可以指定时间间隔或另一个流控制`Observable`实例来实现这一点。

使用`sample()`运算符，我们可以使用另一个`Observable`实例或时间间隔来控制`Observable`实例的发射。

```java
data = data
  .sample(
 Observable
 .interval(100L, TimeUnit.MILLISECONDS)
 .take(10)
 .concatWith(
 Observable
 .interval(200L, TimeUnit.MILLISECONDS)
 )
 );
subscribePrint(data, "Too many lines");
```

*采样* `Observable` 实例在前两秒每 100 毫秒发出一次，然后开始每 200 毫秒发出一次。*data* `Observable` 实例放弃了所有项目，直到 *sampling* 发出。当这种情况发生时，*data* `Observable` 实例发出的最后一个项目被传递。因此，我们有很大的数据丢失，但更难遇到 `MissingBackpressureException` 异常（尽管有可能遇到）。

`sample()` 操作符有两个额外的重载，可以传递时间间隔、`TimeUnit` 度量和可选的 `Scheduler` 实例：

```java
data = data.sample(
 100L,
 TimeUnit.MILLISECONDS
);
```

使用 `sample()` 操作符与 `Observable` 实例可以更详细地控制数据流。`throttleLast()` 操作符只是 `sample()` 操作符的不同版本的别名，它接收时间间隔。`throttleFirst()` 操作符与 `throttleLast()` 操作符相同，但 *source* `Observable` 实例将在间隔开始时发出它发出的第一个项目，而不是最后一个。这些操作符默认在 *computation* 调度程序上运行。

这些技术在有多个相似事件时非常有用（以及本节中的大多数其他技术）。例如，如果您想捕获并对 *鼠标移动事件* 做出反应，您不需要包含所有像素位置的所有事件；您只需要其中一些。

## 防抖动

在我们之前的例子中，*防抖动* 不起作用。它的想法是仅发出在给定时间间隔内没有后续项目的项目。因此，必须在发射之间经过一些时间才能传播一些东西。因为我们 *data* `Observable` 实例中的所有项目似乎一次性发出，它们之间没有可用的间隔。因此，我们需要稍微改变示例以演示这一点。

```java
Observable<Object> sampler = Observable.create(subscriber -> {
  try {
    subscriber.onNext(0);
    Thread.sleep(100L);
    subscriber.onNext(10);
    Thread.sleep(200L);
    subscriber.onNext(20);
    Thread.sleep(150L);
    subscriber.onCompleted();
  }
  catch (Exception e) {
    subscriber.onError(e);
  }
}).repeat()
  .subscribeOn(Schedulers.computation());
data = data
  .sample(sampler)
  .debounce(150L, TimeUnit.MILLISECONDS);
```

在这里，我们使用 `sample()` 操作符与特殊的 *sampling* `Observable` 实例，以便将发射减少到发生在 100、200 和 150 毫秒的时间间隔上。通过使用 `repeat()` 操作符，我们创建了一个重复源的 *无限* `Observable` 实例，并将其设置为在 *computation* 调度程序上执行。现在我们可以使用 `debounce()` 操作符，只发出这组项目，并在它们的发出之间有 150 毫秒或更长的时间间隔。

*防抖动*，像 *节流* 一样，可以用于过滤来自过度生产的源的相似事件。一个很好的例子是自动完成搜索。我们不希望在用户输入每个字母时触发搜索；我们需要等待他/她停止输入，然后触发搜索。我们可以使用 `debounce()` 操作符，并设置一个合理的 *时间间隔*。`debounce()` 操作符有一个重载，它将 `Scheduler` 实例作为其第三个参数。此外，还有一个带有选择器返回 `Observable` 实例的重载，以更精细地控制 *数据流*。

## 缓冲和窗口操作符

这两组操作符与 `map()` 或 `flatMap()` 操作符一样是 *transforming* 操作符。它们将一系列元素转换为一个集合，这些元素的序列将作为一个元素发出。

本书不会详细介绍这些操作符，但值得一提的是，`buffer()` 操作符具有能够基于 *时间间隔*、*选择器* 和其他 `Observable` 实例收集发射的重载。它还可以配置为跳过项目。以下是使用 `buffer(int count, int skip)` 方法的示例，这是 `buffer()` 操作符的一个版本，它收集 *count* 个项目并跳过 *skip* 个项目：

```java
data = data.buffer(2, 3000);
Helpers.subscribePrint(data, "Too many lines");
```

这将输出类似于以下内容：

```java
Too many lines : ["Lorem ipsum dolor sit amet, consectetur adipiscing elit.", "Donec facilisis sollicitudin est non molestie."]
Too many lines : ["Integer nec magna ac ex rhoncus imperdiet.", "Nullam pharetra iaculis sem."]
Too many lines : ["Integer nec magna ac ex rhoncus imperdiet.", "Nullam pharetra iaculis sem."]
Too many lines : ["Nam vitae consectetur risus, vitae congue risus.", "Donec facilisis sollicitudin est non molestie."]
Too many lines : ["Sed mollis facilisis rutrum.", "Proin enim risus, congue id eros at, pharetra consectetur ex."]
Too many lines ended!

```

`window()` 操作符与 `buffer()` 操作符具有完全相同的重载集。不同之处在于，`window()` 操作符创建的 `Observable` 实例发出发出收集的元素的 `Observable` 实例，而不是缓冲元素的数组。

为了演示不同的重载，我们将使用`window(long timespan, long timeshift, TimeUnit units)`方法来举例。该操作符会收集在*timespan*时间间隔内发出的元素，并跳过在*timeshift*时间间隔内发出的所有元素。这将重复，直到源`Observable`实例完成。

```java
data = data
  .window(3L, 200L, TimeUnit.MILLISECONDS)
  .flatMap(o -> o);
subscribePrint(data, "Too many lines");
```

我们使用`flatMap()`操作符来展平`Observable`实例。结果包括在*订阅*的前三毫秒内发出的所有项，以及在 200 毫秒间隔后的三毫秒内发出的项，这将在源发出时重复。

### 注意

在前一节介绍的所有示例都可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter06/BackpressureExamples.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter06/BackpressureExamples.java)找到。

## 背压操作符

最后一组操作符可以防止`MissingBackpressureException`异常，当有一个过度生产的*源*`Observable`实例时，它们会自动激活。

`onBackpressureBuffer()`操作符会对由快于其`Observer`实例的*源*`Observable`发出的项进行缓冲。然后以订阅者可以处理的方式发出缓冲的项。例如：

```java
Helpers.subscribePrint(
  data.onBackpressureBuffer(10000),
  "onBackpressureBuffer(int)"
);
```

在这里，我们使用了一个大容量的缓冲区，因为元素数量很大，但请注意，溢出此缓冲区将导致`MissingBackpressureException`异常。

`onBackpressureDrop()`操作符会丢弃所有来自*源*`Observable`实例的无法被订阅者处理的传入项。

有一种方法可以通过实现智能的 Observables 或 Subscribers 来建立*背压*，但这个话题超出了本书的范围。在 RxJava 维基页面上有一篇关于*背压*和 observable 的优秀文章—[`github.com/ReactiveX/RxJava/wiki/Backpressure`](https://github.com/ReactiveX/RxJava/wiki/Backpressure)。本节中提到的许多操作符在那里都有详细描述，并且有大理石图可用于帮助您理解更复杂的操作符。

# 总结

在本章中，我们学习了如何在与*主*线程不同的其他线程上执行我们的 observable 逻辑。有一些简单的规则和技术可以做到这一点，如果一切都按照规定进行，就不应该有危险。使用这些技术，我们能够编写*并发*程序。我们还学习了如何使用调度程序和`flatMap()`操作符实现*并行*执行，并且看到了一个真实世界的例子。

我们还研究了如何处理*过度生产*的数据源。有许多操作符可以通过不同的方式来做到这一点，我们介绍了其中一些，并讨论了它们的有用性。

有了这些知识，我们可以编写任意的 RxJava 程序，能够处理来自不同源的数据。我们知道如何使用多个线程来做到这一点。使用 RxJava、它的操作符和*构造*几乎就像使用一种新语言编码。它有自己的规则和流程控制方法。

为了编写稳定的应用程序，我们必须学会如何对它们进行*单元测试*。测试*异步*代码并不是一件容易的事情。好消息是，RxJava 提供了一些操作符和类来帮助我们做到这一点。您可以在下一章中了解更多信息。


# 第七章：测试您的 RxJava 应用程序

在编写软件时，尤其是将被许多用户使用的软件，我们需要确保一切都正常运行。我们可以编写可读性强、结构良好、模块化的代码，这将使更改和维护变得更容易。我们应该编写测试，因为每个功能都存在回归的危险。当我们已经为现有代码编写了测试时，重构它就不会那么困难，因为测试可以针对新的、更改过的代码运行。

几乎一切都需要进行测试和自动化。甚至有一些意识形态，如**测试驱动开发**（**TDD**）和**行为驱动开发**（**BDD**）。如果我们不编写自动化测试，我们不断变化的代码往往会随着时间的推移而变得更加难以测试和维护。

在本章中，我们不会讨论为什么需要测试我们的代码。我们将接受这是强制性的，并且是作为程序员生活的一部分。我们将学习如何测试使用 RxJava 编写的代码。

我们将看到编写它的单元测试并不那么困难，但也有一些难以测试的情况，比如*异步*`Observable`实例。我们将学习一些新的操作符，这些操作符将帮助我们进行测试，以及一种新的`Observable`实例。

说到这里，这一章我们将涵盖以下内容：

+   通过`BlockingObservable`类和*聚合*操作测试`Observable`实例

+   使用`TestSubscriber`实例进行深入测试

+   `TestScheduler`类和测试*异步*`Observable`实例

# 使用简单订阅进行测试

我们可以通过简单订阅*源*`Observable`实例并收集所有传入的通知来测试我们得到的内容。为了演示这一点，我们将开发一个用于创建新`Observable`实例并测试其行为的`factory`方法。

该方法将接收一个`Comparator`实例和多个项目，并将返回`Observable`实例，按排序顺序发出这些项目。项目将根据传递的`Comparator`实例进行排序。

我们可以使用 TDD 来开发这个方法。让我们首先定义测试如下：

```java
public class SortedObservableTest {
  private Observable<String> tested;
  private List<String> expected;
  @Before
  public void before() {
    tested = CreateObservable.<String>sorted(
 (a, b) -> a.compareTo(b),
 "Star", "Bar", "Car", "War", "Far", "Jar");
    expected = Arrays.asList(
      "Bar", "Car", "Far", "Jar", "Star", "War"
    );
  }
  TestData data = new TestData();
  tested.subscribe(
    (v) -> data.getResult().add(v),
    (e) -> data.setError(e),
    () -> data.setCompleted(true)
  );
  Assert.assertTrue(data.isCompleted());
  Assert.assertNull(data.getError());
  Assert.assertEquals(expected, data.getResult());
}
```

### 注意

本章的示例使用**JUnit**框架进行测试。您可以在[`junit.org`](http://junit.org)了解更多信息。

该测试使用两个变量来存储预定义的可重用状态。第一个是我们用作源的`Observable`实例—被测试的。在设置`@Before`方法中，它被分配给我们的方法`CreateObservable.sorted(Comparator, T...)`的结果，该方法尚未实现。我们比较一组`String`实例，并期望它们按照*预期*变量中存储的顺序接收—第二个可重用字段。

测试本身相当冗长。它使用`TestData`类的一个实例来存储来自*被测试*`Observable`实例的通知。

如果有一个`OnCompleted`通知，`data.completed`字段将设置为`True`。我们期望这种情况发生，这就是为什么我们在测试方法的最后进行断言。如果有一个`OnError`通知，`data.error`字段将设置为错误。我们不希望发生这种情况，所以我们断言它为`null`。

由`Observable`实例发出的每个传入项目都将添加到`data.resultList`字段中。最后，它应该等于*预期*的`List`变量，我们对此进行断言。

### 注意

前面测试的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/test/java/com/packtpub/reactive/chapter07/SortedObservableTest.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/test/java/com/packtpub/reactive/chapter07/SortedObservableTest.java)中查看/下载——这是第一个测试方法。

然而，这个测试当然失败了，因为`CreateObservable.sorted(Comparator, T...)`方法还没有实现。让我们实现它并再次运行测试：

```java
@SafeVarargs
public static <T> Observable<T> sorted(
  Comparator<? super T> comparator,
  T... data) {
    List<T> listData = Arrays.asList(data);
    listData.sort(comparator);
  return Observable.from(listData);
}
```

就是这么简单！它只是将传递的`varargs`数组转换为一个`List`变量，并使用它的`sort()`方法与传递的`Comparator`实例对其进行排序。然后，使用`Observable.from(Iterable)`方法，我们返回所需的`Observable`实例。

### 注意

前面实现的源代码可以在以下位置找到：[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/common/CreateObservable.java#L262`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/common/CreateObservable.java#L262)。

如果现在运行测试，它将通过。这很好！我们有了我们的第一个测试！但是编写类似这样的测试需要大量的样板代码。我们总是需要这三个状态变量，我们总是需要断言相同的事情。那么像`interval()`和`timer()`方法创建的*异步*`Observable`实例呢？

有一些技术可以去除样板变量，稍后，我们将看看如何测试*异步*行为。现在，我们将介绍一种新类型的 observable。

# BlockingObservable 类

每个`Observable`实例都可以用`toBlocking()`方法转换为`BlockingObservable`实例。`BlockingObservable`实例有多个方法，它们会阻塞当前线程，直到*源*`Observable`实例发出`OnCompleted`或`OnError`通知。如果有`OnError`通知，将抛出异常（`RuntimeException`异常直接抛出，检查异常包装在`RuntimeException`实例中）。

`toBlocking()`方法本身不会阻塞，但它返回的`BlockingObservable`实例的方法可能会阻塞。让我们看一些这些方法：

+   我们可以使用`forEach()`方法迭代`BlockingObservable`实例中的所有项目。这是一个使用的例子：

```java
Observable
  .interval(100L, TimeUnit.MILLISECONDS)
  .take(5)
  .toBlocking()
 .forEach(System.out::println);
System.out.println("END");
```

这也是如何使*异步*代码表现*同步*的一个例子。`interval()`方法创建的`Observable`实例不会在后台执行，因为`toBlocking()`方法使当前线程等待直到它完成。这就是为什么我们在这里使用`take(int)`方法，否则，*主*线程将永远被*阻塞*。`forEach()`方法将使用传递的函数打印五个项目，只有在那之后我们才会看到`END`输出。`BlockingObservable`类也有一个`toIterable()`方法。它返回的`Iterable`实例也可以用于迭代源发出的序列。

+   有类似*异步*的*阻塞*方法，比如`first()`、`last()`、`firstOrDefault()`和`lastOrDefault()`方法（我们在第四章中讨论过它们，*转换、过滤和累积您的数据*）。它们在等待所需项目时都会阻塞。让我们看一下以下代码片段：

```java
Integer first = Observable
  .range(3, 13).toBlocking().first();
  System.out.println(first);
  Integer last = Observable
  .range(3, 13).toBlocking().last();
  System.out.println(last);
```

这将打印`'3'`和`'15'`。

+   一个有趣的方法是`single()`方法；当*源*发出一个项目并且*源*完成时，它只返回一个项目。如果没有发出项目，或者*源*发出多个项目，分别抛出`NoSuchElementException`异常或`IllegalArgumentException`异常。

+   有一个`next()`方法，它不会*阻塞*，而是返回一个`Iterable`实例。当从这个`Iterable`实例中检索到一个`Iterator`实例时，它的每个`next()`方法都会*阻塞*，同时等待下一个传入的项目。这可以用于无限的`Observable`实例，因为*当前线程*只会在等待*下一个*项目时*阻塞*，然后它就可以继续了。（请注意，如果没有人及时调用`next()`方法，源元素可能会被跳过）。这是一个使用的例子：

```java
Iterable<Long> next = Observable
  .interval(100L, TimeUnit.MILLISECONDS)
  .toBlocking()
 .next();
Iterator<Long> iterator = next.iterator();
System.out.println(iterator.next());
System.out.println(iterator.next());
System.out.println(iterator.next());
```

*当前线程*将*阻塞*3 次，每次 100 毫秒，然后在每次暂停后打印`0`，`1`和`2`。还有一个类似的方法叫做`latest()`，它返回一个`Iterable`实例。行为不同，因为`latest()`方法产生的`Iterable`实例返回源发出的最后一个项目，或者如果没有，则等待下一个项目。

```java
Iterable<Long> latest = Observable
  .interval(1000L, TimeUnit.MILLISECONDS)
  .toBlocking()
 .latest();
iterator = latest.iterator();
System.out.println(iterator.next());
Thread.sleep(5500L);
System.out.println(iterator.next());
System.out.println(iterator.next());
```

这将打印`0`，然后`5`和`6`。

### 注意

展示所有前述运算符以及聚合运算符的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter07/BlockingObservablesAndOperators.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter07/BlockingObservablesAndOperators.java)中查看/下载。

使用`BlockingObservable`实例可以帮助我们收集我们的测试数据。但是还有一组称为**聚合运算符**的`Observable`运算符，当与`BlockingObservables`实例结合使用时也很有用。

# 聚合运算符和 BlockingObservable 类

聚合运算符产生的`Observable`实例只发出一个项目并完成。这个项目是由*source* `Observable`实例发出的所有项目组成或计算得出的。在本节中，我们只讨论其中的两个。有关更详细的信息，请参阅[`github.com/ReactiveX/RxJava/wiki/Mathematical-and-Aggregate-Operators`](https://github.com/ReactiveX/RxJava/wiki/Mathematical-and-Aggregate-Operators)。

其中第一个运算符是`count()`或`countLong()`方法。它发出*source* `Observable`实例发出的项目数。例如：

```java
Observable
  .range(10, 100)
  .count()
  .subscribe(System.out::println);
```

这将打印`100`。

另一个是`toList()`或`toSortedList()`方法，它发出一个包含*source* `Observable`实例发出的所有项目的`list`变量（可以排序）并完成。

```java
List<Integer> list = Observable
  .range(5, 15)
  .toList()
  .subscribe(System.out::println);
```

这将输出以下内容：

```java
[5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]
```

所有这些方法，结合`toBlocking()`方法一起很好地工作。例如，如果我们想要检索由*source* `Observable`实例发出的所有项目的列表，我们可以这样做：

```java
List<Integer> single = Observable
  .range(5, 15)
  .toList()
 .toBlocking().single();
```

我们可以根据需要使用这些项目的集合：例如用于测试。

### 提示

聚合运算符还包括一个`collect()`运算符，它可以用于生成`Observable`实例并发出任意集合，例如`Set()`运算符。

# 使用聚合运算符和 BlockingObservable 类进行测试

使用在前两节中学到的运算符和方法，我们能够重新设计我们编写的测试，使其看起来像这样：

```java
@Test
public void testUsingBlockingObservable() {
  List<String> result = tested
    .toList()
 .toBlocking()
 .single();
  Assert.assertEquals(expected, result);
}
```

这里没有样板代码。我们将所有发出的项目作为列表检索并将它们与预期的列表进行比较。

在大多数情况下，使用`BlockingObsevables`类和聚合运算符非常有用。然而，在测试*异步*`Observable`实例时，它们并不那么有用，因为它们发出长时间的慢序列。长时间阻塞测试用例不是一个好的做法：慢测试是糟糕的测试。

### 注意

前面测试的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/test/java/com/packtpub/reactive/chapter07/SortedObservableTest.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/test/java/com/packtpub/reactive/chapter07/SortedObservableTest.java)找到-这是第二个测试方法。

另一个这种测试方法不太有用的情况是当我们想要检查*source*发送的`Notification`对象或订阅状态时。

还有一种编写测试的技术，可以更精细地控制*订阅*本身，这是通过一个特殊的`Subscriber`-`TestSubscriber`。

# 使用 TestSubscriber 类进行深入测试

`TestSubscriber`实例是一个特殊的`Subscriber`实例，我们可以将其传递给任何`Observable`实例的`subscribe()`方法。

我们可以从中检索所有接收到的项目和通知。我们还可以查看接收到通知的最后一个`thread`和订阅状态。

让我们使用它来重写我们的测试，以展示它的功能和存储的内容：

```java
@Test
public void testUsingTestSubscriber() {
  TestSubscriber<String> subscriber =
 new TestSubscriber<String>();
  tested.subscribe(subscriber);
  Assert.assertEquals(expected, subscriber.getOnNextEvents());
  Assert.assertSame(1, subscriber.getOnCompletedEvents().size());
  Assert.assertTrue(subscriber.getOnErrorEvents().isEmpty());
  Assert.assertTrue(subscriber.isUnsubscribed());
}
```

测试是非常简单的。我们创建一个`TestSubscriber`实例，并使用它*订阅*了*被测试的*`Observable`实例。在`Observable`实例*完成*后，我们可以访问整个状态。让我们来看一下以下的术语列表：

+   通过`getOnNextEvents()`方法，我们能够检索`Observable`实例发出的所有项目，并将它们与*expected*`List`变量进行比较。

+   通过`getOnCompletedEvents()`方法，我们能够检查*OnCompleted*通知，并检查是否已发送。例如，`Observable.never()`方法不会发送它。

+   通过`getOnErrorEvents()`方法，我们能够检查*OnError*通知是否存在。在这种情况下，我们*assert*没有*errors*。

+   使用`isUnsubscribed()`方法，我们可以*assert*在一切*完成*后，我们的`Subscriber`实例已被*unsubscribed*。

`TestSubscriber`实例也有一些*assertion*方法。因此，还有一种测试的方法：

```java
@Test
public void testUsingTestSubscriberAssertions() {
  TestSubscriber<String> subscriber = new TestSubscriber<String>();
  tested.subscribe(subscriber);
 subscriber.assertReceivedOnNext(expected);
 subscriber.assertTerminalEvent();
 subscriber.assertNoErrors();
 subscriber.assertUnsubscribed();
}
```

这些几乎是相同的*assertions*，但是使用`TestSubscriber`实例自己的`assert*`方法完成。

### 注意

前面测试的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/test/java/com/packtpub/reactive/chapter07/SortedObservableTest.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/test/java/com/packtpub/reactive/chapter07/SortedObservableTest.java)找到-这是第三和第四个测试方法。

通过这些技术，我们可以测试`RxJava`逻辑的不同行为和状态。在本章中还有一件事要学习-测试*异步*`Observable`实例，例如`Observable.interval()`方法创建的实例。

# 使用 TestScheduler 类测试异步 Observable 实例

在第六章中我们没有提到的最后一种预定义的`scheduler`是`TestScheduler`调度程序，这是一个专为单元测试设计的`scheduler`。在它上面安排的所有操作都被包装在对象中，这些对象包含它们应该执行的时间，并且在调用`Scheduler`实例的`triggerActions()`方法之前不会执行。这个方法执行所有未执行并且计划在`Scheduler`实例的当前时间或之前执行的操作。这个时间是虚拟的。这意味着它是由我们设置的，我们可以使用这个`scheduler`的特殊方法提前到未来的任何时刻。

为了演示它，我们将开发另一种创建新类型的`observable`的方法。该方法的实现本身不会在本章中讨论，但您可以在附带书籍的源代码中找到它。

该方法创建一个在设定时间间隔发出项目的`Observable`实例。但是间隔不是均匀分布的，就像内置的`interval`方法一样。我们可以提供一个不同的多个*间隔*的列表，`Observable`实例将无限循环其中。该方法的签名如下：

```java
Observable<Long> interval(List<Long> gaps, TimeUnit unit, Scheduler scheduler)
```

如果我们传递一个只包含一个时间段值的`List`变量，它的行为应该与`Observable.interval`方法相同。以下是针对这种情况的测试：

```java
@Test
public void testBehavesAsNormalIntervalWithOneGap() {
  TestScheduler testScheduler = Schedulers.test(); // (1)
  Observable<Long> interval = CreateObservable.interval(
 Arrays.asList(100L), TimeUnit.MILLISECONDS, testScheduler
 ); // (2)
  TestSubscriber<Long> subscriber = new TestSubscriber<Long>();
  interval.subscribe(subscriber); // (3)
  assertTrue(subscriber.getOnNextEvents().isEmpty()); // (4)
  testScheduler.advanceTimeBy(101L, TimeUnit.MILLISECONDS); // (5)
  assertEquals(Arrays.asList(0L), subscriber.getOnNextEvents());
  testScheduler.advanceTimeBy(101L, TimeUnit.MILLISECONDS); // (6)
  assertEquals(
    Arrays.asList(0L, 1L),
    subscriber.getOnNextEvents()
  );
  testScheduler.advanceTimeTo(1L, TimeUnit.SECONDS); // (7)
  assertEquals(
    Arrays.asList(0L, 1L, 2L, 3L, 4L, 5L, 6L, 7L, 8L, 9L),
    subscriber.getOnNextEvents()
  );
}
```

让我们来看一下以下的解释：

1.  我们使用`Schedulers.test()`方法创建`TestScheduler`实例。

1.  我们的方法的第三个参数是一个`Scheduler`实例。它将在其上*发出项目*，因此我们传递我们的`TestScheduler`实例。

1.  使用`TestSubscriber`实例，我们*订阅*了`Observable`实例。

1.  订阅后立即，我们不应该有任何通知，因此我们要检查一下。

1.  `TestScheduler`实例有一个`advanceTimeBy(long, TimeUnit)`方法，它控制其`Worker`实例的时间，因此我们可以使用它将时间推进 101 毫秒。101 毫秒后，我们期望收到一个项目——`0`。

1.  使用`advanceTimeBy()`方法，我们将时间推进 101 毫秒，然后我们应该已经收到了`0`和`1`。

1.  `TestScheduler`实例的另一个重要方法是`advanceTimeTo(long, TimeUnit)`方法。它可以用来推进到未来的特定时间点。因此，我们使用它来到达从*订阅*开始过去一秒的时刻。我们期望到那时已经收到了十个通知。

`TestScheduler`实例使用其`advanceTimeBy()`和`advanceTimeTo()`方法来控制时间，因此我们不需要*阻塞**主*`Thread`实例等待某些事件发生。我们可以直接到达它已经发生的时间。使用`TestScheduler`实例，有一个全局事件顺序。因此，如果两个任务被安排在完全相同的时间，它们有一个将执行的顺序，并且可能会导致测试出现问题，因为测试期望特定的全局顺序。如果我们有这样的操作符需要测试，我们应该通过定时到不同的值来避免这种情况——一个是 100 毫秒，另一个是 101 毫秒。使用这种技术，测试*异步*`Observable`实例不再是一个复杂的任务。

### 注意

前面测试的源代码可以在以下链接找到：[`github.com/meddle0x53/learning-rxjava/blob/master/src/test/java/com/packtpub/reactive/chapter07/CreateObservableIntervalTest.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/test/java/com/packtpub/reactive/chapter07/CreateObservableIntervalTest.java)。

# 总结

通过本章，我们不仅了解了如何使用 RxJava 编写程序，还了解了如何测试它们的任何方面。我们还学习了一些新的操作符和`BlockingObservables`类。

RxJava 库有许多在本书中未提及的操作符，但我们已经学习了更重要和有用的操作符。您可以随时参考[`github.com/ReactiveX/RxJava/wiki`](https://github.com/ReactiveX/RxJava/wiki)了解其余部分。关于*订阅*、*背压*和`Observable`实例的*生命周期*还有更多内容，但是凭借您目前的知识，掌握库中的一切不会很难。请记住，这只是一个库，一个编写代码的工具。逻辑才是重要的。这种编程方式与过程式编程有些不同，但一旦您掌握了它，就会觉得自然。

在下一章中，我们将学习如何释放*订阅*分配的资源，如何防止内存泄漏，以及如何创建我们自己的操作符，这些操作符可以在`RxJava`逻辑中链接。


# 第八章：资源管理和扩展 RxJava

通过前面的章节，我们已经学会了如何使用 RxJava 的可观察对象。我们已经使用了许多不同的操作符和`工厂`方法。`工厂`方法是各种具有不同行为和发射源的`Observable`实例的来源。另一方面，使用操作符，我们已经围绕这些可观察对象构建了复杂的逻辑。

在本章中，我们将学习如何创建我们自己的`工厂`方法，这些方法将能够管理它们的源资源。为了做到这一点，我们需要一种管理和释放资源的方法。我们已经创建并使用了多种类似的方法，包括源文件、HTTP 请求、文件夹或内存中的数据。但其中一些并没有清理它们的资源。例如，HTTP 请求可观察对象需要一个`CloseableHttpAsyncClient`实例；我们创建了一个接收它并将其管理留给用户的方法。现在是时候学习如何自动管理和清理我们的源数据，封装在我们的`工厂`方法中了。

我们也将学习如何编写我们自己的操作符。Java 不是一种动态语言，这就是为什么我们不会将操作符添加为`Observable`类的方法。有一种方法可以将它们插入到可观察的操作链中，我们将在本章中看到。

本章涵盖的主题有：

+   使用`using()`方法进行资源管理

+   使用*高阶* `lift()` 操作符创建自定义操作符

+   使用`compose`创建操作符的组合

# 资源管理

如果我们回顾一下我们在第六章中使用的 HTTP 请求方法，*使用调度程序进行并发和并行处理*和第五章中使用的 HTTP 请求方法，它的签名是：`Observable<Map> requestJson(HttpAsyncClient client, String url)`。

我们不仅仅是调用一个方法，该方法向 URL 发出请求并将响应作为 JSON 返回，我们创建了一个`HttpAsyncClient`实例，必须启动它并将其传递给`requestJson()`方法。但还有更多：我们需要在读取结果后关闭*客户端*，因为可观察是*异步*的，我们需要等待它的`OnCompleted`通知，然后关闭它。这非常复杂，应该进行更改。从文件中读取的`Observable`需要在所有订阅者*取消订阅*后创建流/读取器/通道并关闭它们。从数据库中发出数据的`Observable`应该在读取完成后设置并关闭所有连接、语句和结果集。对于`HttpAsyncClient`对象也是如此。它是我们用来打开与远程服务器的连接的资源；我们的可观察对象应该在一切都被读取并且所有订阅者不再订阅时清理它。

让我们回答一个问题：为什么`requestJson()`方法需要这个`HttpAsyncClient`对象？答案是我们使用了一个 RxJava 模块进行 HTTP 请求。其代码如下：

```java
ObservableHttp
  .createGet(url, client)
  .toObservable();
```

这段代码创建了请求，代码需要客户端，所以我们需要客户端来创建我们的`Observable`实例。我们不能改变这段代码，因为改变它意味着要自己编写 HTTP 请求，这样不好。已经有一个库可以为我们做这件事。我们需要使用一些东西，在*订阅*时提供`HttpAsyncClient`实例，并在*取消订阅*时释放它。有一个方法可以做到这一点：`using()`工厂方法。

## 介绍`Observable.using`方法

`Observable.using`方法的签名如下：

```java
public final static <T, Resource> Observable<T> using(
  final Func0<Resource> resourceFactory,
  final Func1<? super Resource, ? extends Observable<? extends T>> observableFactory,
  final Action1<? super Resource> disposeAction
)
```

这看起来相当复杂，但仔细看一下就不难理解了。让我们来看一下以下描述：

+   它的第一个参数是 `Func0<Resource> resourceFactory`，一个创建 `Resource` 对象的函数（这里 `Resource` 是一个任意对象；它不是接口或类，而是类型参数的名称）。我们的工作是实现资源的创建。

+   `Func1<? super Resource, ? extends Observable<? extends T>> observableFactory` 参数，第二个参数，是一个接收 `Resource` 对象并返回 `Observable` 实例的函数。这个函数将使用我们已经通过第一个参数创建的 `Resource` 对象进行调用。我们可以使用这个资源来创建我们的 `Observable` 实例。

+   `Action1<? super Resource> disposeAction` 参数在应该处理 `Resource` 对象时被调用。它接收了由 `resourceFactory` 参数创建的 `Resource` 对象（并用于创建 `Observable` 实例），我们的工作是处理它。这在*取消订阅*时被调用。

我们能够创建一个函数，进行 HTTP 请求，而现在不需要传递 `HttpAsyncClient` 对象。我们有工具可以根据需要创建和处理它。让我们来实现这个函数：

```java
// (1)
public Observable<ObservableHttpResponse> request(String url) {
  Func0<CloseableHttpAsyncClient> resourceFactory = () -> {
    CloseableHttpAsyncClient client = HttpAsyncClients.createDefault(); // (2)
 client.start();
    System.out.println(
      Thread.currentThread().getName() +
      " : Created and started the client."
    );
    return client;
  };
  Func1<HttpAsyncClient, Observable<ObservableHttpResponse>> observableFactory = (client) -> { // (3)
    System.out.println(
      Thread.currentThread().getName() + " : About to create Observable."
    );
    return ObservableHttp.createGet(url, client).toObservable();
  };
  Action1<CloseableHttpAsyncClient> disposeAction = (client) -> {
    try { // (4)
      System.out.println(
        Thread.currentThread().getName() + " : Closing the client."
      );
      client.close();
    }
    catch (IOException e) {}
  };
  return Observable.using( // (5)
 resourceFactory,
 observableFactory,
 disposeAction
 );
}
```

这个方法并不难理解。让我们来分解一下：

1.  该方法的签名很简单；它只有一个参数，`URL`。调用该方法的调用者不需要创建和管理 `CloseableHttpAsyncClient` 实例的生命周期。它返回一个能够发出 `ObservableHttpResponse` 响应并*完成*的 `Observable` 实例。`getJson()` 方法可以使用它将 `ObservableHttpResponse` 响应转换为表示 JSON 的 `Map` 实例，而无需传递 *client*。

1.  `resourceFactory` lambda 很简单；它创建了一个默认的 `CloseableHttpAsyncClient` 实例并启动它。当被调用时，它将返回一个初始化的 HTTP *client*，能够请求远程服务器数据。我们输出 *client* 已准备好用于调试目的。

1.  `observableFactory` 函数可以访问由 `resourceFactory` 函数创建的 `CloseableHttpAsyncClient` 实例，因此它使用它和传递的 `URL` 来构造最终的 `Observable` 实例。这是通过 RxJava 的 `rxjava-apache-http` 模块 API（[`github.com/ReactiveX/RxApacheHttp`](https://github.com/ReactiveX/RxApacheHttp)）完成的。我们输出我们正在做的事情。

1.  `disposeAction` 函数接收了用于创建 `Observable` 实例的 `CloseableHttpAsyncClient` 对象并对其进行*关闭*。同样，我们打印一条消息到标准输出，说明我们即将这样做。

1.  借助 `using()` 工厂方法，我们返回我们的 HTTP *request* `Observable` 实例。这不会触发任何三个 lambda 中的任何一个。订阅返回的 `Observable` 实例将调用 `resourceFactory` 函数，然后调用 `observableFactory` 函数。

这就是我们实现了一个能够管理自己资源的 `Observable` 实例。让我们看看它是如何使用的：

```java
String url = "https://api.github.com/orgs/ReactiveX/repos";

Observable<ObservableHttpResponse> response = request(url);

System.out.println("Not yet subscribed.");

Observable<String> stringResponse = response
.<String>flatMap(resp -> resp.getContent()
.map(bytes -> new String(bytes, java.nio.charset.StandardCharsets.UTF_8))
.retry(5)

.map(String::trim);

System.out.println("Subscribe 1:");
System.out.println(stringResponse.toBlocking().first());

System.out.println("Subscribe 2:");
System.out.println(stringResponse.toBlocking().first());
```

我们使用新的 `request()` 方法来列出 *ReactiveX* *组织*的存储库。我们只需将 URL 传递给它，就会得到一个 `Observable` 响应。在我们订阅它之前，不会分配任何资源，也不会执行任何请求，所以我们打印出你还没有订阅。

`stringResponse` 可观察对象包含逻辑并将原始的 `ObservableHttpResponse` 对象转换为 `String`。但是，没有分配任何资源，也没有发送请求。

我们使用 `BlockingObservable` 类的 `first()` 方法订阅 `Observable` 实例并等待其结果。我们将响应作为 `String` 检索并输出它。现在，资源已分配并发出了请求。在获取数据后，`BlockingObservable` 实例封装的 `subscriber` 会自动取消订阅，因此使用的资源（HTTP 客户端）被处理掉。我们进行第二次订阅，以查看接下来会发生什么。

让我们来看一下这个程序的输出：

```java
Not yet subscribed.
Subscribe 1:
main : Created and started the client.
main : About to create Observable.
[{"id":7268616,"name":"Rx.rb","full_name":"ReactiveX/Rx.rb",...
Subscribe 2:
I/O dispatcher 1 : Closing the client.
main : Created and started the client.
main : About to create Observable.
I/O dispatcher 5 : Closing the client.
[{"id":7268616,"name":"Rx.rb","full_name":"ReactiveX/Rx.rb",...

```

因此，当我们订阅网站时，HTTP 客户端和`Observable`实例是使用我们的工厂 lambda 创建的。创建在当前主线程上执行。发出请求并打印（此处裁剪）。客户端在 IO 线程上被处理，当`Observable`实例完成执行时，请求被执行。

第二次订阅时，我们从头开始经历相同的过程；我们分配资源，创建`Observable`实例并处理资源。这是因为`using()`方法的工作方式——它为每个订阅分配一个资源。我们可以使用不同的技术来重用下一次订阅的相同结果，而不是进行新的请求和分配资源。例如，我们可以为多个订阅者重用`CompositeSubscription`方法或`Subject`实例。然而，有一种更简单的方法可以重用下一次订阅的获取响应。

# 使用 Observable.cache 进行数据缓存

我们可以使用缓存将响应缓存在内存中，然后在下一次订阅时，而不是再次请求远程服务器，使用缓存的数据。

让我们将代码更改为如下所示：

```java
String url = "https://api.github.com/orgs/ReactiveX/repos";
Observable<ObservableHttpResponse> response = request(url);

System.out.println("Not yet subscribed.");
Observable<String> stringResponse = response
.flatMap(resp -> resp.getContent()
.map(bytes -> new String(bytes)))
.retry(5)
.cast(String.class)
.map(String::trim)
.cache();

System.out.println("Subscribe 1:");
System.out.println(stringResponse.toBlocking().first());

System.out.println("Subscribe 2:");
System.out.println(stringResponse.toBlocking().first());
```

在`stringResponse`链的末尾调用的`cache()`操作符将为所有后续的`subscribers`缓存由`string`表示的响应。因此，这次的输出将是：

```java
Not yet subscribed.
Subscribe 1:
main : Created and started the client.
main : About to create Observable.
[{"id":7268616,"name":"Rx.rb",...
I/O dispatcher 1 : Closing the client.
Subscribe 2:
[{"id":7268616,"name":"Rx.rb",...

```

现在，我们可以在程序中重用我们的`stringResponse` `Observable`实例，而无需进行额外的资源分配和请求。

### 注意

演示源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter08/ResourceManagement.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter08/ResourceManagement.java)找到。

最后，`requestJson()`方法可以这样实现：

```java
public Observable<Map> requestJson(String url) {
Observable<String> rawResponse = request(url)

....

return Observable.amb(fromCache(url), response);
}
```

更简单，具有资源自动管理（资源，即 http 客户端会自动创建和销毁），该方法还实现了自己的缓存功能（我们在第五章中实现了它，*组合器、条件和错误处理*）。

### 注意

书中开发的所有创建`Observable`实例的方法都可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/common/CreateObservable.java 类`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/common/CreateObservable.java 类)中找到。那里还有一个`requestJson()`方法的文件缓存实现。

有了这个，我们可以扩展 RxJava，创建自己的工厂方法，使`Observable`实例依赖于任意数据源。

本章的下一部分将展示如何将我们自己的逻辑放入`Observable`操作符链中。

# 使用 lift 创建自定义操作符

在学习和使用了许多不同的操作符之后，我们已经准备好编写自己的操作符。`Observable`类有一个名为`lift`的操作符。它接收`Operator`接口的实例。这个接口只是一个空的接口，它扩展了`Func1<Subscriber<? super R>, Subscriber<? super T>>`接口。这意味着我们甚至可以将 lambda 作为操作符传递。

学习如何使用`lift`操作符的最佳方法是编写一个示例。让我们创建一个操作符，为发出的每个项目添加一个顺序索引（当然，这也可以在没有专用操作符的情况下完成）。这样，我们将能够生成带有索引的项目。为此，我们需要一个存储项目及其索引的类。让我们创建一个更通用的称为`Pair`的类：

```java
public class Pair<L, R> {
  final L left;
  final R right;

public Pair(L left, R right) {
    this.left = left;
    this.right = right;
  }

  public L getLeft() {
    return left;
  }

public R getRight() {
    return right;
  }

  @Override
  public String toString() {
    return String.format("%s : %s", this.left, this.right);
  }

// hashCode and equals omitted

}'
```

这个类的实例是非常简单的*不可变*对象，包含两个任意对象。在我们的例子中，*left*字段将是类型为`Long`的索引，*right*字段将是发射的项。`Pair`类，和任何*不可变*类一样，包含了`hashCode()`和`equals()`方法的实现。

以下是运算符的代码：

```java
public class Indexed<T> implements Operator<Pair<Long, T>, T> {
  private final long initialIndex;
  public Indexed() {
    this(0L);
  }
  public Indexed(long initial) {
    this. initialIndex = initial;
  }
  @Override
  public Subscriber<? super T> call(Subscriber<? super Pair<Long, T>> s) {
 return new Subscriber<T>(s) {
      private long index = initialIndex;
 @Override
 public void onCompleted() {
 s.onCompleted();
 }
 @Override
 public void onError(Throwable e) {
 s.onError(e);
 }
 @Override
 public void onNext(T t) {
 s.onNext(new Pair<Long, T>(index++, t));
 }
 };
 }
}
```

`Operator`接口的`call()`方法有一个参数，一个`Subscriber`实例。这个实例将订阅由`lift()`运算符返回的可观察对象。该方法返回一个新的`Subscriber`实例，它将订阅调用了`lift()`运算符的可观察对象。我们可以在其中更改所有通知的数据，这就是我们将编写我们自己运算符逻辑的方式。

`Indexed`类有一个状态——`index`。默认情况下，它的初始值是`0`，但是有一个*构造函数*可以创建一个具有任意初始值的`Indexed`实例。我们的运算符将`OnError`和`OnCompleted`通知无修改地委托给订阅者。有趣的方法是`onNext()`。它通过创建一个`Pair`实例和`index`字段的当前值来修改传入的项。之后，`index`被递增。这样，下一个项将使用递增的`index`并再次递增它。

现在，我们有了我们的第一个运算符。让我们编写一个单元测试来展示它的行为：

```java
@Test
public void testGeneratesSequentialIndexes() {
  Observable<Pair<Long, String>> observable = Observable
    .just("a", "b", "c", "d", "e")
    .lift(new Indexed<String>());
  List<Pair<Long, String>> expected = Arrays.asList(
    new Pair<Long, String>(0L, "a"),
    new Pair<Long, String>(1L, "b"),
    new Pair<Long, String>(2L, "c"),
    new Pair<Long, String>(3L, "d"),
    new Pair<Long, String>(4L, "e")
  );
  List<Pair<Long, String>> actual = observable
    .toList()
    .toBlocking().
    single();
  assertEquals(expected, actual);
  // Assert that it is the same result for a second subscribtion.
  TestSubscriber<Pair<Long, String>> testSubscriber = new TestSubscriber<Pair<Long, String>>();
  observable.subscribe(testSubscriber);
  testSubscriber.assertReceivedOnNext(expected);
}
```

测试发射从`'a'`到`'e'`的字母，并使用`lift()`运算符将我们的`Indexed`运算符实现插入到可观察链中。我们期望得到一个由从零开始的顺序数字——*索引*和字母组成的五个`Pair`实例的列表。我们使用`toList().toBlocking().single()`技术来检索实际发射项的列表，并断言它们是否等于预期的发射。因为`Pair`实例有定义了`hashCode()`和`equals()`方法，我们可以比较`Pair`实例，所以测试通过了。如果我们第二次*订阅*，`Indexed`运算符应该从初始索引`0`开始提供索引。我们使用`TestSubscriber`实例来做到这一点，并断言字母被索引，从`0`开始。

### 注意

`Indexed`运算符的代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter08/Lift.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter08/Lift.java)找到，以及测试其行为的单元测试可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/test/java/com/packtpub/reactive/chapter08/IndexedTest.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/test/java/com/packtpub/reactive/chapter08/IndexedTest.java)找到。

使用`lift()`运算符和不同的`Operator`实现，我们可以编写我们自己的运算符，这些运算符作用于发射序列的每个单独项。但在大多数情况下，我们将能够在不创建新运算符的情况下实现我们的逻辑。例如，索引行为可以以许多不同的方式实现，其中一种方式是通过与`Observable.range`方法*合并*，就像这样：

```java
Observable<Pair<Long, String>> indexed = Observable.zip(
  Observable.just("a", "b", "c", "d", "e"),
  Observable.range(0, 100),
  (s, i) -> new Pair<Long, String>((long) i, s)
);
subscribePrint(indexed, "Indexed, no lift");
```

实现新的运算符有许多陷阱，比如链接订阅、支持*背压*和重用变量。如果可能的话，我们应该尝试组合现有的由经验丰富的 RxJava 贡献者编写的运算符。因此，在某些情况下，一个转换`Observable`本身的运算符是一个更好的主意，例如，将多个运算符应用于它作为一个。为此，我们可以使用*组合*运算符`compose()`。

# 使用 Observable.compose 运算符组合多个运算符

`compose()`操作符有一个`Transformer`类型的参数。`Transformer`接口，就像`Operator`一样，是一个*空*接口，它扩展了`Func1`（这种方法隐藏了使用`Func1`所涉及的类型复杂性）。不同之处在于它扩展了`Func1<Observable<T>, Observable<R>>`方法，这样它就可以转换一个`Observable`而不是一个`Subscriber`。这意味着它不是在*源*observable 发出的每个单独项目上操作，而是直接在源上操作。

我们可以通过一个例子来说明这个操作符和`Transformer`接口的使用。首先，我们将创建一个`Transformer`实现：

```java
public class OddFilter<T> implements Transformer<T, T> {
  @Override
  public Observable<T> call(Observable<T> observable) {
    return observable
      .lift(new Indexed<T>(1L))
      .filter(pair -> pair.getLeft() % 2 == 1)
      .map(pair -> pair.getRight());
  }
}
```

这个实现的思想是根据 observable 发出的顺序来过滤它们的发射。它在整个序列上操作，使用我们的`Indexed`操作符为每个项目添加一个索引。然后，它过滤具有奇数索引的`Pair`实例，并从过滤后的`Pair`实例中检索原始项目。这样，只有在奇数位置上的发射序列成员才会到达订阅者。

让我们再次编写一个*单元测试*，确保新的`OddFilter`转换器的行为是正确的：

```java
@Test
public void testFiltersOddOfTheSequence() {
  Observable<String> tested = Observable
    .just("One", "Two", "Three", "Four", "Five", "June", "July")
    .compose(new OddFilter<String>());
  List<String> expected =
    Arrays.asList("One", "Three", "Five", "July");
  List<String> actual = tested
    .toList()
    .toBlocking()
    .single();
  assertEquals(expected, actual);
}
```

正如你所看到的，我们的`OddFilter`类的一个实例被传递给`compose()`操作符，这样，它就被应用到了由`range()`工厂方法创建的 observable 上。这个 observable 发出了七个字符串。如果`OddFilter`的实现正确，它应该过滤掉在奇数位置发出的字符串。

### 注意

`OddFilter`类的源代码可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter08/Compose.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/main/java/com/packtpub/reactive/chapter08/Compose.java)找到。测试它的单元测试可以在[`github.com/meddle0x53/learning-rxjava/blob/master/src/test/java/com/packtpub/reactive/chapter08/IndexedTest.java`](https://github.com/meddle0x53/learning-rxjava/blob/master/src/test/java/com/packtpub/reactive/chapter08/IndexedTest.java)中查看/下载。

关于实现自定义操作符的更多信息可以在这里找到：[`github.com/ReactiveX/RxJava/wiki/Implementing-Your-Own-Operators`](https://github.com/ReactiveX/RxJava/wiki/Implementing-Your-Own-Operators)。如果你在 Groovy 等动态语言中使用 RxJava，你可以扩展`Observable`类以添加新方法，或者你可以使用 Xtend，这是一种灵活的 Java 方言。参考[`mnmlst-dvlpr.blogspot.de/2014/07/rxjava-and-xtend.html`](http://mnmlst-dvlpr.blogspot.de/2014/07/rxjava-and-xtend.html)。

# 总结

创建我们自己的操作符和依赖资源的`Observable`实例给了我们在围绕`Observable`类创建逻辑时无限的可能性。我们能够将每个数据源转换成一个`Observable`实例，并以许多不同的方式转换传入的数据。

我希望这本书涵盖了 RxJava 最有趣和重要的部分。如果我漏掉了重要的内容，[`github.com/ReactiveX/RxJava/wiki`](https://github.com/ReactiveX/RxJava/wiki)上的文档是网络上最好的之一。特别是在这一部分，可以找到更多阅读材料：[`github.com/ReactiveX/RxJava/wiki/Additional-Reading`](https://github.com/ReactiveX/RxJava/wiki/Additional-Reading)。

我试图将代码和想法进行结构化，并在各章节中进行小的迭代。第一章和第二章更具有意识形态性；它们向读者介绍了函数式编程和响应式编程的基本思想，第二章试图建立`Observable`类的起源。第三章为读者提供了创建各种不同`Observable`实例的方法。第四章和第五章教会我们如何围绕这些`Observable`实例编写逻辑，第六章将多线程添加到这个逻辑中。第七章涉及读者学会编写的逻辑的*单元测试*，第八章试图进一步扩展这个逻辑的能力。

希望读者发现这本书有用。不要忘记，RxJava 只是一个工具。重要的是你的知识和思维。
