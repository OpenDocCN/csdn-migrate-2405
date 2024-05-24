# Java 编程入门（四）

> 原文：[`zh.annas-archive.org/md5/C2294D9F4E8891D4151421288379909B`](https://zh.annas-archive.org/md5/C2294D9F4E8891D4151421288379909B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：控制流语句

本章描述了一种特定类型的 Java 语句，称为控制语句，它允许根据实现的算法的逻辑构建程序流程，其中包括选择语句、迭代语句、分支语句和异常处理语句。

在本章中，我们将涵盖以下主题：

+   什么是控制流？

+   选择语句：`if`、`if....else`、`switch...case`

+   迭代语句：`for`、`while`、`do...while`

+   分支语句：`break`、`continue`、`return`

+   异常处理语句：`try...catch...finally`、`throw`、`assert`

+   练习-无限循环

# 什么是控制流？

Java 程序是一系列可以执行并产生一些数据或/和启动一些操作的语句。为了使程序更通用，一些语句是有条件执行的，根据表达式评估的结果。这些语句称为控制流语句，因为在计算机科学中，控制流（或控制流）是执行或评估单个语句的顺序。

按照惯例，它们被分为四组：选择语句、迭代语句、分支语句和异常处理语句。

在接下来的章节中，我们将使用术语块，它表示一系列用大括号括起来的语句。这是一个例子：

```java
{ 
  x = 42; 
  y = method(7, x); 
  System.out.println("Example"); 
}

```

一个块也可以包括控制语句-一个娃娃里面的娃娃，里面的娃娃，依此类推。

# 选择语句

选择语句组的控制流语句基于表达式的评估。例如，这是一种可能的格式：`if(expression) do something`。或者，另一种可能的格式：`if(expression) {do something} else {do something else}`。

表达式可能返回一个`boolean`值（如前面的例子）或一个可以与常量进行比较的特定值。在后一种情况下，选择语句的格式为`switch`语句，它执行与特定常量值相关联的语句或块。

# 迭代语句

迭代语句执行某个语句或块，直到达到某个条件。例如，它可以是一个`for`语句，它执行一个语句或一组值的集合的每个值，或者直到某个计数器达到预定义的阈值，或者达到其他某些条件。执行的每个循环称为迭代。

# 分支语句

分支语句允许中断当前执行流程并从当前块后的第一行继续执行，或者从控制流中的某个（标记的）点继续执行。

方法中的`return`语句也是分支语句的一个例子。

# 异常处理语句

异常是表示程序执行过程中发生的事件并中断正常执行流程的类。我们已经看到了在相应条件下生成的`NullPointerException`、`ClassCastException`和`ArrayIndexOutOfBoundsException`的示例。

Java 中的所有异常类都有一个共同的父类，即`java.lang.Exception`类，它又扩展了`java.lang.Throwable`类。这就是为什么所有异常对象都有共同的行为。它们包含有关异常条件的原因和其起源位置（类源代码的行号）的信息。

每个异常都可以被自动（由 JVM）抛出，或者由应用程序代码使用`throw`关键字。方法调用者可以使用异常语句捕获异常，并根据异常类型和它（可选地）携带的消息执行某些操作，或者让异常进一步传播到方法调用堆栈的更高层。

如果堆栈中的应用程序方法都没有捕获异常，最终将由 JVM 捕获异常，并用错误中止应用程序执行。

因此，异常处理语句的目的是生成（`throw`）和捕获异常。

# 选择语句

选择语句有四种变体：

+   `if`语句

+   `if...else`语句

+   `if...else if-...-else`语句

+   `switch...case`语句

# if

简单的`if`语句允许有条件地执行某个语句或块，仅当表达式求值结果为`true`时：

```java
if(booelan expression){
  //do something
} 
```

以下是一些例子：

```java
if(true) System.out.println("true");    //1: true
if(false) System.out.println("false");  //2:

int x = 1, y = 5;
if(x > y) System.out.println("x > y");  //3:
if(x < y) System.out.println("x < y");  //4: x < y

if((x + 5) > y) {                       //5: x + 5 > y
  System.out.println("x + 5 > y");    
  x = y;
}

if(x == y){                             //6: x == y
  System.out.println("x == y");       
}

```

语句 1 打印`true`。语句 2 和 3 什么也不打印。语句 4 打印`x < y`。语句 5 打印`x + 5 > y`。我们使用大括号创建了一个块，因为我们希望`x = y`语句仅在此`if`语句的表达式求值为`true`时执行。语句 6 打印`x == y`。我们可以避免在这里使用大括号，因为只有一个语句需要执行。我们这样做有两个原因：

+   为了证明大括号也可以与单个语句一起使用，从而形成一个语句块。

+   良好的实践是，在`if`后面总是使用大括号`{}`；这样读起来更好，并有助于避免这种令人沮丧的错误：在`if`后添加另一个语句，假设它只在表达式返回`true`时执行：

```java
       if(x > y) System.out.println("x > y"); 
       x = y;
```

但是，此代码中的语句`x = y`是无条件执行的。如果您认为这种错误并不经常发生，您会感到惊讶。

始终在`if`语句后使用大括号`{}`是一个好习惯。

正如我们已经提到的，可以在选择语句内包含选择语句，以创建更精细的控制流逻辑：

```java
if(x > y){
  System.out.println("x > y");
  if(x == 3){
    System.out.println("x == 3");
  }
  if(y == 3){
    System.out.println("y == 3");
    System.out.println("x == " + x);
  }
}
```

它可以根据逻辑要求深入（嵌套）。

# if...else

`if...else`结构允许在表达式求值为`true`时执行某个语句或块；否则，将执行另一个语句或块：

```java
if(Boolean expression){
  //do something
} else {
  //do something else
}
```

以下是两个例子：

```java
int x = 1, y = 1; 
if(x == y){                        
  System.out.println("x == y");  //prints: x == y
  x = y - 1;
} else {
  System.out.println("x != y");  
}

if(x == y){                        
  System.out.println("x == y");
} else {
  System.out.println("x != y");  //prints: x != y
}
```

当大括号`{}`被一致使用时，您可以看到阅读此代码有多容易。并且，就像简单的`if`语句的情况一样，每个块都可以有另一个嵌套块，其中包含另一个`if`语句，依此类推 - 可以有多少块和多么深的嵌套。

# if...else if-...-else

您可以使用此形式来避免创建嵌套块，并使代码更易于阅读和理解。例如，看下面的代码片段：

```java
  if(n > 5){
    System.out.println("n > 5");
  } else {
    if (n == 5) {
      System.out.println("n == 5");
    } else {
      if (n == 4) {
        System.out.println("n == 4");
      } else {
        System.out.println("n < 4");
      }
    }
  }
}
```

这些嵌套的`if...else`语句可以被以下`if...else...if`语句替换：

```java
if(n > 5){
  System.out.println("n > 5");
} else if (n == 5) {
  System.out.println("n == 5");
} else if (n == 4) {
  System.out.println("n == 4");
} else {
  System.out.println("n < 4");
}
```

这样的代码更容易阅读和理解。

如果`n < 4`时不需要执行任何操作，则可以省略最后的`else`子句：

```java
if(n > 5){
  System.out.println("n > 5");
} else if (n == 5) {
  System.out.println("n == 5");
} else if (n == 4) {
  System.out.println("n == 4");
} 
```

如果您需要针对每个特定值执行某些操作，可以编写如下：

```java
if(x == 5){
  //do something
} else if (x == 7) {
  //do something else
} else if (x == 12) {
  //do something different
} else if (x = 50) {
  //do something yet more different
} else {
  //do something completely different
}
```

但是，对于这种情况有一个专门的选择语句，称为`switch...case`，更容易阅读和理解。

# switch...case

上一节的代码示例可以表示为`switch`语句，如下所示：

```java
switch(x){
  case 5:
    //do something
    break;
  case 7:
    //do something else
    break;
  case 12:
    //do something different
    break;
  case 50:
    //do something yet more different
    break;
  default:
    //do something completely different
}
```

返回`x`变量值的表达式的类型可以是`char`、`byte`、`short`、`int`、`Character`、`Byte`、`Short`、`Integer`、`String`或`enum`类型。注意`break`关键字。它强制退出`switch...case`语句。如果没有它，接下来的语句`do something`将被执行。我们将在*分支语句*部分后面讨论`break`语句。

可以在`switch`语句中使用的类型有`char`、`byte`、`short`、`int`、`Character`、`Byte`、`Short`、`Integer`、`String`和`enum`类型。在 case 子句中设置的值必须是常量。

让我们看一个利用`switch`语句的方法：

```java
void switchDemo(int n){
  switch(n + 1){
    case 1:
      System.out.println("case 1: " + n);
      break;
    case 2:
      System.out.println("case 2: " + n);
      break;
    default:
      System.out.println("default: " + n);
      break;
  }
}
```

以下代码演示了`switch`语句的工作原理：

```java
switchDemo(0);     //prints: case1: 0
switchDemo(1);     //prints: case2: 1
switchDemo(2);     //prints: default: 2

```

与`if`语句中的`else`子句类似，如果在程序逻辑中不需要`switch`语句中的默认子句，则默认子句是不需要的：

```java
switch(n + 1){
  case 1:
    System.out.println("case 1: " + n);
    break;
  case 2:
    System.out.println("case 2: " + n);
}
```

# 迭代语句

迭代语句对于 Java 编程和选择语句一样重要。您很有可能经常看到并使用它们。每个迭代语句可以是`while`、`do...while`或`for`中的一种形式。

# while

`while`语句执行布尔表达式和语句或块，直到表达式的值评估为`false`：

```java
while (Boolean expression){
  //do something
}
```

有两件事需要注意：

+   当只有一个语句需要重复执行时，大括号`{}`是不必要的，但为了一致性和更好的代码理解，建议使用。

+   该语句可能根本不会执行（当第一个表达式评估为`false`时）

让我们看一些示例。以下循环执行打印语句五次：

```java
int i = 0;
while(i++ < 5){
  System.out.print(i + " ");   //prints: 1 2 3 4 5
}
```

注意使用的不同的打印方法：`print()`而不是`println()`。后者在打印行之后添加了一个转义序列`\n`（我们已经解释了转义序列是什么，位于第五章，*Java 语言元素和类型*），它将光标移动到下一行。

以下是调用返回某个值并累积直到达到所需阈值的方法的示例：

```java
double result = 0d;
while (result < 1d){
  result += tryAndGetValue();
  System.out.println(result);
}
```

`tryAndGetValue()` 方法非常简单和不切实际，只是为了演示目的而编写的：

```java
double tryAndGetValue(){
  return Math.random();
}
```

如果我们运行最后一个 `while` 语句，我们将看到类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/fab4ec67-c60b-4037-a459-37af35dbc04d.png)

确切的值会因运行而异，因为 `Math.random()` 方法生成大于或等于 0.0 且小于 1.0 的伪随机 `double` 值。一旦累积值等于 1.0 或超过 1.0，循环就会退出。

让这个循环变得更简单是很诱人的：

```java
double result = 0d;
while ((result += tryAndGetValue()) < 1d){
  System.out.println(result);
}
```

甚至更简单：

```java
double result = 0d;
while ((result += Math.random()) < 1d){
  System.out.println(result);
}
```

但如果我们运行最后两个 `while` 语句的变体中的任何一个，我们将得到以下内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/08d31c48-80e3-42d0-89ce-c6634ee01f5d.png)

打印的值永远不会等于或超过 1.0，因为新累积值的表达式在进入执行块之前被评估。当计算包含在表达式中而不是在执行块中时，这是需要注意的事情。

# do...while

类似于 `while` 语句，`do...while` 语句重复执行布尔表达式和语句或块，直到布尔表达式的值评估为 `false`：

```java
do {
  //statement or block
} while (Boolean expression)
```

但它在评估表达式之前首先执行语句或块，这意味着语句或块至少会被执行一次。

让我们看一些例子。以下代码执行打印语句六次（比类似的 `while` 语句多一次）：

```java
int i = 0;
do {
  System.out.print(i + " ");   //prints: 0 1 2 3 4 5
} while(i++ < 5);
```

以下代码的行为与 `while` 语句相同：

```java
double result = 0d;
do {
  result += tryAndGetValue();
  System.out.println(result);
} while (result < 1d);
```

如果我们运行此代码，我们将看到类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/7957ae0e-88ff-4d36-a4b9-9df736c28d38.png)

这是因为值在累积后被打印，然后在再次进入执行块之前评估表达式。

简化的 `do...while` 语句的行为不同。以下是一个例子：

```java
double result = 0d;
do {
  System.out.println(result);
} while ((result += tryAndGetValue()) < 1d);

```

这里是相同的代码，但没有使用 `tryAndGetValue()` 方法：

```java
double result = 0d;
do {
  System.out.println(result);
} while ((result += Math.random()) < 1d);

```

如果我们运行前两个示例中的任何一个，我们将得到以下截图中的内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/da256ca8-5d1a-4fe6-8b10-20d1f22b757a.png)

`result` 变量的初始值总是首先打印，因为在第一次评估表达式之前至少执行一次该语句。

# for

基本 `for` 语句的格式如下：

```java
for(ListInit; Boolean Expression; ListUpdate) block or statement
```

但是，我们将从最流行的、更简单的版本开始，并在稍后的*带有多个初始化器和表达式的 For*部分回到完整版本。更简单的基本 `for` 语句格式如下：

```java
for(DeclInitExpr; Boolean Expression; IncrDecrExpr) block or statement
```

这个定义由以下组件组成：

+   `DeclInitExpr` 是一个声明和初始化表达式，比如 `x = 1`，它只在 `for` 语句执行的最开始被评估一次

+   Boolean Expression 是一个布尔表达式，比如 `x < 10`，它在每次迭代开始时被评估 - 在执行块或语句之前每次都会被评估；如果结果是 `false`，`for` 语句就会终止

+   `IncrDecrExpr`是增量或递减一元表达式，如`++x`、`--x`、`x++`、`x-`，它在每次迭代结束后评估-在执行块或语句后

请注意，我们谈论的是表达式，而不是语句，尽管添加了分号，它们看起来像语句。这是因为分号在`for`语句中作为表达式之间的分隔符。让我们看一个例子：

```java
for (int i=0; i < 3; i++){
  System.out.print(i + " ");  //prints: 0 1 2
}
```

在这段代码中：

+   `int i=0`是声明和初始化表达式，仅在一开始时评估一次

+   `i < 3`是布尔表达式，在每次迭代开始时评估-在执行块或语句之前；如果结果为`false`（在这种情况下为`i >= 3`），则`for`语句的执行终止

+   `i++`是增量表达式，在执行块或语句后评估

并且，与`while`语句的情况一样，当只有一个语句需要执行时，大括号`{}`是不需要的，但最好有它们，这样代码就更一致，更容易阅读。

`for`语句中的任何表达式都不是必需的：

```java
int k = 0;
for (;;){
  System.out.print(k++ + " ");     //prints: 0 1 2
  if(k > 2) break;
}
```

但在语句声明中使用表达式更方便和常规，因此更容易理解。以下是其他示例：

```java
for (int i=0; i < 3;){
  System.out.print(i++ + " "); //prints: 0 1 2
}

for (int i=2; i > 0; i--){
  System.out.print(i + " "); //prints: 2 1
}
```

请注意，在最后一个示例中，递减运算符用于减小初始`i`值。

在使用`for`语句或任何迭代语句时，请确保达到退出条件（除非您故意创建无限循环）。这是迭代语句构建的主要关注点。

# 用于增强

正如我们已经提到的，`for`语句是访问数组组件（元素）的一种非常方便的方式：

```java
int[] arr = {21, 34, 5};
for (int i=0; i < arr.length; i++){
  System.out.print(arr[i] + " ");  //prints: 21 34 5
}
```

注意我们如何使用数组对象的公共属性`length`来确保我们已经到达了所有的数组元素。但在这种情况下，当需要遍历整个数组时，最好（更容易编写和阅读）使用以下格式的增强`for`语句：

```java
<Type> arr = ...;              //an array or any Iterable
for (<Type> a: arr){
  System.out.print(a + " ");  
}
```

从注释中可以看出，它适用于数组或实现接口`Iterable`的类。该接口具有一个`iterator()`方法，返回一个`Iterator`类的对象，该类又有一个名为`next()`的方法，允许按顺序访问类成员。我们将在第十三章中讨论这样的类，称为集合，*Java 集合*。因此，我们可以重写最后的`for`语句示例并使用增强的`for`语句：

```java
int[] arr = {21, 34, 5};
for (int a: arr){
  System.out.print(a + " ");  //prints: 21 34 5
}
```

对于实现`List`接口（`List`扩展`Iterable`）的集合类，对其成员的顺序访问看起来非常相似：

```java
List<String> list = List.of("Bob", "Joe", "Jill");
for (String s: list){
  System.out.print(s + " ");  //prints: Bob Joe Jill
}
```

但是，当不需要访问数组或集合的所有元素时，可能有其他形式的迭代语句更适合。

另外，请注意，自 Java 8 以来，许多数据结构可以生成流，允许编写更紧凑的代码，并且完全避免使用`for`语句。我们将在第十八章中向您展示如何做到这一点，*流和管道*。

# 用于多个初始化程序和表达式

现在，让我们再次回到基本的`for`语句格式。它允许使用的变化比许多程序员知道的要多得多。这不是因为缺乏兴趣或专业好奇心，而可能是因为通常不需要这种额外的功能。然而，偶尔当你阅读别人的代码或在面试中，你可能会遇到需要了解全貌的情况。因此，我们决定至少提一下。

`for`语句的完整格式建立在表达式列表周围：

```java
for(ListInit; Boolean Expression; ListUpdate) block or statement
```

这个定义由以下组件组成：

+   `ListInit`: 可包括声明列表和/或表达式列表

+   `Expression`: 布尔表达式

+   `ListUpdate`: 表达式列表

表达式列表成员，用逗号分隔，可以是：

+   **赋值**：`x = 3`

+   **前/后缀递增/递减表达式**：`++x`  `--x`  `x++`  `x--`

+   **方法调用**：`method(42)`

+   **对象创建表达式**：`new SomeClass(2, "Bob")`

以下两个`for`语句产生相同的结果：

```java
for (int i=0, j=0; i < 3 && j < 3; ++i, ++j){
  System.out.println(i + " " + j);
}
for (int x=new A().getInitialValue(), i=x == -2 ? x + 2 : 0, j=0;
  i < 3 || j < 3 ; ++i, j = i) {
  System.out.println(i + " " + j);
}
```

`getInitialValue()`方法的代码如下：

```java
class A{
  int getInitialValue(){ return -2; }
}
```

正如你所看到的，即使是这样一个简单的功能，当过多地使用多个初始化程序、赋值和表达式时，它看起来可能非常复杂甚至令人困惑。如果有疑问，保持你的代码简单易懂。有时候这并不容易，但根据我们的经验，总是可以做到的，而易于理解是良好代码质量的最重要标准之一。

# 分支语句

你已经在我们的例子中看到了分支语句`break`和`return`。我们将在本节中定义和讨论它们以及该组的第三个成员——分支语句`continue`。

# 中断和标记中断

你可能已经注意到，`break`语句对于`switch...case`选择语句能够正常工作是至关重要的（有关更多信息，请参阅`switch...case`部分）。如果包含在迭代语句的执行块中，它会立即终止`for`或`while`语句。

它在迭代语句中被广泛使用，用于在数组或集合中搜索特定元素。为了演示它的工作原理，例如，假设我们需要在社区学院的学生和教师中通过年龄和姓名找到某个人。首先创建`Person`，`Student`和`Teacher`类：

```java
class Person{
  private int age;
  private  String name;
  public Person(int age, String name) {
    this.age = age;
    this.name = name;
  }
  @Override
  public Boolean equals(Object o) {
    if (this == o) return true;
    Person person = (Person) o;
    return age == person.age &&
              Objects.equals(name, person.name);
  }
  @Override
  public String toString() {
    return "Person{age=" + age +
              ", name='" + name + "'}";
  }
}
class Student extends Person {
  private int year;

  public Student(int age, String name, int year) {
    super(age, name);
    this.year = year;
  }

  @Override
  public String toString() {
    return "Student{year=" + year +
        ", " + super.toString() + "}";
  }
}
class Teacher extends Person {
  private String subject;
  public Teacher(int age, String name, String subject) {
    super(age, name);
    this.subject = subject;
  }
  @Override
  public String toString() {
    return "Student{subject=" + subject +
           ", " + super.toString() + "}";
  }
}
```

注意，`equals()`方法只在基类`Person`中实现。我们只通过姓名和年龄来识别一个人。还要注意使用关键字`super`，它允许我们访问父类的构造函数和`toString()`方法。

假设我们被指派在社区学院数据库中查找一个人（按姓名和年龄）。因此，我们已经创建了一个`List`类型的集合，并将在其中进行迭代，直到找到匹配项：

```java
List<Person> list = 
  List.of(new Teacher(32, "Joe", "History"),
          new Student(29,"Joe", 4),
          new Student(28,"Jill", 3),
          new Teacher(33, "ALice", "Maths"));
Person personOfInterest = new Person(29,"Joe");
Person person = null;
for (Person p: list){
  System.out.println(p);
  if(p.equals(personOfInterest)){
    person = p;
    break;
  }
}
if(person == null){
  System.out.println("Not found: " + personOfInterest);
} else {
  System.out.println("Found: " + person);
}
```

如果我们运行这个程序，结果将是：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/5d1a86d0-d089-4e18-80b6-fb25ea409a53.png)

我们已经找到了我们要找的人。但是如果我们改变我们的搜索并寻找另一个人（只相差一岁）：

```java
Person personOfInterest = new Person(30,"Joe");

```

结果将是：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/61fb11ee-a3a3-4c3b-a0cc-c2228878a8f7.png)

正如你所看到的，`break`语句允许在找到感兴趣的对象时立即退出循环，从而不浪费时间在迭代整个可能相当大的集合上。

在第十八章中，*流和管道*，我们将向您展示另一种（通常更有效）搜索集合或数组的方法。但在许多情况下，迭代元素仍然是一种可行的方法。

`break`语句也可以用于在多维数据结构中搜索特定元素。假设我们需要搜索一个三维数组，并找到其元素之和等于或大于 4 的最低维度数组。这是这样一个数组的示例：

```java
int[][][] data = {
        {{1,0,2},{1,2,0},{2,1,0},{0,3,0}},
        {{1,1,1},{1,3,0},{2,0,1},{1,0,1}}};

```

我们要找的最低维度数组是`{1,3,0}`。如果第一维是`x`，第二维是`y`，那么这个数组的位置是`x=1`，`y=1`，或`[1][1]`。让我们编写一个程序来找到这个数组：

```java
int[][][] data = {
        {{1,0,2},{1,2,0},{2,1,0},{0,3,0}},
        {{1,1,1},{1,3,0},{2,0,1},{1,0,1}}};
int threshold = 4;
int x = 0, y = 0;
Boolean isFound = false;
for(int[][] dd: data){
  y = 0;
  for(int[] d: dd){
    int sum = 0;
    for(int i: d){
      sum += i;
      if(sum >= threshold){
        isFound = true;
        break;
      }
    }
    if(isFound){
      break;
    }
    y++;
  }
  if(isFound){
    break;
  }
  x++;
}
System.out.println("isFound=" + isFound + ", x=" + x + ", y=" + y); 
//prints: isFound=true, x=1, y=1
```

正如你所看到的，我们使用一个名为`isFound`的布尔变量来方便地从最内层循环中退出，一旦在内部循环中找到了期望的结果。检查`isFound`变量的值的无聊需要使 Java 作者引入了一个标签 - 一个标识符后跟着一个冒号（`:`），可以放在语句的前面。`break`语句可以利用它。以下是如何使用标签更改先前的代码：

```java
int[][][] data = {
        {{1,0,2},{1,2,0},{2,1,0},{0,3,0}},
        {{1,1,1},{1,3,0},{2,0,1},{1,0,1}}};
int threshold = 4;
int x = 0, y = 0;
Boolean isFound = false;
exit:
for(int[][] dd: data){
  y = 0;
  for(int[] d: dd){
    int sum = 0;
    for(int i: d){
      sum += i;
      if(sum >= threshold){
        isFound = true;
        break exit;
      }
    }
    y++;
  }
  x++;
}
System.out.println("isFound=" + isFound + ", x=" + x + ", y=" + y); 
//prints: isFound=true, x=1, y=1

```

我们仍然使用变量`isFound`，但仅用于报告目的。`exit:`标签允许`break`语句指定哪个语句必须停止执行。这样，我们就不需要编写检查`isFound`变量值的样板代码。

# 继续和标记继续

`continue`语句支持与`break`语句支持的功能类似。但是，它不是退出循环，而是强制退出当前迭代，所以循环继续执行。为了演示它的工作原理，让我们假设，就像前一节中`break`语句的情况一样，我们需要搜索一个三维数组，并找到其元素总和等于或大于 4 的最低维度的数组。但是这次，总和不应包括等于 1 的元素。这是数组：

```java
int[][][] data = {
        {{1,1,2},{0,3,0},{2,4,1},{2,3,2}},
        {{0,2,0},{1,3,4},{2,0,1},{2,2,2}}};
```

我们的程序应该找到以下数组：

+   `data[0][2] = {2,4,1}`, `sum = 6` (因为 1 必须被跳过)

+   `data[0][3] = {2,3,2}`, `sum = 7`

+   `data[1][1] = {1,3,4}`, `sum = 7` (因为 1 必须被跳过)

+   `data[1][3]={2,2,2}`, `sum = 6`

如果跳过 1，则其他数组元素的总和不会达到 4。

这是程序：

```java
int[][][] data = {
        {{1,1,2},{0,3,0},{2,4,1},{2,3,2}},
        {{0,2,0},{1,3,4},{2,0,1},{2,2,2}}};
int threshold = 4;
int x = 0, y;
for(int[][] dd: data){
  y = 0;
  for(int[] d: dd){
    int sum = 0;
    for(int i: d){
      if(i == 1){
        continue;
      }
      sum += i;
    }
    if(sum >= threshold){
      System.out.println("sum=" + sum + ", x=" + x + ", y=" + y);
    }
    y++;
  }
  x++;
}
```

如果我们运行它，结果将是：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/74f53e31-3c98-4c50-9dc5-ea22b18790dd.png)

如您所见，结果正如我们所期望的那样：所有元素 1 都被跳过了。

为了演示如何使用带标签的`continue`语句，让我们改变要求：不仅要跳过元素 1，还要忽略包含这样一个元素的所有数组。换句话说，我们需要找到不包含 1 并且元素的总和等于或大于 4 的数组。

我们的程序应该只找到两个数组：

+   `data[0][3] = {2,3,2}`, `sum = 7`

+   `data[1][3] = {2,2,2}`, `sum = 6`

这是实现它的代码：

```java
int[][][] data = {
        {{1,1,2},{0,3,0},{2,4,1},{2,3,2}},
        {{0,2,0},{1,3,4},{2,0,1},{2,2,2}}};
int threshold = 4;
int x = 0, y;
for(int[][] dd: data){
  y = 0;
  cont: for(int[] d: dd){
    int sum = 0;
    for(int i: d){
      if(i == 1){
        y++;
        continue cont;
      }
      sum += i;
    }
    if(sum >= threshold){
      System.out.println("sum=" + sum + ", x=" + x + ", y=" + y);
    }
    y++;
  }
  x++;
}
```

如您所见，我们添加了一个名为`cont:`的标签，并在`continue`语句中引用它，因此内部循环的当前迭代和下一个外部循环的迭代停止执行。外部循环然后继续执行下一个迭代。如果我们运行代码，结果将是：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/9e701141-fa2f-411a-8827-6e7aa41bc93e.png)

所有其他数组都被跳过，因为它们包含 1 或其元素的总和小于 4。

# 返回

`return`语句只能放在方法或构造函数中。它的功能是返回控制权给调用者，有或没有值。

在构造函数的情况下，不需要`return`语句。如果放在构造函数中，它必须是最后一条不返回值的语句：

```java
class ConstructorDemo{
  private int field;
  public ConstructorDemo(int i) {
    this.field = i;
    return;
  }
}
```

试图将`return`语句放在构造函数的最后一条语句之外，或者使其返回任何值，都会导致编译错误。

在方法的情况下，如果方法被声明为返回某种类型：

+   `return`语句是必需的

+   `return`语句必须有效地（见下面的示例）是方法的最后一条语句

+   可能有几个返回语句，但其中一个必须有效地（见下面的示例）是方法的最后一条语句，而其他的必须在选择语句内部；否则，将生成编译错误

+   如果`return`语句不返回任何内容，将导致编译错误

+   如果`return`语句返回的类型不是方法定义中声明的类型，也不是其子类型，它会导致编译错误

+   装箱、拆箱和类型扩宽是自动执行的，而类型缩窄需要类型转换

以下示例演示了`return`语句有效地成为方法的最后一条语句：

```java
public String method(int n){
  if(n == 1){
    return "One";
  } else {
    return "Not one";
  }
}
```

方法的最后一条语句是选择语句，但`return`语句是选择语句内最后执行的语句。

这是一个具有许多返回语句的方法的示例：

```java
public static String methodWithManyReturns(){
  if(true){
    return "The only one returned";
  }
  if(true){
    return "Is never reached";
  }
  return "Is never reached";
}
```

尽管在方法中，只有第一个`return`语句总是返回，但编译器不会抱怨，方法会在没有运行时错误的情况下执行。它只是总是返回一个`唯一返回的`文字。

以下是具有多个返回语句的更现实的方法示例：

```java
public Boolean method01(int n){
  if(n < 0) {
    return true;
  } else {
    return false;
  }
}

public Boolean sameAsMethod01(int n){
  if(n < 0) {
    return true;
  }
  return false;
}

public Boolean sameAsAbove(int n){
  return n < 0 ? true : false;
}

public int method02(int n){
  if(n < 0) {
    return 1;
  } else if(n == 0) {
    return 2;
  } else if (n == 1){
    return 3;
  } else {
    return 4;
  }
}
public int methodSameAsMethod02(int n){
  if(n < 0) {
    return 1;
  }
  switch(n) {
    case 0:
      return 2;
    case 1:
      return 3;
    default:
      return 4;
  }
}
```

这里有关于装箱、拆箱、类型扩宽和缩窄的示例：

```java
public Integer methodBoxing(){
  return 42;
}

public int methodUnboxing(){
  return Integer.valueOf(42);
}

public int methodWidening(){
  byte b = 42;
  return b;
}

public byte methodNarrowing(){
  int n = 42;
  return (byte)n;
}
```

我们还可以重新审视程序，该程序在教师和学生名单中寻找特定的人：

```java
List<Person> list = 
  List.of(new Teacher(32, "Joe", "History"),
          new Student(29,"Joe", 4),
          new Student(28,"Jill", 3),
          new Teacher(33, "ALice", "Maths"));
Person personOfInterest = new Person(29,"Joe");
Person person = null;
for (Person p: list){
  System.out.println(p);
  if(p.equals(personOfInterest)){
    person = p;
    break;
  }
}
if(person == null){
  System.out.println("Not found: " + personOfInterest);
} else {
  System.out.println("Found: " + person);
}
```

使用返回语句，我们现在可以创建`findPerson()`方法：

```java
Person findPerson(List<Person> list, Person personOfInterest){
  Person person = null;
  for (Person p: list){
    System.out.println(p);
    if(p.equals(personOfInterest)){
      person = p;
      break;
    }
  }
  return person;
}
```

这个方法可以这样使用：

```java
List<Person> list = List.of(new Teacher(32, "Joe", "History"),
        new Student(29,"Joe", 4),
        new Student(28,"Jill", 3),
        new Teacher(33, "ALice", "Maths"));
Person personOfInterest = new Person(29,"Joe");
Person person = findPerson(list, personOfInterest);
if(person == null){
  System.out.println("Not found: " + personOfInterest);
} else {
  System.out.println("Found: " + person);
}
```

利用新的代码结构，我们可以进一步改变`findPerson()`方法，并展示`return`语句使用的更多变化：

```java
Person findPerson(List<Person> list, Person personOfInterest){
  for (Person p: list){
    System.out.println(p);
    if(p.equals(personOfInterest)){
      return p;
    }
  }
  return null;
}
```

正如您所看到的，我们已经用返回语句替换了`break`语句。现在代码更易读了吗？一些程序员可能会说不，因为他们更喜欢只有一个`return`语句是返回结果的唯一来源。否则，他们认为，人们必须研究代码，看看是否有另一个——第三个——`return`语句，可能会返回另一个值。如果代码不那么简单，人们永远不确定是否已经识别了所有可能的返回。相反派的程序员可能会反驳说，方法应该很小，因此很容易找到所有的返回语句。但是，将方法变得很小通常会迫使创建深度嵌套的方法，这样就不那么容易理解了。这个争论可能会持续很长时间。这就是为什么我们让您自己尝试并决定您更喜欢哪种风格。

如果方法的返回类型定义为`void`：

+   不需要`return`语句

+   如果存在`return`语句，则不返回任何值

+   如果`return`语句返回一些值，会导致编译错误

+   可能有几个返回语句，但其中一个必须有效地成为方法的最后一个语句，而其他语句必须在选择语句内部；否则，将生成编译错误

为了演示没有值的`return`语句，我们将再次使用`findPerson()`方法。如果我们只需要打印结果，那么方法可以更改如下：

```java
void findPerson2(List<Person> list, Person personOfInterest){
  for (Person p: list){
    System.out.println(p);
    if(p.equals(personOfInterest)){
      System.out.println("Found: " + p);
      return;
    }
  }
  System.out.println("Not found: " + personOfInterest);
  return;  //this statement is optional
}
```

并且客户端代码看起来更简单：

```java
List<Person> list = List.of(new Teacher(32, "Joe", "History"),
        new Student(29,"Joe", 4),
        new Student(28,"Jill", 3),
        new Teacher(33, "ALice", "Maths"));
Person personOfInterest = new Person(29,"Joe");
findPerson(list, personOfInterest);
```

或者它甚至可以更紧凑：

```java
List<Person> list = List.of(new Teacher(32, "Joe", "History"),
        new Student(29,"Joe", 4),
        new Student(28,"Jill", 3),
        new Teacher(33, "ALice", "Maths"));
findPerson(list, new Person(29, "Joe");

```

与先前的讨论一样，有不同的风格将参数传递到方法中。有些人更喜欢更紧凑的代码风格。其他人则认为每个参数都必须有一个变量，因为变量的名称携带了额外的信息，有助于传达意图（比如`personOfInterest`的名称）。

这样的讨论是不可避免的，因为同样的代码必须由不同的人理解和维护，每个开发团队都必须找到适合所有团队成员需求和偏好的风格。

# 异常处理语句

正如我们在介绍中解释的那样，意外条件可能会导致 JVM 创建并抛出异常对象，或者应用程序代码可以这样做。一旦发生这种情况，控制流就会转移到异常处理`try`语句（也称为`try-catch`或`try-catch-finally`语句），如果异常是在`try`块内抛出的。这是一个捕获异常的例子：

```java
void exceptionCaught(){
  try {
    method2();
  } catch (Exception ex){
    ex.printStackTrace();
  }
}

void method2(){
  method1(null);
}

void method1(String s){
  s.equals("whatever");
}
```

方法`exceptionCaught()`调用`method2()`，`method2()`调用`method1()`并将`null`传递给它。行`s.equals("whatever")`抛出`NullPointerException`，它通过方法调用堆栈传播，直到被`exceptionCaught()`方法的`try-catch`块捕获，并打印其堆栈跟踪（哪个方法调用了哪个方法以及类的哪一行）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/67e2282b-6d05-4627-ab9f-55ae0b280afa.png)

从堆栈跟踪中，您可以看到所有涉及的方法都属于同一个类`ExceptionHandlingDemo`。从下往上阅读，您可以看到：

+   方法`main()`在`ExceptionHandlingDemo`的第 5 行调用了方法`exceptionCaught()`

+   方法`exceptionCaught()`在同一类的第 10 行调用了`method2()`

+   `method2()`在第 17 行调用了`method1()`

+   `method1()`在第 21 行抛出了`java.lang.NullpointerException`

如果我们不看代码，我们就不知道这个异常是故意抛出的。例如，`method1()`可能如下所示：

```java
void method1(String s){
  if(s == null){
    throw new NullPointerException();
  }
}
```

但通常，程序员会添加一条消息来指示问题是什么：

```java
void method1(String s){
  if(s == null){
    throw new NullPointerException("Parameter String is null");
  }
}
```

如果是这种情况，堆栈跟踪将显示一条消息：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/42776307-171b-476f-a280-ba2e3d606546.png)

但是消息并不是自定义异常的可靠指标。一些标准异常也携带自己的消息。异常包是自定义异常的更好证据，或者异常是基类之一（`java.lang.Exception`或`java.langRuntimeException`）并且其中有一条消息。例如，以下代码自定义了`RuntimeException`：

```java
void method1(String s){
  if(s == null){
    throw new RuntimeException("Parameter String is null");
  }
}
```

以下是使用此类自定义异常的堆栈跟踪：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/13e41dba-0766-4f70-9448-6c0cc91cce5a.png)

稍后我们将在*自定义异常*部分更多地讨论异常定制。

如果异常在`try...catch`块之外抛出，则程序执行将由 JVM 终止。以下是一个未被应用程序捕获的异常的示例：

```java
void exceptionNotCaught(){
  method2();
}

void method2(){
  method1(null);
}

void method1(String s){
  s.equals("whatever");
}
```

如果我们运行此代码，结果是：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/7f0cbbec-63b6-49a5-81a6-0db76a269dbc.png)

现在，让我们谈谈异常处理语句，然后再回到关于处理异常的最佳方法的讨论。

# throw

`throw`语句由关键字`throw`和`java.lang.Throwable`的变量或引用类型的值，或`null`引用组成。由于所有异常都是`java.lang.Throwable`的子类，因此以下任何一个`throw`语句都是正确的：

```java
throw new Exception("Something happened");

Exception ex = new Exception("Something happened");
throw ex;

Throwable thr = new Exception("Something happened");
throw thr;

throw null;
```

如果抛出`null`，就像在最后一条语句中一样，那么 JVM 会将其转换为`NullPointerException`，因此这两条语句是等价的：

```java
throw null;

throw new NullPointerException;
```

另外，提醒一下，包`java.lang`不需要被导入。您可以通过名称引用`java.lang`包的任何成员（接口或类），而无需使用完全限定名称（包括包名）。这就是为什么我们能够写`NullPointerException`而不导入该类，而不是使用其完全限定名称`java.lang.NullPointerException`。我们将在第十二章 *Java 标准和外部库*中查看`java.lang`包的内容。

您还可以通过扩展`Throwable`或其任何子类来创建自己的异常，并抛出它们，而不是抛出`java.lang`包中的标准异常：

```java
class MyNpe extends NullPointerException{
  public MyNpe(String message){
    super(message);
  }
  //whatever code you need to have here
}

class MyRuntimeException extends RuntimeException{
  public MyRuntimeException(String message){
    super(message);
  }
  //whatever code you need to have here
}

class MyThrowable extends Throwable{
  public MyThrowable(String message){
    super(message);
  }
  //whatever code you need to have here
}

class MyException extends Exception{
  public MyException(String message){
    super(message);
  }
  //whatever code you need to have here
}
```

为什么要这样做将在阅读*自定义异常*部分后变得清晰。

# 尝试...捕获

当在`try`块内抛出异常时，它将控制流重定向到其第一个`catch`子句（在下面的示例中捕获`NullPointerException`）：

```java
void exceptionCaught(){
  try {
    method2();
  } catch (NullPointerException ex){
    System.out.println("NPE caught");
    ex.printStackTrace();
  } catch (RuntimeException ex){
    System.out.println("RuntimeException caught");
    ex.printStackTrace();
  } catch (Exception ex){
    System.out.println("Exception caught");
    ex.printStackTrace();
  }
}
```

如果有多个`catch`子句，编译器会强制您安排它们，以便子异常在父异常之前列出。在我们之前的示例中，`NullPointerException`扩展了`RuntimeException`扩展了`Exception`。如果抛出的异常类型与最顶层的`catch`子句匹配，此`catch`块处理异常（我们将很快讨论它的含义）。如果最顶层子句不匹配异常类型，则下一个`catch`子句获取控制流并处理异常（如果匹配子句类型）。如果不匹配，则控制流传递到下一个子句，直到异常被处理或尝试所有子句。如果没有一个子句匹配，异常将被抛出直到它被某个 try-catch 块处理，或者它传播到程序代码之外。在这种情况下，JVM 终止程序执行（准确地说，它终止线程执行，但我们将在第十一章，*JVM 进程和垃圾回收*中讨论线程）。

让我们通过运行示例来演示这一点。如果我们像之前展示的那样在`exceptionCaught()`方法中使用三个`catch`子句，并在`method1()`中抛出`NullPointerException`：

```java
void method1(String s){
  throw new NullPointerException("Parameter String is null");
}
```

结果将如下截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/b8721c37-ab6d-4418-9406-f8c0e2517e3c.png)

您可以看到最顶层的`catch`子句按预期捕获了异常。

如果我们将`method1()`更改为抛出`RuntimeException`：

```java
void method1(String s){
  throw new RuntimeException("Parameter String is null");
}
```

您可能不会感到惊讶，看到第二个`catch`子句捕获它。因此，我们不打算演示它。我们最好再次更改`method1()`，让它抛出`ArrayIndexOutOfBoundsException`，它是`RuntimeException`的扩展，但未列在任何捕获子句中：

```java
void method1(String s){
  throw new ArrayIndexOutOfBoundsException("Index ... is bigger " +
                                        "than the array length ...");
}
```

如果我们再次运行代码，结果将如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/4b8464ff-2568-4c63-a7bf-c8a8fb30d954.png)

正如您所看到的，异常被第一个匹配其类型的`catch`子句捕获。这就是编译器强制您列出它们的原因，以便子类通常在其父类之前列出，因此最具体的类型首先列出。这样，第一个匹配的子句总是最佳匹配。

现在，您可能完全希望看到任何非`RuntimeException`都被最后一个`catch`子句捕获。这是一个正确的期望。但在我们抛出它之前，我们必须解决*已检查*和*未检查*（也称为*运行时*）异常之间的区别。

# 已检查和未检查（运行时）异常

为了理解为什么这个主题很重要，让我们尝试在`method1()`中抛出`Exception`类型的异常。为了进行这个测试，我们将使用`InstantiationException`，它扩展了`Exception`。假设有一些输入数据的验证（来自某些外部来源），结果证明它们不足以实例化某些对象：

```java
void method1(String s) {
  //some input data validation 
  throw new InstantiationException("No value for the field" +
                                   " someField of SomeClass.");
}
```

我们编写了这段代码，突然编译器生成了一个错误，`Unhandled exception java.lang.InstantiationException`，尽管我们在客户端代码中有一个`catch`子句，它将匹配这种类型的异常（在方法`exceptionCaught()`中的最后一个`catch`子句）。

错误的原因是所有扩展`Exception`类但不是其子类`RuntimeException`的异常类型在编译时都会被检查，因此得名。编译器会检查这些异常是否在其发生的方法中得到处理：

+   如果在异常发生的方法中有一个`try-catch`块捕获了这个异常并且不让它传播到方法外部，编译器就不会抱怨

+   否则，它会检查方法声明中是否有列出此异常的`throws`子句；这里是一个例子：

```java
        void method1(String s) throws Exception{
          //some input data validation 
          throw new InstantiationException("No value for the field" +
                                           " someField of SomeClass.");
        }
```

`throws`子句必须列出所有可能传播到方法外部的已检查异常。通过添加`throws Exception`，即使我们决定抛出任何其他已检查异常，编译器也会满意，因为它们都是`Exception`类型，因此都包含在新的`throws`子句中。

在下一节`Throws`中，您将阅读一些使用`throws`子句中基本异常类的优缺点，在稍后的*异常处理的一些最佳实践*部分中，我们将讨论一些其他可能的解决方案。

与此同时，让我们继续讨论已检查异常的使用。在我们的演示代码中，我们决定在`method1()`的声明中添加`throws Exception`子句。这个改变立即在`method2()`中触发了相同的错误`Unhandled exception java.lang.InstantiationException`，因为`method2()`调用了`method1()`但没有处理`Exception`。因此，我们不得不在`method2()`中也添加一个`throws`子句：

```java
void method2() throws Exception{
  method1(null);
}
```

只有`method2()`的调用者——`exceptionCaught()`方法——不需要更改，因为它处理`Exception`类型。代码的最终版本是：

```java
void exceptionCaught(){
  try {
    method2();
  } catch (NullPointerException ex){
    System.out.println("NPE caught");
    ex.printStackTrace();
  } catch (RuntimeException ex){
    System.out.println("RuntimeException caught");
    ex.printStackTrace();
  } catch (Exception ex){
    System.out.println("Exception caught");
    ex.printStackTrace();
  }
}

void method2() throws Exception{
  method1(null);
}

void method1(String s) throws Exception{
  throw new InstantiationException("No value for the field" +
                                           " someField of SomeClass.");
}
```

如果我们现在调用`exceptionCaught()`方法，结果将是：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/8faf4c71-38d5-42b8-96bb-6b261faeae1d.png)

这正是我们所期望的。`Exception`类型的最后一个`catch`子句匹配了`InstantiationException`类型。

未检查的异常——`RuntimeExceptions`类的后代——在编译时不会被检查，因此得名，并且不需要在`throws`子句中列出。

一般来说，已检查异常（应该）用于可恢复的条件，而未检查异常用于不可恢复的条件。我们将在稍后的*什么是异常处理？*和*一些最佳实践* *异常处理*部分中更多地讨论这个问题。

# 抛出

`throws`子句必须列出方法或构造函数可以抛出的所有已检查异常类（`Exception`类的后代，但不是`RuntimeException`类的后代）。在`throws`子句中列出未检查的异常类（`RuntimeException`类的后代）是允许的，但不是必需的。以下是一个例子：

```java
void method1(String s) 
           throws InstantiationException, InterruptedException {
  //some input data validation 
  if(some data missing){
    throw new InstantiationException("No value for the field" +
                                     " someField of SomeClass.");
  }
  //some other code
  if(some other reason){
    throw new InterruptedException("Reason..."); //checked exception 
  }
}
```

或者，可以只列出`throws`子句中的基类异常，而不是声明抛出两种不同的异常：

```java
void method1(String s) throws Exception {
  //some input data validation 
  if(some data missing){
    throw new InstantiationException("No value for the field" +
                                     " someField of SomeClass.");
  }
  //some other code
  if(some other reason){
    throw new InterruptedException("Reason..."); //checked exception 
  }
}
```

然而，这意味着潜在失败的多样性和可能的原因将隐藏在客户端，因此一个人必须要么：

+   在方法内处理异常

+   假设客户端代码将根据消息的内容来确定其行为（这通常是不可靠的并且可能会发生变化）

+   假设客户端无论实际的异常类型是什么都会表现相同

+   假设该方法永远不会抛出任何其他已检查异常，如果确实抛出，客户端的行为不应该改变

有太多的假设让人感到不舒服，只声明`throws`子句中的基类异常。但有一些最佳实践可以避免这种困境。我们将在*异常处理的一些最佳实践*部分中讨论它们。

# 自定义异常

在这一部分，我们承诺讨论自定义异常创建的动机。以下是两个例子：

```java
//Unchecked custom exception
class MyRuntimeException extends RuntimeException{
  public MyRuntimeException(String message){
    super(message);
  }
  //whatever code you need to have here
}

//Checked custom exception
class MyException extends Exception{
  public MyException(String message){
    super(message);
  }
  //whatever code you need to have here
}
```

直到你意识到注释`这里需要任何代码`允许你在自定义类中放入任何数据或功能，并利用异常处理机制将这样的对象从任何代码深度传播到任何你需要的级别，这些示例看起来并不特别有用。

由于这只是 Java 编程的介绍，这些情况超出了本书的范围。我们只是想确保你知道这样的功能存在，所以当你需要它或构建你自己的创新解决方案时，你可以在互联网上搜索。

然而，在 Java 社区中有关利用异常处理机制进行业务目的的讨论仍在进行中，我们将在*异常处理的一些最佳实践*部分中稍后讨论。

# 什么是异常处理？

正如我们已经提到的，检查异常最初被认为是用于可恢复的条件，当调用者代码可能会自动执行某些操作并根据捕获的异常类型和可能携带的数据采取另一个执行分支时。这就是异常处理的主要目的和功能。

不幸的是，这种利用异常的方式被证明并不是非常有效，因为一旦发现异常条件，代码就会得到增强，并使这样的条件成为可能的处理选项之一，尽管并不经常执行。

次要功能是记录错误条件和所有相关信息，以供以后分析和代码增强。

异常处理的第三个同样重要的功能是保护应用程序免受完全失败。意外情况发生了，但希望这种情况很少，主流处理仍然可用于应用程序继续按设计工作。

异常处理的第四个功能是在其他手段不够有效的特殊情况下提供信息传递的机制。异常处理的这最后一个功能仍然存在争议，且并不经常使用。我们将在下一节讨论它。

# 异常处理的一些最佳实践

Java 异常处理机制旨在解决可能的边缘情况和意外的程序终止。预期的错误类别是：

+   **可恢复的**：可以根据应用逻辑自动修复的异常

+   **不可恢复的**：无法自动纠正并导致程序终止的异常

通过引入已检查的异常（`Exception`类的后代）来解决第一类错误，而第二类错误则成为未经检查的异常领域（`RuntimeException`类的后代）。

不幸的是，这种分类方法在编程实践中并不符合实际情况，特别是对于与开发旨在在各种环境和执行上下文中使用的库和框架无关的编程领域。典型的应用程序开发总是能够直接在代码中解决问题，而无需编写复杂的恢复机制。这种区别很重要，因为作为库的作者，你永远不知道你的方法将在何处以及如何被使用，而作为应用程序开发人员，你确切地了解环境和执行上下文。

即使在写作时，Java 的作者们间接地确认了这一经验，向`java.lang`包中添加了 15 个未经检查的异常和仅九个已检查的异常。如果原始期望得到了实践的确认，人们会期望只有少数不可恢复的（未经检查的）异常和更多类型的可恢复的（已检查的）异常。与此同时，甚至`java.lang`包中的一些已检查的异常看起来也不太可恢复：

+   `ClassNotFoundException`：当 JVM 无法找到所引用的类时抛出

+   `CloneNotSupportedException`：指示对象类中的克隆方法未实现`Cloneable`接口

+   `IllegalAccessException`：当当前执行的方法无法访问指定类、字段、方法或构造函数的定义时抛出

实际上，很难找到一种情况，其中编写自动恢复代码比只是在主流处理中添加另一个逻辑分支更值得。

考虑到这一点，让我们列举一些被证明是有用和有效的最佳实践：

+   始终捕获所有异常

+   尽可能接近源头处理每个异常

+   除非必须，否则不要使用已检查的异常

+   通过重新抛出它们作为带有相应消息的`RuntimeException`，将第三方已检查的异常转换为未经检查的异常

+   除非必须，否则不要创建自定义异常

+   除非必须，否则不要使用异常处理机制来驱动业务逻辑

+   通过使用消息系统和可选的枚举类型自定义通用的`RuntimeException`，而不是使用异常类型来传达错误的原因

# 最后

`finally`块可以添加到带有或不带有`catch`子句的`try`块中。格式如下：

```java
try {
  //code of the try block
} catch (...){
  //optional catch block code
} finally {
  //code of the finally block
}
```

如果存在，则`finally`块中的代码总是在方法退出之前执行。无论`try`块中的代码是否抛出异常，以及这个异常是否在`catch`块中的一个中被处理，或者`try`块中的代码是否没有抛出异常，`finally`块都会在方法返回控制流到调用者之前执行。

最初，`finally`块用于关闭`try`块中需要关闭的一些资源。例如，如果代码已经打开了到数据库的连接，或者已经在磁盘上与文件建立了读取或写入连接，那么在操作完成或抛出异常时必须关闭这样的连接。否则，未及时关闭的连接会使资源（维护连接所需的资源）被锁定而不被使用。我们将在[第十一章]（e8c37d86-291d-4500-84ea-719683172477.xhtml）*JVM 进程和垃圾回收*中讨论 JVM 进程。

因此，典型的代码看起来像这样：

```java
Connection conn = null;
try {
  conn = createConnection();
  //code of the try block
} catch (...){
  //optional catch block code
} finally {
  if(conn != null){
    conn.close();
  }
}
```

它运行得很好。但是，一个名为`try...with...resources`的新的 Java 功能允许在连接类实现`AutoCloseable`时自动关闭连接（大多数流行的连接类都是这样）。我们将在[第十六章]（d77f1f16-0aa6-4d13-b9a8-f2b6e195f0f1.xhtml）*数据库编程*中讨论`try...with...resources`结构。这一发展降低了`finally`块的实用性，现在它主要用于处理一些不能使用`AutoCloseable`接口执行的代码，但必须在方法无条件返回之前执行。例如，我们可以通过利用`finally`块来重构我们的`exceptionCaught（）`方法，如下所示：

```java
void exceptionCaught(){
  Exception exf = null;
  try {
    method2();
  } catch (NullPointerException ex){
    exf = ex;
    System.out.println("NPE caught");
  } catch (RuntimeException ex){
    exf = ex;
    System.out.println("RuntimeException caught");
  } catch (Exception ex){
    exf = ex;
    System.out.println("Exception caught");
  } finally {
    if(exf != null){
      exf.printStackTrace();
    }
  }
```

还有其他情况下的`finally`块使用，基于它在控制流返回给方法调用者之前的保证执行。

# Assert 需要 JVM 选项-ea

分支`assert`语句可用于验证应用程序测试中的数据，特别是用于访问很少使用的执行路径或数据组合。这种能力的独特之处在于，除非 JVM 使用选项`-ea`运行，否则不会执行代码。

本书不讨论`assert`语句的功能和可能的应用。我们只会演示它的基本用法以及如何在 IntelliJ IDEA 中打开它。

看看下面的代码：

```java
public class AssertDemo {
  public static void main(String... args) {
    int x = 2;
    assert x > 1 : "x <= 1";
    assert x == 1 : "x != 1";
  }
}
```

第一个`assert`语句评估表达式`x>1`，如果表达式`x>1`评估为`false`，则停止程序执行（并报告`x<=1`）。

第二个`assert`语句评估表达式`x == 1`，如果表达式`x == 1`评估为`false`，则停止程序执行（并报告`x！= 1`）。

如果我们现在运行这个程序，将不会执行任何`assert`语句。要打开它们，请单击 IntelliJ IDEA 菜单中的 Run 并选择 Edit Configurations，如下面的屏幕截图所示：

！[]（img / 4cfd5dda-e07c-45ec-b9bd-13c4e4b6ac33.png）

运行/调试配置屏幕将打开。在 VM 选项字段中键入`-ea`，如下面的屏幕截图所示：

！[]（img / 8019cb61-0d4f-4d29-8d28-d10aef60490e.png）

然后，点击屏幕底部的确定按钮。

如果现在运行`AssertDemo`程序，结果将是：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/9666cbdf-3943-494e-a7b8-d8a9eebdd592.png)

`-ea`选项不应该在生产中使用，除非可能是为了测试目的而临时使用，因为它会增加开销并影响应用程序的性能。

# 练习-无限循环

写一个或两个无限循环的例子。

# 答案

以下是一个可能的无限循环实现：

```java
while(true){
  System.out.println("try and stop me"); //prints indefinitely
}
```

以下是另一个：

```java
for (;;){
  System.out.println("try and stop me"); //prints indefinitely
}

```

这也是一个无限循环：

```java
for (int x=2; x > 0; x--){
  System.out.println(x++ + " "); //prints 2 indefinitely
}

```

在这段代码中，布尔表达式`x > 0`总是被评估为`true`，因为`x`被初始化为`2`，然后在每次迭代中递增和递减`1`。

# 总结

本章描述了 Java 语句，让您根据实现的算法逻辑构建程序流，使用条件语句、迭代语句、分支语句和异常处理。对 Java 异常的广泛讨论帮助您在这个复杂且经常正确使用的领域中进行导航。为最有效和最少混淆的异常处理提供了最佳实践。

在下一章中，我们将深入了解 JVM 的内部工作机制，讨论其进程和其他重要方面，包括线程和垃圾回收机制，这些对于有效的 Java 编程非常重要，它们帮助应用程序重新获得不再使用的内存。


# 第十一章：JVM 进程和垃圾回收

本章使读者能够深入了解 JVM 并了解其进程。 JVM 的结构和行为比仅仅按照编码逻辑执行一系列指令的执行器更复杂。 JVM 会找到并加载应用程序请求的`.class`文件到内存中，对其进行验证，解释字节码（将其转换为特定平台的二进制代码），并将生成的机器代码传递给中央处理器（或处理器）进行执行，除了应用程序线程外，还使用几个服务线程。其中一个名为垃圾回收的服务线程执行重要任务，即释放未使用对象的内存。

在本章中，我们将涵盖以下主题：

+   JVM 进程是什么？

+   JVM 架构

+   垃圾回收

+   线程

+   练习-在运行应用程序时监视 JVM

# JVM 进程是什么？

正如我们在第一章中已经确定的那样，*计算机上的 Java 虚拟机（JVM）*，JVM 对 Java 语言和源代码一无所知。 它只知道如何读取字节码。 它从`.class`文件中读取字节码和其他信息，解释它（将其转换为特定微处理器的二进制代码序列），并将结果传递给执行它的计算机。

在谈论它时，程序员经常将 JVM 称为* JVM 实例*或*进程*。 这是因为每次执行`java`命令时，都会启动一个新的 JVM *实例*，专门用于在单独的进程中运行特定应用程序，并分配内存大小（默认或作为命令选项传递）。 在这个 JVM 进程内部，多个线程正在运行，每个线程都有自己分配的内存； 一些是 JVM 创建的服务线程，而其他是应用程序创建和控制的应用程序线程。

线程是轻量级进程，需要比 JVM 执行进程更少的资源分配。

这是 JVM 执行编译代码的大局观。 但是，如果您仔细观察并阅读 JVM 规范，您会发现与 JVM 相关的“进程”一词被重复使用了很多次。 JVM 规范确定了 JVM 内部运行的其他几个进程，程序员通常不提及它们，除了可能是类加载过程。

这是因为大多数情况下，人们可以成功地编写和执行 Java 程序，而无需了解 JVM 的更多信息。 但是偶尔，对 JVM 内部工作原理的一些一般了解有助于确定某些相关问题的根本原因。 这就是为什么在本节中，我们将简要概述 JVM 内部发生的所有进程。 然后，在接下来的几节中，我们将更详细地讨论 JVM 的内存结构和 JVM 功能的其他一些方面，这可能对程序员有用。

有两个子系统运行所有 JVM 内部进程：

+   类加载器，读取`.class`文件并使用类相关数据填充 JVM 内存中的方法区域：

+   静态字段

+   方法字节码

+   描述类的类元数据

+   执行引擎，使用以下内容执行字节码：

+   堆区用于对象实例化

+   Java 和本地方法堆栈用于跟踪调用的方法

+   垃圾回收过程以回收内存

运行在主 JVM 进程内部的进程列表包括：

+   类加载器执行的进程：

+   类加载

+   类链接

+   类初始化

+   执行引擎执行的进程：

+   类实例化

+   方法执行

+   垃圾回收

+   应用程序终止

JVM 架构可以描述为具有两个子系统 - 类加载器和执行引擎 - 它们使用运行时数据内存区域运行服务进程和应用程序线程：方法区域，堆和应用程序线程堆栈。

前面的列表可能会让你觉得这些过程是按顺序执行的。在某种程度上，如果我们只谈论一个类的话，这是正确的。在加载之前无法对类做任何操作。只有在完成所有先前的过程之后，方法的执行才能开始。然而，例如垃圾回收并不会在对象停止使用后立即发生（请参阅下一节，*垃圾回收*）。此外，应用程序可能在发生未处理的异常或其他错误时随时退出。

JVM 规范只对类加载器进程进行了规定。执行引擎的实现在很大程度上取决于每个供应商。它基于语言语义和实现作者设定的性能目标。

执行引擎的过程不受 JVM 规范的约束。有常识、传统、已知和经过验证的解决方案，以及 Java 语言规范可以指导 JVM 供应商的实现决策，但没有单一的监管文件。好消息是，最流行的 JVM 使用类似的解决方案，或者至少从入门课程的高层来看是这样的。有关特定供应商的详细信息，请参阅维基百科上的*Java 虚拟机比较*（[`en.wikipedia.org/wiki/Comparison_of_Java_virtual_machines`](https://en.wikipedia.org/wiki/Comparison_of_Java_virtual_machines)）和其他互联网上可用的来源。

有了这个理解，让我们更详细地描述之前列出的七个过程中的每一个。

# 加载

根据 JVM 规范，加载阶段包括通过其名称找到`.class`文件并在内存中创建其表示。

要加载的第一个类是在命令行中传递的带有`main(String[])`方法的类。我们之前在第四章中描述过它，*你的第一个 Java 项目*。类加载器读取`.class`文件，根据内部数据结构解析它，并用静态字段和方法字节码填充方法区。它还创建了描述该类的`java.lang.Class`的实例。然后，类加载器链接（见*链接*部分）和初始化（见*初始化*部分）该类，并将其传递给执行引擎以运行其字节码。

在第四章中的第一个项目，*你的第一个 Java 项目*中，`main(String[])`方法没有使用任何其他方法或类。但在实际应用程序中，`main(String[])`方法是应用程序的入口。如果它调用另一个类的方法，那么必须在类路径上找到该类并读取、解析和初始化；只有这样它的方法才能被执行。依此类推。这就是 Java 应用程序的启动和运行方式。

在接下来的部分*如何执行 main(String[])方法*中，我们将展示 Java 应用程序可以启动的几种方式，包括使用带有清单的可执行`.jar`文件。

每个类都允许有一个`main(String[])`方法，通常也有。这样的方法用于独立运行类作为独立应用程序进行测试或演示。这样的方法的存在并不使类成为主类。只有在`java`命令行或`.jar`文件清单中标识为主类时，该类才成为主类。

说了这些，让我们继续讨论加载过程。

如果查看`java.lang.Class`的 API，你不会在那里看到公共构造函数。类加载器会自动创建它的实例，并且顺便说一句，这是由`getClass()`方法返回的相同实例，你可以在任何对象上调用该方法。它不携带类的静态数据（这些数据在方法区中维护）或状态（它们在执行期间创建的对象中）。它也不包含方法的字节码（这也存储在方法区中）。相反，`Class`实例提供描述类的元数据 - 其名称、包、字段、构造函数、方法签名等。这就是为什么它不仅对 JVM 有用，对应用程序代码也有用，正如我们已经在一些示例中看到的。

类加载器在内存中创建并由执行引擎维护的所有数据称为类型的二进制表示。

如果`.class`文件存在错误或不符合特定格式，该过程将被终止。这意味着加载过程会对加载的类格式及其字节码进行一些验证。但更多的验证将在下一个称为**链接**的过程开始时进行。

以下是加载过程的高级描述。它执行三项任务：

+   查找并读取`.class`文件

+   根据内部数据结构将其解析到方法区

+   创建一个携带类元数据的`java.lang.Class`的实例

# 链接

根据 JVM 规范，链接是解析已加载类的引用，以便执行类的方法。

虽然 JVM 可以合理地期望`.class`文件是由 Java 编译器生成的，并且所有指令都满足语言的约束和要求，但无法保证加载的文件是由已知的编译器实现或根本没有编译器生成的。这就是为什么链接过程的第一步是*验证*，以确保类的二进制表示在结构上是正确的：每个方法调用的参数与方法描述符兼容，返回指令与其方法的返回类型匹配，依此类推。

验证成功完成后，下一步是*准备*。接口或类（静态）变量在方法区中创建，并初始化为其类型的默认值。其他类型的初始化（由程序员指定的显式赋值和静态初始化块）被推迟到称为**初始化**的过程中（请参阅下一节*初始化*）。

如果加载的字节码引用其他方法、接口或类，则符号引用将被解析为指向方法区的具体引用，这是通过*解析*过程完成的。如果所引用的接口和类尚未加载，类加载器会找到它们并根据需要加载它们。

以下是链接过程的高级描述。它执行三项任务：

+   验证类或接口的二进制表示

+   在方法区中准备静态字段

+   将符号引用解析为指向方法区的具体引用

# 初始化

根据 JVM 规范，初始化是通过执行类初始化方法来完成的。

这是程序员定义的初始化（在静态块和静态赋值中）进行的时候，除非类已经在另一个类的请求下进行了初始化。

这个陈述的最后一部分很重要，因为该类可能会被不同（已加载）方法多次请求，并且因为 JVM 进程由不同线程执行（参见*线程*部分中线程的定义），可能会同时访问同一个类。因此，需要在不同线程之间进行协调（也称为同步），这大大复杂了 JVM 的实现。

# 实例化

从技术上讲，由`new`操作符触发的实例化过程是执行的第一步，这一部分可能不存在。但是，如果`main(String[])`方法（静态方法）只使用其他类的静态方法，实例化就永远不会发生。这就是为什么将这个过程与执行分开是合理的。此外，这个活动有非常具体的任务：

+   在堆区为对象（其状态）分配内存

+   将实例字段初始化为默认值

+   为 Java 和本地方法创建线程堆栈

执行从第一个方法（不是构造函数）准备执行开始。为每个应用程序线程创建一个专用的运行时堆栈，在其中捕获每个方法调用的堆栈帧。如果发生异常，我们可以从当前堆栈帧中调用`printStackTrace()`方法获取数据。

# 执行

当`main(String[])`方法开始执行时，将创建第一个应用程序线程（称为*主*线程）。它可以创建其他应用程序线程。执行引擎读取字节码，解释它们，并将二进制代码发送到微处理器执行。它还维护了每个方法被调用的次数和频率的计数。如果计数超过一定阈值，执行引擎将使用一个称为 JIT 编译器的编译器，将方法的字节码编译成本地代码。下次调用该方法时，它将准备好而无需解释。这大大提高了代码的性能。

当前正在执行的指令和下一条指令的地址都保存在**程序计数器**（**PC**）寄存器中。每个线程都有自己专用的 PC 寄存器。这也提高了性能并跟踪执行情况。

# 垃圾收集

**垃圾收集器**（**GC**）运行的过程是识别不再被引用的对象，因此可以从内存中删除。有一个 Java 静态方法`System.gc()`，可以通过编程方式触发垃圾收集，但不能保证立即执行。每次 GC 循环都会影响应用程序的性能，因此 JVM 必须在内存可用性和执行字节码的速度之间保持平衡。

# 应用程序终止

应用程序可以通过多种方式（以及通过编程方式）终止（并停止 JVM）：

+   正常终止而没有错误状态码

+   由于未处理的异常或强制的编程方式退出而导致的异常终止，无论是否带有错误状态码

如果没有异常和无限循环，`main(String[])`方法将通过`return`语句或在执行其最后一条语句后完成。一旦发生这种情况，主应用程序线程将控制流返回给 JVM，JVM 也停止执行。

这是一个幸福的结局，许多应用程序在现实生活中也享受着这种结局。除了我们展示了异常或无限循环的例外情况，大多数示例也都成功结束了。

然而，Java 应用程序还有其他退出方式，其中一些方式也相当优雅。其他方式则不那么优雅。

如果主应用程序线程创建了子线程，或者换句话说，程序员编写了生成其他线程的代码，即使优雅地退出也可能不那么容易。这完全取决于创建的子线程的类型。如果其中任何一个是`用户`线程（默认情况下），那么即使主线程退出后，JVM 实例也会继续运行。

只有在所有`用户`线程完成后，JVM 实例才会停止。主线程可以请求子`用户`线程完成（我们将在下一节*线程*中讨论这一点）。但在退出之前，JVM 会继续运行，这意味着应用程序仍在运行。

但是，如果所有子线程都是`守护`线程（请参阅下一节*线程*），或者没有正在运行的子线程，那么一旦主应用程序线程退出，JVM 实例就会停止运行。

在没有强制终止的情况下，JVM 实例会继续运行，直到主应用程序线程和所有子`用户`线程完成。如果没有子`用户`线程或者所有子线程都是`守护`线程，那么一旦主应用程序线程退出，JVM 就会停止运行。

在异常情况下应用程序如何退出取决于代码设计。我们在上一章讨论异常处理的最佳实践时已经提到过。如果线程在`main(String[])`或类似高级方法中的`try...catch`块中捕获了所有异常，那么控制流将返回到应用程序代码，并由应用程序（以及编写代码的程序员）决定如何继续——尝试恢复、记录错误并继续，或者退出。

另一方面，如果异常仍未处理并传播到 JVM 代码中，那么发生异常的线程将停止执行并退出。然后，将发生以下情况之一：

+   如果没有其他线程，则 JVM 停止执行并返回错误代码和堆栈跟踪

+   如果出现未处理的异常的线程不是主线程，则其他线程（如果存在）会继续运行

+   如果主线程抛出未处理的异常，并且子线程（如果存在）是守护线程，则它们也会退出

+   如果至少有一个用户子线程，JVM 会继续运行，直到所有用户线程退出

还有一些编程方法可以强制应用程序停止：

+   `System.exit(0);`

+   `Runtime.getRuntime().exit(0);`

+   `Runtime.getRuntime().halt(0);`

所有前述方法都会强制 JVM 停止执行任何线程，并以作为参数传递的状态代码（在我们的示例中为 0）退出：

+   零表示正常终止

+   非零值表示异常终止

如果 Java 命令是由某个脚本或其他系统启动的，则状态代码的值可用于自动化决定下一步的操作。但这已经超出了应用程序和 Java 代码的范围。

前两种方法具有相同的功能，因为`System.exit()`的实现方式如下：

```java
public static void exit(int status) {
  Runtime.getRuntime().exit(status);
}
```

要在 IDE 中查看源代码，只需单击该方法。

当某个线程调用`Runtime`或`System`类的`exit()`方法，或者`Runtime`类的`halt()`方法，并且退出或中止操作被安全管理器允许时，Java 虚拟机退出。

`exit()`和`halt()`之间的区别在于`halt()`会立即强制 JVM 退出，而`exit()`会执行可以使用`Runtime.addShutdownHook()`方法设置的附加操作。

但所有这些选项在主流编程中很少使用，因此我们已经超出了本书的范围。

# JVM 架构

JVM 架构可以用内存中的运行时数据结构和使用运行时数据的两个子系统——类加载器和执行引擎来描述。

# 运行时数据区

JVM 内存的每个运行时数据区都属于两个类别之一：

+   共享区域，包括以下内容：

+   **方法区**：类元数据，静态字段，方法字节码

+   **堆区**：对象（状态）

+   不共享区域，专门为每个应用程序线程而设，包括以下内容：

+   **Java 堆栈**：当前和调用者帧，每个帧保持 Java（非本地）方法调用的状态：

+   本地变量的值

+   方法参数值

+   中间计算的操作数的值（操作数栈）

+   方法返回值（如果有）

+   **程序计数器（PC）寄存器**：下一条要执行的指令

+   **本地方法堆栈**：本地方法调用的状态

我们已经讨论过，程序员在使用引用类型时必须小心，不要修改对象本身，除非需要这样做。在多线程应用程序中，如果对象的引用可以在线程之间传递，就必须特别小心，因为可能会同时修改相同的数据。

光明的一面是，这样的共享区域可以并且经常被用作线程之间的通信手段。我们将在即将到来的*Threads*部分讨论这个问题。

# 类加载器

类加载器执行以下三个功能：

+   读取`.class`文件

+   填充方法区

+   初始化程序员未初始化的静态字段

# 执行引擎

执行引擎执行以下操作：

+   在堆区实例化对象

+   使用程序员编写的初始化器初始化静态和实例字段

+   向 Java 堆栈添加/删除帧

+   更新 PC 寄存器以执行下一条指令

+   维护本地方法堆栈

+   保持方法调用的计数并编译流行的方法

+   完成对象

+   运行垃圾回收

+   终止应用程序

# 线程

正如我们已经提到的，主应用程序线程可以创建其他 - 子 - 线程，并让它们并行运行，无论是通过时间切片共享同一个核心，还是为每个线程分配一个专用的 CPU。可以使用实现了功能接口`Runnable`的类`java.lang.Thread`来实现。如果接口只有一个抽象方法，就称为功能接口（我们将在第十七章中讨论功能接口，*Lambda 表达式和函数式编程*）。`Runnable`接口包含一个方法`run()`。 

有两种方法创建新线程：

+   扩展`Thread`类

+   实现`Runnable`接口，并将实现的对象传递到类`Thread`的构造函数中

# 扩展 Thread 类

无论使用什么方法，最终我们都会得到一个具有`start()`方法的`Thread`类对象。这个方法调用开始线程执行。让我们看一个例子。让我们创建一个名为`AThread`的类，它扩展了`Thread`并重写了它的`run()`方法：

```java
public class AThread extends Thread {
  int i1, i2;
  public AThread(int i1, int i2) {
    this.i1 = i1;
    this.i2 = i2;
  }
  public void run() {
    for (int i = i1; i <= i2; i++) {
      System.out.println("child thread " + (isDaemon() ? "daemon" : "user") + " " + i);
      try {
        TimeUnit.SECONDS.sleep(1);
      } catch (InterruptedException e) {
        e.printStackTrace();
      }
    }
  }
}
```

重写`run()`方法很重要，否则线程将不执行任何操作。`Thread`类实现了`Runnable`接口，并且有`run()`方法的实现，但它看起来如下：

```java
public void run() {
  if (target != null) {
    target.run();
  }
}
```

变量`target`保存在构造函数中传递的值：

```java
public Thread(Runnable target) {
  init(null, target, "Thread-" + nextThreadNum(), 0);
}
```

但是我们的`AThread`类没有向父类`Target`传递任何值；变量 target 是`null`，所以`Thread`类中的`run()`方法不执行任何操作。

现在让我们使用我们新创建的线程。我们期望它将变量`i`从`i1`增加到`i2`（这些是通过构造函数传递的参数），并打印其值以及`isDaemon()`方法返回的布尔值，然后等待（休眠）1 秒并再次增加变量`i`。

# 什么是守护进程？

“守护”一词源自古希腊语，意思是介于神和人之间的神性或超自然存在，以及内在或随从精神或激励力量。但在计算机科学中，这个术语有更加平凡的用法，用于指代作为后台进程运行的计算机程序，而不是受交互式用户直接控制。这就是为什么 Java 中有两种类型的线程：

+   用户线程（默认），由应用程序发起（主线程就是这样的一个示例）

+   在支持用户线程活动的后台运行的守护线程（垃圾收集是守护线程的一个示例）

这就是为什么所有守护线程在最后一个用户线程退出或 JVM 在未处理的异常后终止之后立即退出。

# 扩展线程运行

让我们使用我们的新类`AThread`来演示我们所描述的行为。这是我们首先要运行的代码：

```java
Thread thr1 = new AThread(1, 4);
thr1.start();

Thread thr2 = new AThread(11, 14);
thr2.setDaemon(true);
thr2.start();

try {
  TimeUnit.SECONDS.sleep(1);
} catch (InterruptedException e) {
  e.printStackTrace();
}
System.out.println("Main thread exists");

```

在前面的代码中，我们创建并立即启动了两个线程-用户线程`thr1`和守护线程`thr2`。实际上，还有一个名为`main`的用户线程，所以我们运行了两个用户线程和一个守护线程。每个子线程将打印递增的数字四次，每次打印后暂停 1 秒。这意味着每个线程将运行 4 秒。主线程也会暂停 1 秒，但只有一次，所以它将运行大约 1 秒。然后，它打印“主线程存在”并退出。如果我们运行此代码，将看到以下输出：

！[]（img / 42afcacb-82d0-414b-afd4-e5d36be0c2d5.png）

我们在一个共享的 CPU 上执行此代码，因此，尽管所有三个线程都在同时运行，但它们只能顺序使用 CPU。因此，它们不能并行运行。在多核计算机上，每个线程可以在不同的 CPU 上执行，输出可能略有不同，但差别不大。无论如何，您会看到主线程首先退出（大约 1 秒后），子线程运行直到完成，每个线程总共运行大约 4 秒。

让用户线程只运行 2 秒：

```java
Thread thr1 = new AThread(1, 2);
thr1.start();

```

结果是：

！[]（img / ab8a6642-440f-4a0b-af2e-1589b74c8613.png）

如您所见，守护线程没有完全运行。它成功打印了 13，可能仅因为它在 JVM 响应最后一个用户线程退出之前已将消息发送到输出设备。

# 实现 Runnable

创建线程的第二种方法是使用实现`Runnable`的类。以下是一个几乎与类`AThread`具有完全相同功能的类的示例：

```java
public class ARunnable implements Runnable {
  int i1, i2;

  public ARunnable(int i1, int i2) {
    this.i1 = i1;
    this.i2 = i2;
  }

  public void run() {
    for (int i = i1; i <= i2; i++) {
      System.out.println("child thread "  + i);
      try {
        TimeUnit.SECONDS.sleep(1);
      } catch (InterruptedException e) {
        e.printStackTrace();
      }
    }
  }
}
```

唯一的区别是`Runnable`接口中没有`isDaemon（）`方法，因此我们无法打印线程是否为守护线程。

# 运行实现 Runnable 的线程

以下是如何使用此类创建两个子线程-一个用户线程和另一个守护线程-与我们之前所做的完全相同：

```java
Thread thr1 = new Thread(new ARunnable(1, 4));
thr1.start();

Thread thr2 = new Thread(new ARunnable(11, 14));
thr2.setDaemon(true);
thr2.start();

try {
  TimeUnit.SECONDS.sleep(1);
} catch (InterruptedException e) {
  e.printStackTrace();
}

System.out.println("Main thread exists");
```

如果我们运行前面的代码，结果将与基于扩展`Thread`类的线程运行相同。

# 扩展 Thread 与实现 Runnable

实现`Runnable`的优点（在某些情况下，也是唯一可能的选项）是允许实现扩展另一个类。当您想要向现有类添加类似线程的行为时，这是特别有帮助的。

```java
public class BRunnable extends SomeClass implements Runnable {
  int i; 
  BRunnable(int i, String s) {
    super(s);
    this.i = i;
  }
  public int calculateSomething(double x) {
    //calculate result
    return result;
  }
  public void run() {
    //any code you need goes here
  }
}
```

您甚至可以直接调用方法`run()`，而不将对象传递到 Thread 构造函数中：

```java
BRunnable obj = new BRunnable(2, "whatever");
int i = obj.calculateSomething(42d);
obj.run(); 
Thread thr = new Thread (obj);
thr.start(); 
```

在上面的代码片段中，我们展示了执行实现`Runnable`的类的方法的许多不同方式。因此，实现`Runnable`允许更灵活地使用。但是，与扩展`Thread`相比，在功能上没有区别。

`Thread`类有几个构造函数，允许设置线程名称和它所属的组。对线程进行分组有助于在许多线程并行运行的情况下对其进行管理。`Thread`类还有几种方法，提供有关线程状态和属性的信息，并允许我们控制其行为。

线程——以及任何对象——也可以使用基类`java.lang.Object`的`wait()`、`notify()`和`notifyAll()`方法相互通信。

但所有这些都已经超出了入门课程的范围。

# 如何执行 main(String[])方法

在深入讨论垃圾收集过程之前，我们想要回顾并总结如何从命令行运行应用程序。在 Java 中，以下语句用作同义词：

+   运行/执行主类

+   运行/执行/启动应用程序

+   运行/执行/启动主方法

+   运行/执行/启动/启动 JVM 或 Java 进程

这是因为列出的每个操作都会在执行其中一个操作时发生。还有几种方法可以做到这一点。我们已经向您展示了如何使用 IntelliJ IDEA 和`java`命令行运行`main(String[])`方法。现在，我们将重复已经说过的一些内容，并添加其他可能对您有帮助的变体。

# 使用 IDE

任何 IDE 都允许运行主方法。在 IntelliJ IDEA 中，有三种方法可以做到这一点：

+   通过单击方法名称旁边的绿色箭头

+   通过从下拉菜单中选择类名（在顶部行的左侧，绿色箭头的左侧）并单击菜单右侧的绿色箭头：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/47ecc693-bded-4567-b5f6-2fea2f282d4b.png)

+   通过单击运行菜单并选择类的名称：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/90dbb360-a4a9-435d-82de-6f2c4d56b72c.png)

在上面的截图中，您还可以看到选项“编辑配置”。我们已经使用它来设置可以在启动时传递给主方法的参数。但是还有更多的设置可能：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/3a7dc463-e2f3-4594-9549-0f64f3460763.png)

正如您所看到的，还可以设置：

+   VM 选项：Java 命令选项（我们将在下一节中进行）

+   环境变量：设置一些参数，不仅可以在主方法中读取，还可以在应用程序的任何地方使用`System.getenv()`方法

例如，看看以下截图：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/1e093c7a-d9fd-49ef-9bff-c3a8dd3b08fa.png)

我们已经设置了`java`命令选项`-Xlog:gc`和环境变量`myprop1=whatever`。IDE 将使用这些设置来形成以下`java`命令：

```java
java -Xlog:gc -Dmyprop1=whatever com.packt.javapath.ch04demo.MyApplication 2
```

选项`-Xlog:gc`告诉 JVM 显示来自垃圾回收过程的日志消息。我们将在下一节中使用此选项来演示垃圾回收的工作原理。可以使用以下语句在应用程序的任何位置检索变量`myprop1`的值：

```java
String myprop = System.getenv("myprop1");     //returns: "whatever"
```

我们已经看到参数 2 如何在主方法中读取：

```java
public static void main(String[] args) {
  String p1 = args[0];          //returns: "2"
}
```

# 带有类路径上的类的命令行

让我们使用我们在第四章中创建的第一个程序，*Your First Java Project*，来演示如何使用命令行。以下是我们当时编写的程序：

```java
package com.packt.javapath.ch04demo;
import com.packt.javapath.ch04demo.math.SimpleMath;
public class MyApplication {
  public static void main(String[] args) {
    int i = Integer.parseInt(args[0]);
    SimpleMath simpleMath = new SimpleMath();
    int result = simpleMath.multiplyByTwo(i);
    System.out.println(i + " * 2 = " + result);
  }
}
```

要从命令行运行它，必须首先使用`javac`命令对其进行编译。使用 Maven 的 IDE 将`.class`文件放在目录`target/classes`中。如果进入项目的根目录或单击 Terminal（IntelliJ IDEA 左下角），可以运行以下命令：

```java
java -cp target/classes com.packt.javapath.ch04demo.MyApplication 2
```

结果应显示为`2 * 2 = 4`。

# 带有类路径上的.jar 文件的命令行

创建一个带有编译应用程序代码的`.jar`文件，转到项目根目录并运行以下命令：

```java
cd target/classes
jar -cf myapp.jar com/packt/javapath/ch04demo/**
```

创建了一个带有类`MyApplication`和`SimpleMath`的`.jar`文件。现在我们可以将其放在类路径上并再次运行应用程序：

```java
java -cp myapp.jar com.packt.javapath.ch04demo.MyApplication 2
```

结果将显示相同；`2 * 2 = 4`。

# 带有可执行.jar 文件的命令行

可以避免在命令行中指定主类。相反，可以创建一个“可执行”的`.jar`文件。可以通过将主类的名称（需要运行的类，包含主方法的类）放入清单文件中来实现。以下是步骤：

+   创建一个文本文件`manifest.txt`（实际名称并不重要，但它可以清楚地表达意图），其中包含以下一行：`Main-Class: com.packt.javapath.ch04demo.MyApplication`。冒号（`:`）后必须有一个空格，并且末尾必须有一个不可见的换行符号，因此请确保您按下了*Enter*键并且光标已跳转到下一行的开头。

+   执行命令`cd target/classes`并进入目录`classes`。

+   执行以下命令：`jar -cfm myapp.jar  manifest.txt  com/packt/javapath/ch04demo/**`。

注意`jar`命令选项`fm`的顺序和以下文件的顺序；`myapp.jar manifest.txt`。它们必须相同，因为`f`代表`jar`命令将要创建的文件，`m`代表清单源。如果将选项放置为`mf`，则文件必须列为`manifest.txt myapp.jar`。

现在，运行以下命令：

```java
java -jar  myapp.jar  2
```

结果将再次显示为`2 * 2 = 4`。

具备运行应用程序的知识后，我们现在可以继续到下一节，那里将需要它。

# 垃圾回收

自动内存管理是 JVM 的一个重要方面，它使程序员无需以编程方式进行内存管理。在 Java 中，清理内存并允许您重用它的过程称为**垃圾回收**（**GC**）。

# 响应性、吞吐量和停顿时间

垃圾收集的有效性影响着两个主要应用程序特征 - 响应性和吞吐量。响应性是指应用程序对请求的快速响应（提供必要数据）的度量。例如，网站返回页面的速度，或者桌面应用程序对事件的快速响应。响应时间越短，用户体验就越好。另一方面，吞吐量表示应用程序在单位时间内可以完成的工作量。例如，一个 Web 应用程序可以提供多少请求，或者一个数据库可以支持多少交易。数字越大，应用程序可能产生的价值就越大，可以支持的用户请求也就越多。

与此同时，垃圾收集器需要移动数据，这在允许数据处理的同时是不可能完成的，因为引用将会发生变化。这就是为什么垃圾收集器需要偶尔停止应用程序线程的执行一段时间，这段时间被称为停顿时间。这些停顿时间越长，垃圾收集器完成工作的速度就越快，应用程序冻结的时间也就越长，最终可能会足够大以至于影响应用程序的响应性和吞吐量。幸运的是，可以使用`java`命令选项来调整垃圾收集器的行为，但这超出了本书的范围，本书更多地是介绍而不是解决复杂问题。因此，我们将集中讨论垃圾收集器主要活动的高层视图；检查堆中的对象并删除那些在任何线程堆栈中没有引用的对象。

# 对象年龄和代

基本的垃圾收集算法确定了每个对象的年龄。年龄指的是对象存活的收集周期数。当 JVM 启动时，堆是空的，并被分为三个部分：年轻代、老年代或终身代，以及用于容纳大小为标准区域的 50%或更大的对象的巨大区域。

年轻代有三个区域，一个伊甸园空间和两个幸存者空间，如幸存者 0（*S0*）和幸存者 1（*S1*）。新创建的对象被放置在伊甸园中。当它填满时，会启动一个次要的垃圾收集过程。它会移除无引用和循环引用的对象，并将其他对象移动到*S1*区域。在下一次次要收集时，*S0*和*S1*会交换角色。引用对象会从伊甸园和*S1*移动到*S0*。

在每次次要收集时，已经达到一定年龄的对象会被移动到老年代。由于这个算法的结果，老年代包含了比一定年龄更老的对象。这个区域比年轻代要大，因此垃圾收集在这里更昂贵，不像在年轻代那样频繁。但最终会进行检查（经过几次次要收集）；无引用的对象将从那里删除，并且内存会被整理。这种老年代的清理被认为是一次主要收集。

# 当无法避免停顿时间时

老年代中的一些对象收集是并发进行的，而另一些则使用停顿时间进行。具体步骤包括：

+   对可能在老年代中引用对象的幸存者区域（根区域）进行初始标记，使用停顿时间进行

+   扫描幸存者区域以查找对老年代的引用，与此同时应用程序继续运行

+   并发标记整个堆中的活动对象，与此同时应用程序继续运行

+   标记 - 完成对活动对象的标记，使用停顿时间进行

+   清理 - 计算活动对象的年龄并释放区域（使用停顿时间），并将其返回到空闲列表（并发进行）

前面的序列可能会与年轻一代的疏散交错，因为大多数对象的生命周期很短，通过更频繁地扫描年轻一代来释放大量内存更容易。还有一个混合阶段（当 G1 收集已标记为大部分垃圾的区域，既在年轻一代又在旧一代）和巨大分配（将大对象移动到或从巨大区域疏散）。

为了演示 GC 的工作原理，让我们创建一个产生比我们通常的示例更多垃圾的程序：

```java
public class GarbageCollectionDemo {
  public static void main(String... args) {
    int max = 99888999;
    List<Integer> list = new ArrayList<>();
    for(int i = 1; i < max; i++){
      list.add(Integer.valueOf(i));
    }
  }
}
```

此程序生成接近 100,000,000 个占用大量堆空间的对象，并迫使 GC 将它们从 Eden 移动到 S0、S1 等。正如我们已经提到的，要查看 GC 的日志消息，必须在`java`命令中包含选项`-Xlog:gc`。我们选择使用 IDE，正如我们在上一节中描述的那样：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/c73265ab-f907-43e7-855d-8e04e98394a9.png)

然后，我们运行了程序`GarbageCollectionDemo`并得到了以下输出（我们只显示了其开头）：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/intr-prog-java/img/173896b1-0e47-4fc2-ac88-4e8e33db9032.png)

正如您所看到的，GC 过程经过循环，并根据需要移动对象，暂停一小段时间。我们希望您了解了 GC 的工作原理。我们唯一想提到的是，在几个场合下会执行完全 GC，使用停止-世界暂停：

+   并发故障：如果在标记阶段旧一代变满。

+   **提升失败**：如果在混合阶段旧一代空间不足。

+   **疏散失败**：当收集器无法将对象提升到幸存者空间和旧一代时。

+   **巨大分配**：当应用程序尝试分配一个非常大的对象时。如果调整正确，您的应用程序应该避免完全 GC。

为了帮助 GC 调优，JVM 提供了平台相关的默认选择，用于垃圾收集器、堆大小和运行时编译器。但幸运的是，JVM 供应商一直在改进和调优 GC 过程，因此大多数应用程序都可以很好地使用默认的 GC 行为。

# 练习-在运行应用程序时监视 JVM

阅读 Java 官方文档，并命名几个随 JDK 安装提供的工具，可用于监视 JVM 和 Java 应用程序。

# 答案

例如 Jcmd、Java VisualVM 和 JConsole。Jcmd 特别有帮助，因为它易于记忆，并为您列出当前正在运行的所有 Java 进程。只需在终端窗口中键入`jcmd`。这是一个不可或缺的工具，因为您可能正在尝试运行几个 Java 应用程序，其中一些可能因为缺陷或故意设计而无法退出。Jcmd 为每个正在运行的 Java 进程显示一个**进程 ID**（**PID**），您可以使用该 ID 通过键入命令`kill -9 <PID>`来停止它。

# 摘要

在本章中，您已经了解了支持任何应用程序执行的主要 Java 进程，程序执行的步骤以及组成执行环境的 JVM 架构的主要组件；运行时数据区域，类加载器和执行引擎。您还了解了称为线程的轻量级进程以及它们如何用于并发处理。有关运行 Java 应用程序的方法总结以及垃圾收集过程的主要特点结束了有关 JVM 的讨论。

在下一章中，我们将介绍几个经常使用的库-标准库（随 JDK 一起提供）和外部开源库。很快，您将非常了解它们中的大部分，但要到达那里，您需要开始，我们将在评论和示例中帮助您。
