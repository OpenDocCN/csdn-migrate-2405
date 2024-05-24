# Java SE7 编程学习指南（三）

> 原文：[`zh.annas-archive.org/md5/F72094373E33408AE85D942CB0C47C3B`](https://zh.annas-archive.org/md5/F72094373E33408AE85D942CB0C47C3B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：循环结构

通常希望一遍又一遍地重复一系列操作。例如，我们可能希望显示存储在数组中的组织中员工的信息。数组的每个元素可能包含对`Employee`对象的引用。对象的方法调用将放置在循环结构内部。

在 Java 中有四种循环结构可用：

+   for 语句

+   For-each 语句

+   while 语句

d. while 语句

此外，break 和 continue 语句用于控制循环的行为。break 语句用于提前退出或短路循环，并在*break 语句*部分讨论。正如我们在第三章中观察到的，在*决策结构*中，break 也在 switch 语句中使用。continue 语句用于绕过循环中的语句并继续执行循环。它在*continue 语句*部分中介绍。我们还将研究在 Java 中使用标签，尽管它们应该谨慎使用。

循环的循环体根据循环结构的特定次数进行迭代。迭代是通常用来描述这种执行的术语。

循环使用控制信息来确定循环体将被执行多少次。对于大多数循环，有一组初始值，一组在循环体结束时执行的操作，以及一个终止条件，它将停止循环的执行。并非所有循环都有这些部分，因为其中一些部分要么缺失，要么隐含。终止条件几乎总是存在的，因为这是终止循环迭代所需的。如果终止条件缺失，则会创建一个无限循环。

无限循环指的是那些可能永远不会终止的循环，而不使用 break 语句等语句。尽管它们的名称是无限循环，但它们并不会无限执行，因为它们总会在某个时刻终止。它们在某些情况下很有用，这些情况中提供循环终止条件是不方便或尴尬的。

我们还将介绍嵌套循环的使用以及与循环相关的各种陷阱。还提供了一个处理编程逻辑开发的部分，以帮助在创建程序逻辑时提供一种方法。

# for 语句

当需要知道循环需要执行的次数时，使用 for 语句。for 循环有两种变体。第一种在本节中讨论，是传统形式。for-each 语句是第二种形式，引入于 Java 5。它在*for-each 语句*部分中讨论。

for 语句由以下三部分组成：

+   初始操作

+   终止条件

+   结束循环操作

for 循环的一般形式如下：

```java
for (<initial-expression>;<terminal-expression>;<end-loopoperation>)
  //statements;
```

for 循环的循环体通常是一个块语句。初始操作在循环的第一次迭代之前进行，只执行一次。结束循环操作在每次循环执行结束时进行。终止条件确定循环何时终止，并且是一个逻辑表达式。它在每次循环重复开始时执行。因此，如果第一次评估终止条件时，它的值为 false，则 for 循环的循环体可能会执行零次。

通常作为初始操作、终止条件和结束循环操作的一部分使用变量。变量要么作为循环的一部分声明，要么作为循环外部声明。以下代码片段是声明变量`i`作为循环一部分的示例。使用外部变量的示例在*for 语句和作用域*部分中介绍：

```java
for (int i = 1; i <= 10; i++) {
   System.out.print(i + "  ");
}
System.out.println();
```

在这个例子中，我们在循环体中使用了一个语句。变量`i`被赋予初始值 1，并且每次循环执行时增加 1。循环执行了 10 次，并产生了 1 行输出。语句`i++`是一种更简洁的方式，表示`i = i + 1`。输出应该是以下内容：

```java
1  2  3  4  5  6  7  8  9  10 

```

以下示例使用 for 语句计算从`1`到`64`的整数的平方：

```java
for (int i = 1; i <= 64; i++) {
  System.out.println (i + " squared is = " + i * i);
  }

```

输出的部分列表如下：

**1 的平方是= 1**

**2 的平方是= 4**

**3 的平方是= 9**

**4 的平方是= 16**

**...**

循环变量的初始值可以是任何值。此外，结束循环操作可以根据需要递减或修改变量。在下一个例子中，从`10`到`1`显示数字：

```java
for (int i = 10; i > 0; i--) {
   System.out.print(i + "  ");
}
System.out.println();
```

以下是此序列的输出：

```java
10  9  8  7  6  5  4  3  2  1 

```

一个常见的操作是计算累积和，如下面的代码序列所示。这个例子在*时间就是一切*部分中有更详细的讨论：

```java
int sum = 0;
for(i = 1; i <= 10; i++) {
  sum += i;
}
System.out.println(sum);
```

`sum`的值应该是`55`。

## 逗号运算符

逗号运算符可以作为 for 语句的一部分，用于添加其他变量以在循环内使用和/或控制循环。它用于分隔 for 循环的初始表达式和结束循环操作部分的各个部分。逗号运算符的使用如下所示：

```java
for(int i = 0, j = 10; j > 5; i++, j--) {
   System.out.printf("%3d  %3d%n",i , j);
}
```

注意在`printf`语句中使用了`%n`格式说明符。这指定应生成一个新行字符。此外，这个新行分隔符是特定于平台的，使应用程序更具可移植性。

执行此代码序列时，将产生以下输出：

```java
0   10
1    9
2    8
3    7
4    6

```

循环声明了两个变量，`i`和`j`。变量`i`初始化为`0`，`j`初始化为`10`。循环结束时，`i`增加了`1`，`j`减少了`1`。只要`j`大于`5`，循环就会执行。

我们可以使用更复杂的终止条件，如下面的代码片段所示：

```java
for(int i = 0, j = 10; j > 5 && i < 3; i++, j--) {
   System.out.printf("%3d  %3d%n",i , j);
}
```

在这个例子中，循环将在第三次迭代后终止，产生以下输出：

```java
  0   10
  1    9
  2    8
```

在这里分别声明变量是非法的：

```java
for(int i = 0, int j = 10; j > 5; i++, j--) {
```

生成了一个语法错误，如下所示。由于消息过长，只提供了消息的第一部分。这也说明了 Java 和大多数其他编程语言生成的错误消息的神秘性质：

```java
<identifier> expected
'.class' expected
...

```

## for 语句和作用域

for 语句使用的索引变量可以根据其声明方式具有不同的作用域。我们可以利用这一点来控制循环的执行，然后根据需要在循环外部使用变量。第一个 for 循环的示例如下重复。在这个代码序列中，`i`变量的作用域仅限于 for 循环的主体：

```java
for (int i = 1; i <= 10; i++) {
   System.out.println(i);
}
System.out.println();
```

一种替代方法是将`i`声明为循环外部，如下所示：

```java
int i;
for (i = 1; i <= 10; i++) {
  System.out.print(i + " ");
}
System.out.println();
```

这两个 for 循环是等价的，因为它们都在一行上显示 1 到 10 的数字。它们在`i`变量的作用域上有所不同。在第一个例子中，作用域仅限于循环体。尝试在循环外部使用变量，如下面的代码所示，将导致语法错误：

```java
for (int i = 1; i <= 10; i++) {
   System.out.println(i);
}
System.out.println(i);
```

错误消息如下：

```java
cannot find symbol
 symbol:   variable i

```

在第二个例子中，循环终止后，变量将保留其值，并可供后续使用。以下示例说明了这一点：

```java
int i;
for (i = 1; i <= 10; i++) {
  System.out.print(i + "  ");
}
System.out.println();
System.out.println(i);
```

以下是此序列的输出：

```java
1  2  3  4  5  6  7  8  9  10 
11

```

作用域在第二章的*作用域和生存期*部分中有更详细的讨论，*Java 数据类型及其用法*。

## for 循环的变体

for 循环的主体可能由多个语句组成。重要的是要记住 for 循环的主体只包含一个语句。下面说明了循环中多个语句的使用。这个循环将读取一系列数字并将它们逐行打印出来。它将继续读取，直到读取到一个负值，然后退出循环。`java.util.Scanner`类用于从输入源中读取数据。在这种情况下，它使用`System.in`指定键盘作为输入源：

```java
Scanner scanner = new Scanner(System.in);
int number = 0;

for (int i = 0; number >= 0; i++) {
   System.out.print("Enter a number: ");
   number = scanner.nextInt();
   System.out.printf("%d%n", number);
}
```

执行这段代码序列的一个可能的输出如下：

```java
Enter a number: 3
3
Enter a number: 56
56
Enter a number: -5
-5

```

初始操作、终止条件或结束循环操作是不需要的。例如，以下语句将执行`i++`语句 5 次，退出循环时`i`的值为`5`：

```java
int i = 0;
for (;i<5;) {
   i++;
}
```

在下面的例子中，循环的主体将永远执行，创建一个无限循环：

```java
int i = 0;
for (;;i++)
   ;
```

对于以下的 for 循环也是一样的：

```java
int i = 0;
for(;;) 
   ;
```

这被称为**无限循环**，在*无限循环*部分中有更详细的介绍。

### 注意

当你知道循环将被执行多少次时，通常使用 for 循环。通常使用一个控制整数变量作为数组的索引或在循环体内进行计算。

# for-each 语句

for-each 语句是在 Java 5 发布时引入的。有时它被称为增强型 for 循环。使用 for-each 语句的优点包括：

+   不需要为计数变量提供结束条件

+   它更简单，更易读

+   该语句提供了编译器优化的机会

+   泛型的使用变得更简单

for-each 语句与集合和数组一起使用。它提供了一种更容易遍历数组或实现了`java.util.Iterable`接口的类的每个成员的方法。由于`Iterable`接口是`java.util.Collection`接口的超级接口，因此 for-each 语句可以与实现`Collection`接口的类一起使用。

这个语句的语法与常规的 for 语句类似，除了括号内的内容。括号内包括数据类型，后跟一个变量，一个冒号，然后是数组名或集合，如下所示：

```java
for (<dataType variable>:<collection/array>)
   //statements;
```

它与集合的使用在*使用 for-each 语句与列表*部分进行了说明。在下面的序列中，声明了一个整数数组，初始化了它，并使用 for-each 语句显示了数组的每个元素：

```java
int numbers[] = new int[10];

for (int i = 0; i < 10; i++) {
   numbers[i] = i;
}

for (int element : numbers) {
   System.out.print(element + "  ");
}    
System.out.println();
```

numbers 数组的元素被初始化为它们的索引。请注意使用了 for 语句。这是因为我们无法在 for-each 语句中直接访问索引变量。在上述代码片段中，for-each 语句被读作“对于 numbers 中的每个元素”。在循环的每次迭代中，`element`对应数组的一个元素。它从第一个元素开始，直到最后一个元素结束。这个序列的输出如下：

```java
0 1 2 3 4 5 6 7 8 9

```

使用 for-each 语句与数组存在一些缺点。无法执行以下操作：

+   修改数组或列表中的当前位置

+   直接迭代多个数组或集合

例如，使用前面的例子，如果我们尝试使用以下代码修改包含 5 的数组元素，它不会导致语法错误。但它也不会修改相应的数组元素：

```java
for (int element : numbers) {
   if (element == 5) {
      element = -5;
   }
}

for (int element : numbers) {
   System.out.print(element + "  ");
}
System.out.println();
```

这个序列的输出如下：

```java
0 1 2 3 4 5 6 7 8 9

```

如果我们想要使用一个循环来访问两个不同的数组，就不能使用 for-each 循环。例如，如果我们想要将一个数组复制到另一个数组，我们需要使用 for 循环，如下所示：

```java
int source[] = new int[5];
int destination[] = new int[5];

for(int number : source) {
   number = 100;
}

for(int i = 0; i < 5; i++) {
   destination[i] = source[i];
}
```

虽然我们使用 for-each 来初始化源数组，但我们一次只能处理一个数组。因此，在第二个循环中，我们被迫使用 for 语句。

## 使用 for-each 语句与列表

我们将首先说明如何使用 for-each 语句与`ArrayList`。`ArrayList`类实现了`List`接口，该接口扩展了`Collection`接口。接口的使用和声明在第六章中有更详细的介绍，*类，构造函数和方法*。由于 for-each 语句可以与实现`Collection`接口的类一起使用，我们也可以将其与`ArrayList`类一起使用。在下一节中，我们将创建自己的`Iterable`类：

```java
ArrayList<String> list = new ArrayList<String>();

list.add("Lions and");
list.add("tigers and");
list.add("bears.");
list.add("Oh My!");

for(String word : list) {
   System.out.print(word + "  ");
}
System.out.println();
```

输出，正如你可能预测的那样，如下所示：

```java
Lions and tigers and bears. Oh My!

```

在这个例子中，使用 for-each 与数组的使用并没有太大的不同。我们只是使用了`ArrayList`的名称而不是数组名称。

使用 for-each 语句与列表具有与我们之前在数组中看到的类似的限制：

+   可能无法在遍历列表时删除元素

+   无法修改列表中的当前位置

+   不可能同时迭代多个集合

`remove`方法可能会抛出`UnsupportedOperationException`异常。这是可能的，因为`Iteratable`接口的`Iterator`的实现可能没有实现`remove`方法。这将在下一节详细说明。

在`ArrayList`的情况下，我们可以移除一个元素，如下面的代码片段所示：

```java
for(String word : list) {
   if(word.equals("bears.")) {
      list.remove(word);
      System.out.println(word + " removed");
   }
}

for(String word : list) {
   System.out.print(word + "  ");
}
System.out.println();
```

for-each 语句用于遍历列表。当找到`bears.`字符串时，它被移除。前面序列的输出如下：

```java
Lions and tigers and bears. Oh My! 
bears. removed
Lions and tigers and Oh My!

```

我们不能在 for-each 语句内修改列表。例如，以下代码序列尝试修改`word`并向`list`添加一个字符串。列表不会受到影响：

```java
for(String word : list) {
   if(word.equals("bears.")) {
      word = "kitty cats";
      list.add("kitty cats");
   }
}
```

尝试修改`word`变量并不会产生任何效果，也不会生成异常。但`add`方法不是这样。在前面的 for-each 语句中使用它将生成一个`java.util.ConcurrentModificationException`异常。

### 注意

与数组一样，使用 for-each 语句一次只能迭代一个集合。由于 for-each 语句只支持一个引用变量，因此一次只能访问一个列表。

如果您需要从列表中删除一个元素，请使用迭代器而不是 for-each 语句。

## 实现迭代器接口

如前所述，任何实现`Iterable`接口的类都可以与 for-each 语句一起使用。为了说明这一点，我们将创建两个类：

+   `MyIterator`：这实现了`Iterator`接口并支持一个简单的迭代

+   `MyIterable`：这使用`MyIterator`来支持它在 for-each 语句中的使用

首先，让我们来看一下接下来的`MyIterator`类。该类将迭代 1 到 10 的数字。它通过将`value`变量与 10 的上限进行比较，并在其`hasNext`方法中返回`true`或`false`来实现这一点。`next`方法只是返回并增加当前值。`remove`方法不受支持：

```java
import java.util.Iterator;

public class MyIterator implements Iterator<Integer> {
   private int value;
   private final int size;

   public MyIterator() {
      value = 1;
      size = 10;
   }

   @Override
   public boolean hasNext() {
      return value<=size;
   }

   @Override
   public Integer next() {
      return value++;
   }

   @Override
   public void remove() {
      throw new UnsupportedOperationException(
            "Not supported yet.");
   }
}
```

`MyIterable`类实现了`Iterable`接口。该接口包含一个方法`iterator`。在这个类中，它使用`MyIterator`类的一个实例来提供一个`Iterator`对象：

```java
import java.util.Iterator;

public class MyIterable implements Iterable<Integer> {
   private MyIterator iterator;

   public MyIterable() {
      iterator = new MyIterator();
   }

   @Override
   public Iterator<Integer> iterator() {
      return iterator;
   }
}
```

我们可以使用以下代码序列测试这些类：

```java
MyIterable iterable = new MyIterable();

for(Integer number : iterable) {
   System.out.print(number + "  ");
}
System.out.println();
```

输出将显示数字从 1 到 10，如下所示：

```java
1 2 3 4 5 6 7 8 9 10

```

### 注意

在许多情况下，并不总是需要使用`Iterator`方法来迭代集合。在许多情况下，for-each 语句提供了一种更方便和简单的技术。

## for-each 语句-使用问题

在使用 for-each 语句时，有几个问题需要注意：

+   如果数组/集合为空，您将会得到一个空指针异常

+   它可以很好地与具有可变数量参数的方法一起使用

### 空值

如果数组/集合为 null，您将获得一个空指针异常。考虑以下示例。我们创建了一个字符串数组，但未初始化第三个元素：

```java
String names[] = new String[5];
names[0] = "Will Turner";
names[1] = "Captain Jack Sparrow";
names[3] = "Barbossa";
names[4] = "Elizabeth Swann";
```

我们可以使用 for-each 语句显示名称，如下所示：

```java
for(String name : names) {
   System.out.println(name);
}
```

输出如下所示，将为缺失的条目显示`null`。这是因为`println`方法检查其参数是否为 null 值，当为 null 时，它会打印`null`：

```java
Will Turner
Captain Jack Sparrow
null
Barbossa
Elizabeth Swann

```

但是，如果我们对名称应用`toString`方法，我们将在第三个元素上得到`java.lang.NullPointerException`：

```java
for(String name : names) {
   System.out.println(name.toString());
}
```

如下输出所示，这是经过验证的：

```java
Will Turner
Captain Jack Sparrow
java.lang.NullPointerException

```

### 可变数量的参数

for-each 语句在使用可变数量的参数的方法中效果很好。关于使用可变数量的参数的方法的更详细解释可以在第六章的*可变数量的参数*部分找到。

在以下方法中，我们传递了可变数量的整数参数。接下来，我们计算这些整数的累积和并返回总和：

```java
public int total(int ... array) {
   int sum = 0;
   for(int number : array) {
      sum+=number;
   }
   return sum;
}
```

当使用以下调用执行时，我们得到`15`和`0`作为输出：

```java
result = total(1,2,3,4,5);
result = total();
```

但是，我们需要小心，不要传递`null`值，因为这将导致`java.lang.NullPointerException`，如下面的代码片段所示：

```java
result = total(null);
```

### 注意

尽可能使用 for-each 循环，而不是 for 循环。

# while 语句

while 语句提供了另一种重复执行一组语句的方法。当要执行块的次数未知时，它经常被使用。它的一般形式包括`while`关键字后跟一组括号括起来的逻辑表达式，然后是一个语句。只要逻辑表达式评估为 true，循环的主体将执行：

```java
while (<boolean-expression>) <statements>;
```

一个简单的示例重复了第一个 for 循环示例，其中我们在一行上显示数字 1 到 10：

```java
int i = 1;
while(i <= 10) {
   System.out.print(i++ + "  ");
}
System.out.println();
```

输出如下：

```java
1 2 3 4 5 6 7 8 9 10

```

以下示例稍微复杂一些，计算了`number`变量的因子：

```java
int number;
int divisor = 1;
Scanner scanner = new Scanner(System.in);
System.out.print("Enter a number: ");
number = scanner.nextInt();
while (number >= divisor) {
   if ((number % divisor) == 0) {
      System.out.printf("%d%n", divisor);
   }
   divisor++;
}
```

当使用输入`6`执行时，我们得到以下输出：

```java
Enter a number: 6
1
2
3
6

```

以下表格说明了语句序列的操作：

| 迭代次数 | 除数 | 数字 | 输出 |
| --- | --- | --- | --- |
| 1 | 1 | 6 | 1 |
| 2 | 2 | 6 | 2 |
| 3 | 3 | 6 | 3 |
| 4 | 4 | 6 |   |
| 5 | 5 | 6 |   |
| 6 | 6 | 6 | 6 |

在以下示例中，当用户输入负数时，循环将终止。在此过程中，它计算了输入数字的累积和：

```java
int number;
System.out.print("Enter a number: ");
number = scanner.nextInt();
while (number > 0) {
   sum += number;
   System.out.print("Enter a number: ");
   number = scanner.nextInt();
}
System.out.println("The sum is " + sum);
```

请注意，此示例重复了提示用户输入数字所需的代码。可以更优雅地使用 do-while 语句来处理这个问题，如下一节所讨论的。以下输出说明了对一系列数字执行此代码的执行情况：

```java
Enter a number: 8
Enter a number: 12
Enter a number: 4
Enter a number: -5
The sum is 24

```

while 语句对于需要未知循环次数的循环很有用。while 循环的主体将执行，直到循环表达式变为 false。当终止条件相当复杂时，它也很有用。

### 注意

while 语句的一个重要特点是在循环开始时对表达式进行评估。因此，如果逻辑表达式的第一次评估为 false，则循环的主体可能永远不会执行。

# do-while 语句

do-while 语句类似于 while 循环，不同之处在于循环的主体始终至少执行一次。它由`do`关键字后跟一个语句，`while`关键字，然后是括号括起来的逻辑表达式组成：

```java
do <statement> while (<boolean-expression>);
```

通常，do-while 循环的主体，如语句所表示的那样，是一个块语句。以下代码片段说明了 do 语句的用法。它是对前一节中使用的等效 while 循环的改进，因为它避免了在循环开始之前提示输入一个数字：

```java
int sum = 0;
int number;
Scanner scanner = new Scanner(System.in);
do {
   System.out.print("Enter a number: ");
   number = scanner.nextInt();
   if(number > 0 ) {
     sum += number;
   }
} while (number > 0);
System.out.println("The sum is " + sum);
```

当执行时，您应该获得类似以下的输出：

```java
Enter a number: 8
Enter a number: 12
Enter a number: 4
Enter a number: -5
The sum is 24

```

### 注意

`do-while`语句与`while`语句不同，因为表达式的评估发生在循环结束时。这意味着该语句至少会执行一次。

这个语句并不像`for`或`while`语句那样经常使用，但在循环底部进行测试时很有用。下一个语句序列将确定整数数字中的数字位数：

```java
int numOfDigits;
System.out.print("Enter a number: ");
Scanner scanner = new Scanner(System.in);
int number = scanner.nextInt();
numOfDigits = 0;
do {
   number /= 10;
   numOfDigits++;
} while (number != 0);
System.out.printf("Number of digits: %d%n", numOfDigits);
```

这个序列的输出如下：

```java
Enter a number: 452
Number of digits: 3

```

值`452`的结果如下表所示：

| 迭代次数 | 数字 | 数字位数 |
| --- | --- | --- |
| 0 | 452 | 0 |
| 1 | 45 | 1 |
| 2 | 4 | 2 |
| 3 | 0 | 3 |

# `break`语句

`break`语句的效果是终止当前循环，无论是`while`、`for`、`for-each`还是`do-while`语句。它也用于`switch`语句。`break`语句将控制传递给循环后面的下一个语句。`break`语句由关键字`break`组成。

考虑以下语句序列的影响，该序列会在无限循环中重复提示用户输入命令。当用户输入`Quit`命令时，循环将终止：

```java
String command;
while (true) {
   System.out.print("Enter a command: ");
   Scanner scanner = new Scanner(System.in);
   command = scanner.next();
   if ("Add".equals(command)) {
      // Process Add command
   } else if ("Subtract".equals(command)) {
      // Process Subtract command
   } else if ("Quit".equals(command)) {
      break;
   } else {
      System.out.println("Invalid Command");
   }
}

```

注意`equals`方法的使用方式。`equals`方法针对字符串字面量执行，并将命令用作其参数。这种方法避免了`NullPointerException`，如果命令包含空值，将会导致该异常。由于字符串字面量永远不会为空，这种异常永远不会发生。

# `continue`语句

`continue`语句用于将控制从循环内部转移到循环的末尾，但不像`break`语句那样退出循环。`continue`语句由关键字`continue`组成。

执行时，它会强制执行循环的逻辑表达式。在以下语句序列中：

```java
while (i < j) {
   …
   if (i < 0) {
      continue;
   }
   …
}
```

如果`i`小于`0`，它将绕过循环体的其余部分。如果循环条件`i<j`不为假，将执行循环的下一次迭代。

`continue`语句通常用于消除通常是必要的嵌套级别。如果没有使用`continue`语句，前面的示例将如下所示：

```java
while (i < j) {
   …
   if (i < 0) {
      // Do nothing
   } else {
      …
   }
}
```

# 嵌套循环

循环可以嵌套在彼此之内。可以嵌套组合`for`、`for-each`、`while`或`do-while`循环。这对解决许多问题很有用。接下来的示例计算了二维数组中一行元素的总和。它首先将每个元素初始化为其索引的总和。然后显示数组。然后使用嵌套循环计算并显示每行元素的总和：

```java
final int numberOfRows = 2;
final int numberOfColumns = 3;
int matrix[][] = new int[numberOfRows][numberOfColumns];

for (int i = 0; i < matrix.length; i++) {
   for (int j = 0; j < matrix[i].length; j++) {
      matrix[i][j] = i + j;
   }
}

for (int i = 0; i < matrix.length; i++) {
   for(int element : matrix[i]) {
      System.out.print(element + "  ");
   }
   System.out.println();
}  

for (int i = 0; i < matrix.length; i++) {
   int sum = 0;
   for(int element : matrix[i]) {
      sum += element;
   }
   System.out.println("Sum of row " + i + " is " +sum);
}
```

注意使用`length`方法来控制循环执行的次数。如果数组的大小发生变化，这将使代码更易于维护。执行时，我们得到以下输出：

```java
0 1 2 
1 2 3 
Sum of row 0 is 3
Sum of row 1 is 6

```

注意在显示数组和计算行的总和时使用`for-each`语句。这简化了计算。

`break`和`continue`语句也可以在嵌套循环中使用。但是，它们只能与当前循环一起使用。也就是说，从内部循环中跳出只会跳出内部循环，而不是外部循环。正如我们将在下一节中看到的，我们可以使用标签从内部循环中跳出外部循环。

在最后一个嵌套循环序列的修改中，当总和超过 2 时，我们跳出内部循环：

```java
for (int i = 0; i < matrix.length; i++) {
   int sum = 0;
   for(int element : matrix[i]) {
      sum += element;
      if(sum > 2) {
         break;
      }
   }
   System.out.println("Sum of row " + i + " is " +sum);
}
```

这个嵌套循环的执行将改变最后一行的总和，如下所示：

```java
Sum of row 0 is 3
Sum of row 1 is 3

```

`break`语句使我们跳出内部循环，但没有跳出外部循环。如果在外部循环的立即体中有相应的`break`语句，我们可以跳出外部循环。`continue`语句在内部和外部循环方面的行为类似。

# 使用标签

标签是程序内的位置名称。它们可以用于改变控制流，并且应该谨慎使用。在前面的例子中，我们无法使用 break 语句跳出最内层的循环。但是，标签可以用于跳出多个循环。

在下面的例子中，我们在外部循环前放置一个标签。在内部循环中，当`i`大于 0 时执行 break 语句，有效地在第一行的求和计算完成后终止外部循环。标签由名称后跟一个冒号组成：

```java
outerLoop:
for(int i = 0; i < 2; i++) {
   int sum = 0;
   for(int element : matrix[i]) {
      sum += element;
      if(i > 0) {
         break outerLoop;
      }
   }
   System.out.println("Sum of row " + i + " is " +sum);
}
```

这个序列的输出如下：

```java
Sum of row 0 is 3

```

我们也可以使用带有标签的 continue 语句来达到类似的效果。

### 注意

标签应该避免，因为它们会导致代码难以阅读和维护。

# 无限循环

无限循环是一种除非使用 break 语句等语句强制终止，否则将永远执行的循环。无限循环非常有用，可以避免循环的尴尬逻辑条件。

一个无限 while 循环应该使用`true`关键字作为其逻辑表达式：

```java
while (true) {
   // body
}
```

一个 for 循环可以简单到使用 nulls 作为 for 语句的每个部分：

```java
for (;;) {
   // body
}
```

一个永远不会终止的循环通常对大多数程序没有价值，因为大多数程序最终应该终止。然而，大多数无限循环都设计为使用 break 语句终止，如下所示：

```java
while (true) {
   // first part
   if(someCondition) {
      break;
   }
   // last part
}
```

这种技术相当常见，用于简化程序的逻辑。考虑需要读取年龄并在年龄为负时终止的需要。需要为年龄分配一个非负值，以确保循环至少执行一次：

```java
int age;
age = 1;
Scanner scanner = new Scanner(System.in);
while (age > 0) {
   System.out.print("Enter an age: ");
   age = scanner.nextInt();
   // use the age
}
```

另一个选择是在循环开始之前复制用户提示和用于读取年龄的语句：

```java
System.out.print("Enter an age: ");
age = scanner.nextInt();
while (age > 0) {
   System.out.print("Enter an age: ");
   age = scanner.nextInt();
   // use the age
}
```

在循环开始之前，要么需要为年龄分配一个任意值，要么需要复制代码。这两种方法都不令人满意。

然而，使用无限循环会导致更清晰的代码。不需要分配任意值，也不需要复制代码：

```java
while (true) {
   System.out.print("Enter an age: ");
   age = scanner.nextInt();
   if (age < 0) {
      break;
   }
   // use the age
}
```

虽然有许多情况下无限循环是可取的，但程序员在不小心的情况下也可能出现无限循环，导致意想不到的结果。一个常见的方式是构建一个没有有效终止条件的 for 循环，如下所示：

```java
for(int i = 1; i > 0; i++) {
   // Body
}
```

循环从`i`的值为 1 开始，并且在每次循环迭代时递增`i`。终止条件表明循环不会终止，因为`i`只会变得更大，因此总是大于 0。然而，最终变量会溢出，`i`会变成负数，循环将终止。这需要多长时间取决于机器的执行速度。

故事的寓意是，“小心循环”。无限循环既可以是解决某些问题的有用构造，也可以是在无意中使用时出现问题的构造。

# 时间就是一切

一个常见的编程需求是执行某种求和。我们在之前的例子中已经计算了几个数字序列的和。虽然求和过程相对简单，但对于新手程序员来说可能会很困难。更重要的是，我们将在这里使用它来提供对编程过程的洞察。

编程本质上是一个抽象的过程。程序员需要查看静态代码清单并推断其动态执行。这对很多人来说可能很困难。帮助开发人员编写代码的一种方法是考虑以下三个问题：

+   我们想要做什么？

+   我们想要怎么做？

+   我们想要做什么时候？

在这里，我们将询问并应用这三个问题的答案来解决求和问题。然而，这些问题同样适用于其他编程问题。

让我们专注于计算一组学生的平均年龄，这将涉及到求和过程。假设年龄存储在`age`数组中，然后按照以下代码片段中所示进行初始化：

```java
final int size = 5;
int age[] = new int[size];
int total;
float average;

age[0] = 23;
age[1] = 18;
age[2] = 19;
age[3] = 18;
age[4] = 21;
```

然后求和可以如下计算：

```java
total = 0;
for (int number : age) {
   total = total + number;
}
average = total / (age.length * 1.0f);
```

请注意，`total`明确地被赋予了零值。for 循环的每次迭代将把下一个`age`添加到`total`中。在循环完成时，`total`将被数组的长度乘以`1.0f`来计算平均值。通过使用数组长度，如果数组大小发生变化，代码表达式就不需要更改。乘以`1.0f`是为了避免整数除法。以下表格说明了循环执行时变量的值：

| 循环计数 | i | total |
| --- | --- | --- |
| 0 | - | 0 |
| 1 | 1 | 23 |
| 2 | 2 | 41 |
| 3 | 3 | 60 |
| 4 | 4 | 78 |
| 5 | 5 | 99 |

让我们从以下三个基本问题的角度来考虑这个问题：

+   **我们想要做什么**：我们想要计算一个部门的总工资。

+   **我们想要如何做**：这有一个多部分的答案。我们知道我们需要一个变量来保存总工资，`total`，并且它需要初始化为 0。

```java
total = 0;
```

我们还了解到计算累积和的基本操作如下：

```java
total = total + number;
```

循环需要使用数组的每个元素，因此使用 for-each 语句：

```java
for (int number : age) {
   …
}
```

我们已经为解决问题奠定了基础。

+   **我们想要什么时候做**：在这种情况下，“何时”暗示着三个基本选择：

+   在循环之前

+   在循环中

+   在循环之后

我们的解决方案的三个部分可以以不同的方式组合。基本操作需要在循环内部，因为它需要执行多次。只执行一次基本操作将不会得到我们喜欢的答案。

变量`total`需要初始化为 0。如何做到这一点？我们通过使用赋值语句来实现。这应该在循环之前、之中还是之后完成？在循环之后这样做是愚蠢的。当循环完成时，`total`应该包含答案，而不是零。如果我们在循环内部将其初始化为 0，那么在循环的每次迭代中，`total`都会被重置为 0。这让我们只能选择在循环之前放置该语句作为唯一有意义的选项。我们想要做的第一件事是将`total`赋值为 0。

大多数问题的解决方案似乎总是有所变化。例如，我们可以使用 while 循环而不是 for-each 循环。`+=`运算符可以用来简化基本操作。使用这些技术的一个潜在解决方案引入了一个索引变量：

```java
int index = 0;
total = 0;

while(index < age.length) {
   total += age[index++];
}
average = total / (age.length * 1.0f);
```

显然，并不总是有一个特定问题的最佳解决方案。这使得编程过程既是一种创造性的，也是一种潜在有趣的活动。

# 陷阱

与大多数编程结构一样，循环也有自己一套潜在的陷阱。在本节中，我们将讨论可能对不慎的开发人员造成问题的领域。

当程序员在每个语句后使用分号时，常见的问题之一是出现问题。例如，以下语句由于额外的分号导致无限循环：

```java
int i = 1;
while(i < 10) ;
  i++;
```

单独一行上的分号是空语句。这个语句什么也不做。然而，在这个例子中，它构成了 while 循环的主体部分。增量语句不是 while 循环的一部分。它是跟在 while 循环后面的第一个语句。缩进虽然是可取的，但并不会使语句成为循环的一部分。因此，`i`永远不会增加，逻辑控制表达式将始终返回 true。

在循环的主体部分没有使用块语句可能会导致问题。在下面的例子中，我们尝试计算从 1 到 5 的数字的乘积的总和。然而，这并不起作用，因为循环的主体部分只包括了乘积的计算。当求和语句缩进时，它不是循环的主体部分，只会执行一次：

```java
int sum = 0;
int product = 0;
for(int i = 1; i <= 5; i++)
   product = i * i;;
   sum += product;
```

循环的正确实现如下所示使用块语句：

```java
int sum = 0;
int product = 0;
for(int i = 1; i <= 5; i++) {
   product = i * i;;
   sum += product;
}
```

### 注意

在循环的主体中始终使用块语句是一个很好的策略，即使主体只包含一个语句。

在以下序列中，循环的主体由多个语句组成。然而，`i`从未递增。这也将导致无限循环，除非限制之一被更改或遇到 break 语句：

```java
int i = 0;
while(i<limit) {
  // Process i
}
```

即使是看似简单的循环，如果对浮点运算不小心，实际上可能是无限循环。在这个例子中，每次循环迭代时，`x`都会加上`0.1`。循环应该在`x`恰好等于`1.1`时停止。这永远不会发生，因为某些值的浮点数存储方式存在问题：

```java
float x = 0.1f;
while (x != 1.1) {
   System.out.printf("x = %f%n", x);
   x = x + 0.1f;
}
```

在二进制基数中，`0.1`不能被精确存储，就像分数 1/3 的十进制等价物无法被精确表示一样（0.333333…）。将这个数字重复添加到`x`的结果将导致一个不完全等于`1.1`的数字。比较`x != 1.1`将返回 true，循环永远不会结束。`printf`语句的输出不显示这种差异：

```java
…
x = 0.900000
x = 1.000000
x = 1.100000
x = 1.200000
x = 1.300000
…

```

在处理涉及自动装箱的操作时要小心。根据实现方式，如果频繁发生装箱和拆箱，可能会导致性能损失。

虽然不一定是陷阱，但要记住逻辑表达式可能会短路。也就是说，逻辑 AND 或 OR 操作的最后部分可能不会被评估，这取决于从第一部分评估返回的值。这在第三章的*短路评估*部分中有详细讨论，*决策结构*。

### 注意

请记住，数组、字符串和大多数集合都是从零开始的。忘记从`0`开始循环将忽略第一个元素。

始终使用块语句作为循环的主体。

# 总结

在本章中，我们研究了 Java 为循环提供的支持。我们已经说明了 for、for-each、while 和 do-while 语句的使用。这些演示提供了正确使用它们的见解，以及何时应该使用它们，何时不应该使用它们。

展示了使用 break 和 continue 语句，以及标签的使用。我们看到了 break 语句的实用性，特别是在支持无限循环时。标签虽然应该避免使用，但在跳出嵌套循环时可能会有用。

研究了各种陷阱，并研究了总结过程的创建，以深入了解一般编程问题。具体而言，它解决了代码段应放置在何处的问题。

现在我们已经了解了循环，我们准备研究类、方法和数据封装的创建，这是下一章的主题。

# 认证目标涵盖

在本章中，我们解决了以下认证目标：

+   创建和使用 while 循环

+   创建和使用 for 循环，包括增强的 for 循环

+   创建和使用 do/while 循环

+   比较循环结构

+   使用 break 和 continue

此外，我们还提供了对这些目标的额外覆盖：

+   定义变量的作用域

+   使用运算符和决策结构

+   声明和使用 ArrayList

# 测试你的知识

1.  给定以下声明，哪个语句将编译？

```java
int i = 5;
int j = 10;
```

a. `while(i < j) {}`

b. `while(i) {}`

c. `while(i = 5) {}`

d. `while((i = 12)!=5) {}`

1.  给定数组的以下声明，哪个语句将显示数组的每个元素？

```java
int arr[] = {1,2,3,4,5};
```

a. `for(int n : arr[]) { System.out.println(n); }`

b. `for(int n : arr) { System.out.println(n); }`

c. `for(int n=1; n < 6; n++) { System.out.println(arr[n]); }`

d. `for(int n=1; n <= 5; n++) { System.out.println(arr[n]); }`

1.  以下哪个 do/while 循环将在没有错误的情况下编译？

a.

```java
int i = 0;
do {
	System.out.println(i++);
} while (i < 5);

```

b.

```java
int i = 0;
do
	System.out.println(i++);
while (i < 5);

```

c.

```java
int i = 0;
do 
	System.out.println(i++);
while i < 5;

```

d.

```java
i = 0;
do
	System.out.println(i);
	i++;
while (i < 5);

```

1.  以下哪个循环是等价的？

a.

```java
for(String n : list) { 
	System.out.println(n);
}

```

b.

```java
for(int n = 0; n < list.size(); n++ ){ 
	System.out.println(list.get(n));
}

```

c.

```java
Iterator it = list.iterator();
while(it.hasNext()) {
	System.out.println(it.next());
}

```

1.  以下代码将输出什么？

```java
int i;
int j;
for (i=1; i < 4; i++) {
   for (j=2; j < 4; j++) {
      if (j == 3) {
         continue;
      }
      System.out.println("i: " + i + " j: " + j);
   }
}
```

a. `i: 1 j: 2i: 2 j: 2i: 3 j: 2`

b. `i: 1 j: 3i: 2 j: 3i: 3 j: 3`

c. `i: 1 j: 1i: 2 j: 1i: 3 j: 1`


# 第六章：类，构造函数和方法

面向对象编程的核心是类和从类创建的对象。对象的初始化发生在构造函数中，而对象状态的修改通过方法进行。这些构造函数和方法的封装是数据封装的重点。本章讨论了类，构造函数，方法和数据封装的基础知识。

我们从介绍类开始，包括如何在内存中管理对象。然后介绍了构造函数和方法的共同方面，包括签名的概念，参数的传递以及`this`关键字的用法。

讨论了构造函数的使用，包括默认构造函数，它们如何重载以及私有构造函数的使用。还介绍了 Java 初始化顺序，包括初始化程序列表的使用。

解释了方法及其用法，包括如何重载它们以及创建访问器和修改器方法。本章最后讨论了静态方法和实例方法。

# 类

**类**是数据结构的定义，以及对它们进行操作的动作，通常对应于现实世界的对象或概念。类只定义一次，但不会直接在应用程序中使用。相反，基于类创建（实例化）对象，并为对象分配内存。

在本章中，我们将使用`Employee`类来说明构造函数和方法的用法。该类的一部分如下所示：

```java
public class Employee {
    private String name;
    private int zip;
    private int age;
   …
}
```

这个定义将被扩展，以解释与类和对象相关的概念和技术。

## 对象创建

使用`new`关键字创建对象。该关键字与类名一起使用，导致为对象从堆中分配内存。堆是内存的一个区域，通常位于堆栈上方，如第二章中的*堆栈和堆*部分所述，*Java 数据类型及其使用*。

使用`new`关键字实例化新对象时：

+   为类的新实例分配内存

+   然后调用构造函数来初始化对象

+   返回对象的引用

在下面的例子中，创建了`Employee`类的两个实例，并将引用分配给引用变量`employee1`和`employee2`：

```java
Employee employee1 = new Employee();
Employee employee2 = new Employee();
```

类的每个实例都有自己独立的实例变量集。这在下图中显示。请注意，类的两个实例都包含它们自己的实例变量的副本：

![对象创建](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324_06_01.jpg)

当创建一个新对象时，会执行该对象的构造函数。构造函数的目的是初始化一个对象。这个过程在*构造函数*部分有详细介绍。类的方法在类的实例之间是共享的。也就是说，方法只有一个副本。

## 内存管理

Java 内存管理是动态和自动的。当使用`new`关键字时，它会自动在堆上分配内存。

在下面的例子中，创建了`Employee`类的一个实例，并将其分配给`employee1`变量。接下来，将`employee2`变量赋值为`employee1`变量的值。这种赋值的效果是两个引用变量都指向同一个对象：

```java
Employee employee1 = new Employee();
Employee employee2 = employee1;
```

下面的图表说明了这一点：

![内存管理](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324_06_02.jpg)

引用变量可以通过以下方式取消引用对象的实例：

+   被重新分配给另一个对象

+   将其设置为 null

当垃圾收集器确定没有引用指向它时，对象就有资格被垃圾收集线程从堆中移除，并且它的内存可以被重新使用。这个垃圾收集过程基本上是应用程序无法控制的。

## 数据封装

数据封装涉及隐藏程序员不相关的信息，并公开相关信息。隐藏实现细节允许更改而不影响程序的其他部分。例如，如果程序员想要在屏幕上显示一个矩形，可以使用几种方法。可能涉及逐像素绘制矩形或绘制一系列线条。隐藏操作的细节称为数据封装。

数据封装的主要目的是降低软件开发的复杂性。通过隐藏执行操作所需的细节，使用该操作变得更简单。该方法的使用并不复杂，因为用户不必担心其实现的细节。用户可以专注于它的功能，而不是它的实现方式。这反过来又使开发人员能够做更多事情。

例如，考虑`Employee`类的实现。最初，实例变量都声明为私有：

```java
public class Employee {
    public String name;
    private int age;

   ...

    public int getAge() {
        return age;
    }

    private void setAge(int age) {
        this.age = age;
    }

}
```

`name`变量的访问修饰符类型已更改为 public，`setAge`方法的访问修饰符已更改为 private。这意味着类的任何用户都可以访问`name`字段，但他们只能读取员工的`age`。当我们明确决定应该向类的用户公开什么和不公开什么时，数据封装就会受到影响。

类及其实现的细节应该对用户隐藏。这允许修改类内部的实现而不改变类的公共方面。通常情况下，实例变量被设置为私有，方法被设置为公共。根据类的需求，可以对此规则进行例外处理。

还可以控制对构造函数的访问。这个主题在*构造函数*部分有所涉及。

## 引用实例变量

引用变量保存对对象的引用或指针。通过在对象引用变量名称后跟一个句点，然后是字段或方法名称，可以访问对象的字段或变量。以下代码片段说明了基于前一节中`Employee`声明的`Employee`类的可能引用：

```java
Employee employee = new Employee();
int employeeAge = employee.getAge(24);
String employeeName = employee.name;
```

请注意，我们没有使用`age`字段，因为它被声明为`Employee`类的私有字段。修饰符的使用在第一章的*访问修饰符*部分中有所涉及，*Java 入门*。

## 签名

构造函数或方法的签名用于唯一标识构造函数或方法。签名由以下组成：

+   方法或构造函数名称

+   参数的数量

+   参数的类型

+   参数的顺序

同一类中的所有构造函数或方法必须具有唯一的签名。请注意，方法的返回类型不是签名的一部分。以下表格显示了重载`Employee`类构造函数的签名。第三个和第四个构造函数在构造函数参数的顺序上有所不同。如果同一类中有多个具有相同名称但具有不同签名的方法或构造函数，则称该方法或构造函数被重载：

| 方法 | 参数数量 | 参数类型 |
| --- | --- | --- |
| `Employee()` | 0 |   |
| `Employee(String name)` | 1 | `String` |
| `Employee(String name, int zip)` | 2 | `String`, `int` |
| `Employee(int zip, String name)` | 2 | `int`, `String` |
| `Employee(String name, int zip, int age)` | 3 | `String`, `int`, `int` |

# 使用 this 关键字

`this`关键字有四种用途：

+   执行构造函数链接

+   访问实例变量

+   将当前对象传递给方法

+   从方法返回当前对象

构造函数链接在*重载构造函数*部分进行了讨论。让我们来看一下使用`this`关键字访问实例变量的用法。`setAge`方法可以实现如下：

```java
public class Employee {
    public String name;
    private int age;
   ...

    private void setAge(int age) {
        age = age;
    }

}
```

这段代码不会产生修改`age`实例变量的预期结果。实例变量的作用域是整个类。参数的作用域仅限于方法。参数将优先于实例变量。结果是传递给方法的年龄被分配给自己。实例变量没有被修改。

纠正这个问题有两种方法：

+   更改参数名称

+   使用`this`关键字

我们可以更改参数的名称。然而，为同一事物设计不同的名称会导致奇怪或尴尬的名称。例如，我们可以使用以下方法：

```java
public class Employee {
  private int age;
     …
    private void setAge(int initialAge) {
        age = initialAge;
    }

}
```

`initialAge`参数将被分配为成员变量`age`的初始值。然而，也可以使用任意数量的其他可能有意义的名称。对于这种类型的参数，没有标准的命名约定。

另一种方法是使用`final`关键字将参数声明为常量，如下面的代码片段所示。当采用这种方法时，会生成语法错误，因为我们试图修改参数。由于它是常量，我们无法更改它：

```java
public void setAge(final int age) {
   age = age;
}
```

生成的语法错误消息如下：

```java
final parameter age may not be assigned

Assignment To Itself

```

首选方法是使用`this`关键字明确指定成员变量和参数。下面是一个示例：

```java
public class Employee {
  private int age;
   …
  private void setAge(int age) {
      this.age = age;
  }

}
```

在这个赋值语句中，我们使用`this`关键字和一个句点作为成员变量的前缀。考虑以下语句：

```java
       this.age = age;
```

`this`关键字引用了赋值语句左侧的`age`实例变量。在右侧，使用了`age`参数。因此，参数被分配给实例变量。使用`this`关键字避免了为参数分配给成员变量而设计一些非标准且可能令人困惑的名称。

`this`关键字也可以用于传递或返回对当前对象的引用。在下面的序列中，假定`validateEmployee`方法是`Employee`类的成员。如果满足条件，则当前员工，由`this`关键字标识，将被添加到一个维护部门信息的类中，该类由`department`变量引用。对当前对象的引用被传递给`add`方法：

```java
private Department department;
   …
private void validateEmployee() {
   if(someCondition) {
      department.add(this);
   }
}
```

`this`关键字也可以用于返回对当前对象的引用。在下一个序列中，当前对象由假定为`Employee`类的`getReference`方法返回：

```java
private Employee getReference() {
   …
   return this;
}
```

## 传递参数

在任何方法中可能存在两种类型的变量——参数和局部变量。参数包含在调用方法时传递的值。局部变量是方法的一部分，并用于帮助方法完成其任务。这里讨论的技术适用于构造函数和方法，尽管在本节的示例中我们只使用方法。

参数作为参数列表的一部分传递。此列表使用逗号来分隔参数的类型和名称的声明。例如，以下代码片段中的方法传递了两个参数——一个整数和一个字符串：

```java
public void passParameters(int number, String label) {
   …
}
```

原始数据类型或对象被传递给方法。以下术语用于标识被传递的数据：

+   参数：被传递的变量

+   参数：这是在方法签名中定义的元素

例如，在以下代码序列中，`number`和`employee1`是参数，而`num`和`employee`是`changeValues`方法的相应参数：

```java
public static void main(String[] args) {
   int number = 10;
   Employee employee1 = new Employee();
   changeValues(number, employee1);
   …
}

private static void changeValues(int num, 
   Employee employee) {
   …
}
```

在 Java 中，只有原始数据类型和对象引用被传递给方法或构造函数。这是使用一种称为**传值**的技术执行的。当调用方法时，参数被分配给参数的副本。

当传递原始数据类型时，只传递值的副本。这意味着如果在被调用的方法中更改了副本，则原始数据不会更改。

当传递引用变量时，只传递引用的副本。对象本身不会被传递或复制。此时我们有两个对同一对象的引用——参数引用变量和参数引用变量。我们可以使用任一引用变量修改对象。

我们还可以更改参数的引用。也就是说，我们可以修改参数以引用不同的对象。如果我们修改参数，我们并没有修改参数。参数和参数引用变量是不同的变量。

考虑以下程序，我们将一个整数和一个`Employee`对象的引用传递给`changeValues`方法。在方法中，我们更改整数，`Employee`对象的一个字段，以及`employee`引用变量。

```java
public static void main(String[] args) {
   …
   int number = 10;
   employee = new Employee();
   employee.setAge(11);
   changeValues(number, employee);

   System.out.println(number);
   System.out.println(employee.getAge());

}
```

```java
private static void changeValues(int num, Employee employee) {
   num = 20;
   employee.setAge(22);
   employee = new Employee();
   employee.setAge(33);
}
```

执行时我们得到以下输出：

```java
10
22

```

### 注意

请注意，当我们更改`num`参数的值时，`main`方法的`number`变量没有更改。此外，我们使用`changeValues`方法的`employee`引用变量更改了对象的`age`字段。但是，当我们通过创建一个新的 employee 修改了`changeValues`方法的`employee`引用变量指向的内容时，我们并没有更改`main`方法的`employee`引用变量。它仍然引用原始对象。

以下图示说明了这是如何工作的。堆栈和堆反映了应用程序在启动`changeValues`方法时和在它返回之前的状态。为简单起见，我们忽略了`args`变量：

![传递参数](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324_06_03.jpg)

通过值传递对象是一种高效的参数传递技术。它是高效的，因为我们不复制整个对象。我们只复制对象的引用。

### 可变数量的参数

可以将可变数量的参数传递给方法。但是，有一些限制：

+   可变数量的参数必须都是相同的类型

+   它们在方法中被视为数组

+   它们必须是方法的最后一个参数

要理解这些限制，请考虑以下代码片段中使用的方法，用于返回整数列表中的最大整数：

```java
private static int largest(int... numbers) {
   int currentLargest = numbers[0];
   for (int number : numbers) {
      if (number > currentLargest) {
         currentLargest = number;
      }
   }
   return currentLargest;
}
```

不需要将具有可变数量参数的方法声明为静态。我们这样做是为了可以从静态的`main`方法中调用它。在以下代码序列中，我们调用该方法两次：

```java
System.out.println(largest(12, -12, 45, 4, 345, 23, 49));
System.out.println(largest(-43, -12, -705, -48, -3));
```

输出如下：

```java
345
-3

```

`largest`方法将第一个参数，`numbers`数组的第一个元素，分配给`currentLargest`。它假设最大的数字是第一个参数。如果不是，那么它最终会被替换。这避免了将最小可能值分配给`currentLargest`变量。

### 注意

最大和最小的整数分别在`Integer`类中定义为`Integer.MAX_VALUE`和`Integer.MIN_VALUE`。

我们使用 for-each 语句将 numbers 数组的每个元素与最大变量进行比较。如果数字更大，那么我们用该数字替换`largest`。for-each 语句在第五章的*for-each 语句*部分详细说明了循环结构。

如果我们不带参数调用该方法，如下所示：

```java
System.out.println(largest());
```

程序将执行，但会生成`ArrayIndexOutOfBoundsException`异常。这是因为我们尝试在方法中访问数组的第一个元素，但该数组为空，因此不存在第一个元素。如果在方法中没有引用第一个元素，这个问题就不会发生。也就是说，在大多数情况下，使用可变数量的参数的方法可以不带参数调用。

我们可以实现一个`largest`方法的版本，处理没有传递参数的情况。然而，当没有传递任何内容时，返回值应该是什么？我们返回的任何值都会暗示该数字是最大的，而实际上并没有最大的数字。我们能做的最好可能就是返回一个反映这个问题的异常。然而，这实际上就是当前版本所做的。异常`ArrayIndexOutOfBoundsException`可能不如自定义异常有意义。

我们可以在具有可变数量参数的方法中使用其他参数。在下面的示例中，我们将一个字符串和零个或多个浮点数传递给`displayAspects`方法。该方法的目的是显示由第一个参数标识的元素的信息：

```java
private static void displayAspects(String item, 
    float... aspects) {
   ...    
}
```

以下代码是方法可能被调用的示例：

```java
displayAspects("Europa", 2.3f, 56.005f, 0.0034f);
```

### 注意

可变参数必须是相同类型，并且必须是参数列表中的最后一个参数。

## 不可变对象

不可变对象是其状态无法更改的对象。所谓状态，是指其成员变量的值。这些类型的对象可以简化应用程序，并且更不容易出错。JDK 核心中有几个不可变的类，包括`String`类。

创建不可变对象：

+   使类变为 final，这意味着它不能被扩展（在第七章的*使用 final 关键字与类*部分中有介绍，*继承和多态*）

+   将类的字段保持为私有，最好是 final

d. 不提供任何修改对象状态的方法，即不提供 setter 或类似的方法

d. 不允许可变字段对象被更改

以下是一个表示页面标题的不可变类的声明示例：

```java
package packt;

import java.util.Date;

final public class Header {
    private final String title;
    private final int version;
    private final Date date;

    public Date getDate() {
        return new Date(date.getTime());
    }

    public String getTitle() {
        return title;
    }

    public int getVersion() {
        return version;
    }

    public Header(String title, int version, Date date) {
        this.title = title;
        this.version = version;
        this.date = new Date(date.getTime());
    }

    public String toString() {
        return  "Title: " + this.title + "\n" +
                "Version: " + this.version + "\n" +
                "Date: " + this.date + "\n";
    }
}
```

注意`getDate`方法创建了一个基于标题的`date`字段的新`Date`对象。任何`Date`对象都是可变的，因此通过返回日期的副本而不是当前日期的引用，用户无法访问和修改私有字段。三参数构造函数也使用了相同的方法。

# 构造函数

构造函数用于初始化类的成员变量。当创建对象时，为对象分配内存，并执行类的构造函数。这通常使用`new`关键字来实现。

初始化对象的实例变量是重要的。开发人员的责任之一是确保对象的状态始终有效。为了协助这一过程，构造函数在创建对象时执行。

另一种方法是使用初始化方法，程序员应该在创建对象后调用该方法。然而，使用这种初始化方法并不是一种万无一失的技术。程序员可能不知道该方法的存在，或者可能忘记调用该方法。为了避免这类问题，当创建对象时会自动调用构造函数。

构造函数的重要特点包括：

+   构造函数与类名相同

+   构造函数重载是允许的

+   构造函数不是方法

+   构造函数没有返回类型，甚至没有 void

下面的代码片段说明了如何定义构造函数。在这个例子中，定义了三个重载的构造函数。目前，我们省略了它们的主体。这些构造函数的目的是初始化组成类的三个实例变量：

```java
public class Employee {
   private String name;
   private int zip;
   private int age;

   public Employee() {

   }

   public Employee(String name) {

   }

   public Employee(String name, int zip) {

   }

}
```

## 默认构造函数

通常类都会有默认构造函数。如果一个类没有显式声明任何构造函数，它会自动拥有一个默认构造函数。默认构造函数是一个没有参数的构造函数。下面的代码片段演示了`Employee`类中没有定义构造函数的情况：

```java
public class Employee {
   private String name;
   private int zip;
   private int age;

   …

}
```

默认构造函数本质上会将其实例变量初始化为 0，就像第二章中的*初始化标识符*部分所解释的那样，*Java 数据类型及其使用*。分配给成员变量的值在下表中找到，该表从第二章中的*Java 数据类型及其使用*部分复制过来，以方便您查阅：

| 数据类型 | 默认值（对于字段） |
| --- | --- |
| 布尔值 | false |
| 字节 | 0 |
| 字符 | '\u0000' |
| 短整型 | 0 |
| 整型 | 0 |
| 长整型 | 0L |
| 浮点数 | 0.0f |
| 双精度 | 0.0d |
| 字符串（或任何对象） | null |

然而，我们也可以添加一个显式的默认构造函数，如下面的代码片段所示。默认构造函数是一个没有参数的构造函数。正如我们所看到的，我们可以自由地将类的字段初始化为我们选择的任何值。对于我们没有初始化的字段，JVM 将会像上面详细说明的那样将它们初始化为零：

```java
public Employee() {
    this.name = "Default name";
    this.zip = 12345;
    this.age = 21;
}
```

注意使用`this`关键字。在这个上下文中，它用于明确指定紧随其后的变量是类成员变量，而不是其他局部变量。在这里，没有其他可能引起混淆的变量。`this`关键字在*使用 this 关键字*部分有详细介绍。在成员变量中使用`this`关键字是一种常见做法。

如果程序员向类添加了构造函数，那么该类将不再自动添加默认构造函数。程序员必须显式为类添加一个默认构造函数。在下面的`Employee`类的声明中，省略了默认构造函数：

```java
public class Employee {
   private String name;
   private int zip;
   private int age;
   public Employee(String name) {

   }

   …

}
```

如果我们尝试使用默认构造函数创建对象，如下面的代码片段所示，那么我们将会得到一个语法错误：

```java
Employee employee1 = new Employee();
```

生成的错误消息如下：

```java
no suitable constructor found for Employee()

```

### 注意

一般规则是，总是为类添加一个默认构造函数。当类是一个基类时，这一点尤为重要。

## 构造函数的重载

构造函数可以被重载。通过重载构造函数，我们为类的用户提供了更多创建对象的灵活性。这可以简化开发过程。

重载的构造函数具有相同的名称但不同的签名。签名的定义在之前讨论的*签名*部分中提供。在`Employee`类的以下版本中，我们提供了四个构造函数。请注意，每个构造函数为那些没有通过构造函数传递的成员变量分配了默认值：

```java
public class Employee {
   private String name;
   private int zip;
   private int age;

   public Employee() {
       this.name = "Default name";
       this.zip = 12345;
       this.age = 21;
   }
   public Employee(String name) {
       this.name = name;
       this.zip = 12345;
       this.age = 21;
   }
   public Employee(String name, int zip) {
       this.name = name;
       this.zip = zip;
       this.age = 21;
   }

   public Employee(String name, int zip, int age) {
       this.name = name;
       this.zip = zip;
       this.age = age;
   }

}
```

这个例子在构造函数之间重复了工作。另一种方法如下所示，使用`this`关键字来减少这种重复的工作并简化整个过程：

```java
public class Employee {
   private String name;
   private int zip;
   private int age;

   public Employee() {
       this("Default name", 12345, 21);
   }

   public Employee(String name) {
       this(name, 12345, 21);
   }

   public Employee(String name, int zip) {
       this(name, zip, 21);
   }

   public Employee(String name, int zip, int age) {
       this.name = name;
       this.zip = zip;
       this.age = age;
   }
}
```

在这种情况下，`this`关键字用于构造函数的参数列表开头。其效果是调用与使用的签名匹配的同一类构造函数。在这个例子中，前三个构造函数中的每一个都调用最后一个构造函数。这被称为**构造函数链**。所有的工作都是在最后一个构造函数中完成的，减少了重复工作的量和出错的机会，特别是当添加新字段时。

如果在构造函数中对字段变量进行赋值之前进行检查，这样会更加高效。例如，如果我们需要验证名称是否符合特定的命名标准，只需要在一个位置执行，而不是在每个传递名称的构造函数中执行。

## 私有构造函数

可以将构造函数声明为私有，以便将其隐藏。这样做可能是为了：

+   限制对类的某些构造函数的访问，而不是全部

+   隐藏所有构造函数

在某些情况下，我们可能希望将构造函数设置为私有或受保护（参见第七章中的*继承和多态*，讨论`protected`关键字）以限制对某些初始化序列的访问。例如，私有构造函数可以用于以较不严格的方式初始化类的字段。由于我们从其他构造函数中调用构造函数，我们可能更加确信被赋值的值，并且不觉得需要对其参数进行广泛的检查。

在某些情况下，我们可能希望将所有构造函数声明为私有。这将限制用户通过类的公共方法创建对象。`java.util.Calendar`类就是这样一个例子。获取此类的实例的唯一方法是使用其静态的`getInstance`方法。

私有构造函数的使用用于控制应用程序可以创建的类实例的数量。单例设计模式规定一个类只能创建一个实例。这种设计模式可以通过将所有构造函数设为私有，并提供一个公共的`getInstance`方法来创建类的单个实例来支持。

以下是`Employee`类的这种方法的示例。构造函数被设置为私有，`getInstance`方法确保只创建一个对象：

```java
public class Employee {
   private static Employee instance = null;
   private String name;
   private int zip;
   private int age;

   private Employee instance = null;
   ...

   private Employee() {
      this.name = "Default name";
      this.zip = 12345;
      this.age = 21;
   }

   public Employee getInstance() {
      if(instance == null) {
         instance = new Employee();
      }
      return instance;
   }

   ...
}
```

第一次调用`getInstance`方法时，`instance`变量为 null，这导致创建一个新的`Employee`对象。在对`getInstance`方法的后续调用中，`instance`将不为 null，不会创建新的`Employee`对象。而是返回对单个对象的当前引用。

## 构造函数问题

如果一个“构造函数”有返回类型，实际上它是一个方法，恰好与类名相同。即使返回类型是`void`，也是如此，如下面的代码片段所示：

```java
public void Employee(String name) {

}
```

我们可以创建`Employee`类的新实例，然后对该对象应用`Employee`方法，如下面的代码片段所示：

```java
Employee employee = new Employee();
employee.Employee("Calling a method");
```

虽然这是合法的，但不是良好的风格，可能会令人困惑。此外，正如我们在第一章中看到的*Java 命名约定*部分，方法的命名约定建议方法名的初始单词应以小写字母开头。

## Java 初始化序列

构造函数涉及对象字段的初始化。然而，还有两种方法可以用来补充构造函数的使用。第一种是使用实例变量初始化器。使用`Employee`类，我们可以将年龄初始化为 21，如下所示：

```java
public class Employee {
   ...
   private int age = 21;

   ...

}
```

如果我们以这种方式初始化实例变量，就不必在构造函数中初始化它。

第二种方法是使用初始化块。这种类型的块在构造函数执行之前执行。下面的代码片段说明了这种方法：

```java
public class Employee {
   ...
   private int age;

   // Initialization block
   {
      age = 31;
   }
   ...
}
```

初始化块在需要更复杂的初始化序列时非常有用，这是无法通过更简单的实例变量初始化器支持的。这种初始化也可以在构造函数中执行。

因此，有几种初始化成员变量的方法。如果我们使用其中一种或多种技术来初始化相同的变量，那么我们可能会想知道它们的执行顺序。实际的初始化顺序比这里描述的要复杂一些。但是，一般的顺序如下：

1.  在实例化对象时执行字段的清零

1.  final 和静态变量的初始化

1.  分配实例变量初始化器

1.  初始化块的执行

1.  构造函数中的代码

有关初始化顺序的更多详细信息可以在 Java 语言规范([`docs.oracle.com/javase/specs/`](http://docs.oracle.com/javase/specs/))中找到。

# 方法

**方法**是一组语句，用于完成特定的任务。方法具有返回值、名称、一组参数和一个主体。参数被传递给方法，并用于执行操作。如果要从方法返回一个值，则使用返回语句。一个方法可能有零个或多个返回语句。返回`void`的方法可能使用返回语句，但该语句没有参数。

## 定义方法

方法是作为类定义的一部分来定义的，通常在实例变量的声明之后。方法声明指定了返回类型。返回类型`void`表示该方法不返回值。

### 注意

Java 方法的命名约定指定第一个单词不大写，但后续的单词大写。方法名应该是动词。

在以下示例中，该方法返回`boolean`，并传递了两个整数参数：

```java
public boolean isAgeInRange(int startAge, int endAge) {
    return (startAge <= age) && (age <= endAge); }
```

同一程序中的所有方法必须具有唯一的签名。签名在前面的*签名*部分中有讨论。请注意，方法的返回类型不是签名的一部分。例如，考虑以下代码片段中的声明：

```java
   public int getAgeInMonths() {
      …
   }

   public float getAgeInMonths() {
      …
   }
```

这两种方法的签名是相同的。返回类型不被使用。如果我们尝试在`Employee`类中声明这两种方法，将会得到以下语法错误消息：

```java
getAgeInMonths() is already defined in packt.Employee

```

## 调用方法

调用方法的语法看起来类似于使用实例变量。实例方法将始终针对一个对象执行。正常的语法使用对象的名称，后跟一个句点，然后是方法的名称和任何需要的参数。在以下示例中，`getAgeInMonths`方法针对`employee`引用变量被调用：

```java
Employee employee = new Employee();
System.out.println(employee.getAgeInMonths());
```

静态方法可以使用类名或对象来调用。考虑以下静态变量`entityCode`的声明：

```java
public class Employee {
    // static variables
    private static int entityCode;

    public static void setEntityCode(int entityCode) {
        Employee.entityCode = entityCode;
    }
   ...
}
```

以下代码片段中的两个方法调用都将调用相同的方法：

```java
Employee employee = new Employee();
employee.setEntityCode(42);
Employee.setEntityCode(42);
```

但是，使用引用变量调用静态方法并不是一个好的做法。而应该始终使用类名。尝试使用对象将导致以下语法警告：

```java
Accessing static method setEntityCode

```

### 注意

静态方法在*实例和静态类成员*部分有详细说明。

如果不向方法传递参数，则参数列表可以为空。在以下简化的方法中，返回员工的年龄（以月为单位）。没有向方法传递参数，并返回一个整数。该方法被简化了，因为实际的值需要考虑员工的出生日期和当前日期：

```java
public int getAgeInMonths() {
    int months = age*12;
    return months;
}
```

## 方法的重载

Java 允许具有相同名称的多个方法。这为实现参数类型不同的方法提供了一种便捷的技术。重载的方法都具有相同的方法名称。这些方法的区别在于每个重载的方法必须具有唯一的签名。签名在前面的*签名*部分中有讨论。请记住，方法的返回类型不是签名的一部分。

以下代码片段说明了方法的重载：

```java
int max(int, int);
int max(int, int, int);  // Different number of parameters
int max(int …);         // Varying number of arguments
int max(int, float);    // Different type of parameters
int max(float, int)    // Different order of parameters
```

在调用重载方法时必须小心，因为编译器可能无法确定使用哪个方法。考虑以下 `max` 方法的声明：

```java
class OverloadingDemo {

    public int max(int n1, int n2, int n3) {
        return 0;
    }

    public float max(long n1, long n2, long n3) {
        return 0.0f;
    }

    public float max(float n1, float n2) {
        return 0.0f;
    }
}
```

以下代码序列说明了会给编译器带来问题的情况：

```java
int num;
float result;
OverloadingDemo demo = new OverloadingDemo();
num = demo.max(45, 98, 2);
num = demo.max(45L, 98L, 2L);		// assignment issue
result = demo.max(45L, 98L, 2L);
num = demo.max(45, 98, 2L);       // assignment issue
result = demo.max(45, 98, 2L);
result = demo.max(45.0f, 0.056f);
result = demo.max(45.0, 0.056f);  // Overload problem
```

第二个和第四个赋值语句将与三个长参数方法调用匹配。这对于第二个是预期的。对于第四个赋值，只有一个参数是长整型，但它仍然使用了三个长参数方法。这些赋值的问题在于该方法返回 `long` 而不是 `int`。它无法将浮点值分配给 `int` 变量而不会丢失精度，如以下语法错误消息所示：

```java
possible loss of precision
  required: int
  found:    float
```

最后一个赋值找不到可接受的重载方法。以下语法错误消息结果如下：

```java
no suitable method found for max(double,float)

```

### 注意

与重载密切相关的是重写方法的过程。通过重写，两个方法的签名是相同的，但它们位于不同的类中。这个主题在第七章的*继承和多态*部分中有所涉及。

## 访问器/修改器

访问器方法是读取或访问类的变量的方法。修改器方法是修改类的变量的方法。这些方法通常是公共的，变量通常声明为私有的。这是数据封装的重要部分。私有数据对用户隐藏，但通过方法提供访问。

访问器和修改器方法应使用一致的命名约定。该约定使用私有成员变量名称作为基础，并在基础前加上 get 或 set 前缀。get 方法返回变量的值，而 set 方法接受一个参数，该参数被分配给私有变量。在这两种方法中，成员变量名称都是大写的。

这种方法用于 `Employee` 类的私有 `age` 字段：

```java
public class Employee {
   ...
   private int age;
   ...
   public int getAge() {
      return age;
   }

   public void setAge(int age) {
      this.age = age;
   }
}
```

注意 `getAge` 的返回类型是 `int`，也是 `setAge` 方法的参数类型。这是访问器和修改器的标准格式。访问器方法通常被称为 getters，修改器方法被称为 setters。

私有数据通常通过将其设置为私有并提供公共方法来访问而进行封装。具有私有或不存在设置器的字段被称为**只读字段**。具有私有或不存在获取器的字段被称为**只写字段**，但不太常见。获取器和设置器的主要原因是限制访问并对字段进行额外处理。

例如，我们可能有一个 `getWidth` 方法，返回 `Rectangle` 类的宽度。但是，返回的值可能取决于所使用的测量单位。它可能根据另一个测量单位字段设置为英寸、厘米或像素而返回一个值。在一个安全意识强的环境中，我们可能希望限制可以根据用户或者时间来读取或写入的内容。

# 实例和静态类成员

有两种类型的变量或方法：

+   实例

+   静态

实例变量声明为类的一部分，并与对象关联。静态变量以相同的方式声明，只是在前面加上 `static` 关键字。当创建对象时，它有自己的一组实例变量。但是，所有对象共享静态变量的单个副本。

有时，有一个可以被所有类实例共享和访问的单个变量是有意义的。当与变量一起使用时，它被称为**类变量**，并且仅限于类本身。

考虑以下 `Employee` 类：

```java
public class Employee {
    // static variables
    private static int minimumAge;

    // instance variables
    private String name;
    private int zip;
    private int age;

   ...
}
```

每个`Employee`对象都将有自己的`name`、`zip`和`age`变量的副本。所有`Employee`对象可能共享相同的`minimumAge`变量。使用单个变量的副本确保了类的所有部分都可以访问和使用相同的值，并且节省了空间。

考虑以下代码序列：

```java
Employee employee1 = new Employee();
Employee employee2 = new Employee();
```

以下图表说明了堆中两个对象的分配情况。每个对象都有自己的一组实例变量。单个静态变量显示在堆的上方，分配在自己的特殊内存区域中：

![实例和静态类成员](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324_06_04.jpg)

无论方法是实例方法还是静态方法，对于一个类来说，每个方法只有一个副本。静态方法的声明方式与实例方法相同，只是在方法的声明之前加上`static`关键字。以下代码片段中的静态`setMinimumAge`方法说明了静态方法的声明：

```java
public static void setMinimumAge(int minimumAge) {
   Employee.minimumAge = minimumAge;
}
```

所有实例方法必须针对一个对象执行。不可能像静态方法那样针对类名执行。实例方法旨在访问或修改实例变量。因此，它需要针对具有实例变量的对象执行。如果我们尝试针对类名执行实例方法，如下所示：

```java
Employee.getAge();
```

这将导致以下语法错误消息：

```java
non-static method getAge() cannot be referenced from a static context

```

静态方法可以针对对象或类名执行。静态方法可能无法访问实例变量或调用实例方法。由于静态方法可以针对类名执行，这意味着即使可能不存在任何对象，它也可以执行。如果没有对象，那么就不可能有实例变量。因此，静态方法无法访问实例变量。

静态方法可能不会调用实例方法。如果它能够访问实例方法，那么它间接地就能够访问实例变量。由于可能不存在任何对象，因此静态方法不允许调用实例方法。

实例方法可以访问静态变量或调用静态方法。静态变量始终存在。因此，实例方法应该能够访问静态变量和方法是毫无理由的。

以下表格总结了静态/实例变量和方法之间的关系：

|   | 变量 |   | 方法 |   |
| --- | --- | --- | --- | --- |
|   | 实例 | 静态 | 实例 | 静态 |
| 实例方法 | ![实例和静态类成员](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324EN_06_05.jpg) | ![实例和静态类成员](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324EN_06_05.jpg) | ![实例和静态类成员](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324EN_06_05.jpg) | ![实例和静态类成员](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324EN_06_05.jpg) |
| 静态方法 | ![实例和静态类成员](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324EN_06_06.jpg) | ![实例和静态类成员](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324EN_06_05.jpg) | ![实例和静态类成员](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324EN_06_06.jpg) | ![实例和静态类成员](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-se7-std-gd/img/7324EN_06_05.jpg) |

# 总结

在本章中，我们考察了类的许多重要方面。这包括创建类的实例时如何管理内存，初始化过程以及如何调用方法来使用类。

构造函数和方法都涉及到几个问题。在详细讨论构造函数和方法的细节之前，我们讨论了使用`this`关键字、传递参数和签名。我们还举例说明了构造函数和各种初始化技术，包括这些初始化发生的顺序。还讨论了方法的声明，包括如何重载方法。

我们还考察了实例和静态变量、方法之间的区别。在整个章节中，我们阐明了内存的分配方式。

现在我们已经学习了类的基础知识，我们准备讨论继承和多态的主题，如下一章所讨论的那样。在那一章中，我们将扩展内存分配、初始化顺序，并介绍新的主题，比如重写方法。

# 涵盖的认证目标

本章涵盖的认证目标包括：

+   创建带有参数和返回值的方法

+   将`static`关键字应用于方法和字段

+   创建重载方法

+   区分默认构造函数和用户定义的构造函数

+   应用访问修饰符

+   将封装原则应用于类

+   确定当对象引用和原始值传递到改变值的方法中时的影响

# 测试你的知识

1.  以下哪个声明了一个接受浮点数和整数并返回整数数组的方法？

a. `public int[] someMethod(int i, float f) { return new` `int[5];}`

b. `public int[] someMethod(int i, float f) { return new int[];}`

c. `public int[] someMethod(int i, float f) { return new int[i];}`

d. `public int []someMethod(int i, float f) { return new int[5];}`

1.  如果尝试编译和运行以下代码会发生什么？

```java
public class SomeClass {public static void main(String arguments[]) {
      someMethod(arguments);
   }
   public void someMethod(String[] parameters) {
      System.out.println(parameters);
   }
}
```

a. 语法错误 - `main`没有正确声明。

b. 语法错误 - 变量参数不能像在`println`方法中那样使用。

c. 语法错误 - `someMethod`需要声明为静态。

d. 程序将无错误地执行。

1.  以下关于重载方法的陈述哪些是真的？

a. 静态方法不能被重载。

b. 在重载方法时，不考虑返回值。

c. 私有方法不能被重载。

d. 重载的方法不能抛出异常。

1.  给定以下代码，以下哪些陈述是真的？

```java
public class SomeClass {
   public SomeClass(int i, float f) { }
   public SomeClass(float f, int i) { }
   public SomeClass(float f) { }
   public void SomeClass() { }
}
```

a. 由于 void 不能与构造函数一起使用，将会发生语法错误。

b. 由于前两个构造函数不是唯一的，将会发生语法错误。

c. 该类没有默认构造函数。

d. 不会生成语法错误。

1.  在声明类时，以下关键字中哪个不能使用？

a. `public`

b. `private`

c. `protected`

d. `package`

1.  假设以下类在同一个包中，哪些陈述是真的？

```java
class SomeClass {void method1() { }public void method2( { }
   private void method3( { }
   protected void method4() { }
}

class demo [
   public void someMethod(String[] parameters) {SomeClass sc = new SomeClass();
      sc.method1();
      sc.method2();
      sc.method3();
      sc.method41();}
}
```

a. `sc.method1()`将生成语法错误。

b. `sc.method2()`将生成语法错误。

c. `sc.method3()`将生成语法错误。

d. `sc.method4()`将生成语法错误。

e. 不会生成语法错误。

1.  以下代码的输出是什么？

```java
public static void main(String args[]) { 
    String s = "string 1";
    int i = 5;
    someMethod1(i);
    System.out.println(i);
    someMethod2(s);
    System.out.println(s);
}

public static void someMethod1(int i) { 
    System.out.println(++i);
}
public static void someMethod2(String s) { 
    s = "string 2"; 
    System.out.println(s);
}
```

a. `5 5 string 2 string 1`

b. `6 6 string 2 string 2`

c. `5 5 string 2 string 2`

d. `6 5 string 2 string 1`
