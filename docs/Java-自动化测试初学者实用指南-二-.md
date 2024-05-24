# Java 自动化测试初学者实用指南（二）

> 原文：[`zh.annas-archive.org/md5/2fe4dbe3a91a5b3bffbf3ffa1b79bc31`](https://zh.annas-archive.org/md5/2fe4dbe3a91a5b3bffbf3ffa1b79bc31)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：Java 中 super 和 this 关键字以及异常的重要性

在本章中，我们将看看两个关键字：`super` 和 `this`。我们将举例并解释它们在编写 Java 代码时在各种情况下的使用方式。我们还将看看异常以及如何使用它们来处理代码由于某些错误而失败的情况。我们将以 `finally` 块的部分结束本章。

在本章中，我们将涵盖以下主题：

+   super 关键字

+   super 关键字的实际用法

+   this 关键字的重要性

+   不同类型的异常

+   try...catch 机制用于处理异常

+   Java 中 finally 块的重要性

# super 关键字

通常，当人们从不同的类中继承属性时，如果父类和子类中使用相同的变量名，可能会出现冗余。为了区分父变量和子变量，我们使用 `super` 关键字。

让我们用一个例子来解释这个问题。我们创建两个类，分别命名为 `childDemo` 和 `parentDemo`。在 `parentDemo` 类中，我们定义一个名为 `name` 的字符串，并将字符串 `'rahul'` 赋给它。

现在，在 `childDemo` 类中，我们继承了 `parentDemo` 的属性。我们知道如何使用 `extends` 关键字继承父类的属性，这是我们在第五章中学到的，*关于接口和继承的一切*。继承属性的代码如下所示：

```java
public class childDemo extend parentDemo{
```

在这段代码中，`childDemo` 继承了 `parentDemo` 的属性。

在 `childDemo` 类中添加一个字符串，称为 `name`，并将字符串 `QAClickAcademy` 赋给它。然后我们在 `childDemo` 类内定义一个名为 `public void getStringdata()` 的方法，并给出一个语句来打印 `name` 的值作为输出。我们在 `getStringdata()` 外定义另一个方法，称为 `public static void main(String[] args)`，并为子类创建一个对象，`childDemo cd = new childDemo();`。一旦对象被创建，我们在其下面添加另一行代码：`cd.getStringdata();`。这将调用 `getrStringdata()` 方法，因此显然名称将作为输出打印，即 `QAClickAcademy`。尽管我们继承了 `parentDemo` 类的属性，该类也包含一个同名的字符串，但打印语句调用的是 `childDemo` 中字符串的值。这是因为 Java 优先使用局部变量。

当父类和子类的变量名发生冲突时，它会优先使用局部变量，即 `childDemo` 类。如果我们需要在 `parentDemo` 类中打印字符串名称，该怎么办呢？为此，我们使用 `super` 关键字来引用从中继承属性到 `childDemo` 类的 `parentDemo` 类。因此，如果我们想要从 `parentDemo` 类中调用名称变量，我们添加一个打印语句，并在要打印的变量前添加 `super` 关键字，这将获取来自 `parentDemo` 的值。现在运行代码，我们将得到父对象和子对象作为输出，因为我们在两个类中都留下了名称字符串的打印语句。`parentDemo` 类的代码如下所示：

```java
public class parentDemo{
    String name= "Rahul";
    public static viod main (String[] args){
    }
}
```

`childDemo` 类的代码如下所示：

```java
public class childDemo extends parentDemo{

    String name = "QAClickAcademy";
    public void getStringdata();
    {
        System.out.println(name);
        System.out.println(super.name);
    }

    public static void main(String[] args){
    childDemo cd = new childDemo();
    cd.getStringdata();
    }
}
```

最终输出将是：

```java
QAClickAcademy
Rahul
```

# super 关键字的实际用法

在这一部分，我们将看看在 Java 中使用 `super` 关键字的不同方式。

# 使用 super 关键字处理方法

我们看到了如何使用 `super` 关键字处理父变量。在本节中，我们还将看到如何处理 `parentDemo` 和 `childDemo` 类中名称相同的两个方法。我们也将在本节中使用之前的例子。

在`parentDemo`类中，添加一个名为`getData()`的方法，并在方法内部添加一个打印语句来显示`"I am in parent class"`消息。如果我们想在`childDemo`类中执行`getData()`方法，我们在`childDemo`类的`main`方法中写入`cd.getData()`。我们可以访问`getData()`，因为我们继承了`parentDemo`类的属性。如果我们运行`childDemo`类，我们将收到先前示例的输出以及我们在`parentDemo`类中添加的新句子`I am in parent class`。

在`childDemo`类中，我们将定义另一个与`parentDemo`类相同名称的方法，并添加一个打印语句来显示`I am in child class`消息。如果我们运行`childDemo`类，我们将得到先前示例的输出，然后显示`I am in child class`。这是因为优先考虑本地类，所以`childDemo`类中的`getData()`方法覆盖了`parentDemo`类中的`getData()`方法。

现在，我们想在`childDemo`类中使用`parentDemo`类的`getData()`方法。为此，我们只需像处理变量一样，在`childDemo`类的`getData()`方法中添加`super.getData()`。当我们运行`childDemo()`类时，我们得到先前示例的输出，然后是`I am in parent class`，然后是`I am in child class`。

# 使用`super`关键字进行构造函数

让我们在本节中使用`super`关键字进行构造函数。我们也将在这里使用先前的示例。

在`parentDemo`类中，我们定义一个构造函数`parentDemo()`，并添加一个打印语句来打印：`Parent class constructor`。

在`childDemo`中，我们定义一个构造函数`childDemo()`并添加一个打印语句来打印：`Child class constructor`。如果我们想在`childDemo`类中使用`parentDemo`类的构造函数，我们在`childDemo()`构造函数中添加`super()`方法。这样控制器就会调用`parentDemo`类中的构造函数。

在使用构造函数时，我们需要遵循一个重要的规则：每当在子构造函数中使用`super`构造函数时，它应该始终是第一行。

当我们运行`childDemo`类时，控制器首先执行`super()`方法。它进入`parentDemo()`构造函数并执行它，然后执行`childDemo()`。因此最终输出将是：

```java
Parent class constructor
Child class constructor
QAClickAcademy
Rahul
I am parent class
I am in child class
```

# `this`关键字的重要性

在 Java 中还有一个与`super`关键字类似的关键字：`this`。在本节中，我们将看一下`this`关键字。

让我们用一个例子来解释`this`关键字。创建一个名为`thisDemo`的类，并声明一个变量`a`，并将值`2`赋给它。我们在其类中定义一个`getData()`方法，在其中声明`a`变量，并将值`3`赋给它。我们还在其中添加一个打印语句。代码将如下所示：

```java
package coreJava;public class thisDemo
{
    int a= 2;
    public void getData()
    {
        int a= 3;
        System.out.println(a);
    }
```

正如我们所看到的，在整个类中`a`的值是`2`，但在一个特定的方法`getData()`中，我们希望变量的值是`3`。在这段代码中，我们想要调用`a`的两个值，即`2`和`3`。我们在主方法中创建一个对象，并将`td`对象添加到其中。`td`对象的代码如下：

```java
thisDemo td=new thisDemo();
td.getData();
```

如果我们运行代码，我们得到的输出是`3`。但是我们也希望在同一个块中将`a`的值打印为`2`。这就是`this`关键字发挥作用的时候。类对象的范围将在类级别而不是方法级别。因此，我们说`getData()`方法是指当前对象，对象范围位于类级别。因此`a=2`对整个类是有效的，而`a=3`仅对`getData()`方法有效。这就是为什么我们称`getData()`方法中的`a`变量为局部变量，而类中的`a`变量为全局变量。

要打印我们正在处理的示例的全局变量，我们需要在`getData()`方法中添加一个打印语句，并在打印语句中添加`this.a`。打印语句将如下所示：

```java
System.out.println(this.a);
```

当我们运行代码时，我们得到以下输出：

```java
3
2
```

这就结束了我们关于这个变量的示例。现在让我们学习一下异常。

# 不同种类的异常

在本节中，我们将看看如何在 Java 中处理异常。

一般来说，如果代码中有错误，我们需要捕获它并打印一条消息而不是失败；这可以使用`try...catch`机制来实现。因此，一般来说，当我们尝试编写代码并怀疑其中可能有错误时，我们将使用该错误进行异常处理。

我们将通过一个练习来解释它。让我们创建一个名为`exceptionDemo`的新类，在`main`块内声明`a`、`b`和`c`变量，并分别为它们赋值`4`、`7`和`0`。我们在主块内添加一个`try`块，并声明一个整数变量`k`，它等于`b`除以`c`。每当我们在`try`块中添加任何内容时，我们都在尝试看代码是否能正常工作。如果失败，控制器将退出这个`try`块并进入包含异常的`catch`块。一个重要的要点是`catch`块紧跟在`try`块后面。在`catch`块内，我们编写一个打印消息来显示`I caught the error/exception`。

当控制器进入`k`变量行时，脚本失败，因为`7/0`是无穷大，这是一个算术异常，但脚本不会立即失败。如果我们不编写`try...catch`块，我们会看到一种不同的错误。

让我们去掉`try...catch`块，运行代码，看看我们得到的错误。我们在输出部分看到一个错误，`Java.lang.ArithmeticException`；这是因为我们不能将`7`除以`0`，所以脚本突然失败了。

如果我们最初觉得我们的代码会出错，我们可以简单地编写一个脚本来通过并捕获错误，通过放置一个适当的调试消息，可以通过`try...catch`机制来处理。现在，让我们再次添加`try...catch`块并调试整个代码。输出将是`I caught the error/exception`；这是因为`7`除以`0`是无穷大，所以脚本应该失败，但我们在输出部分没有看到任何错误，说代码已经失败。这是因为控制器简单地移动到`catch`块并执行它。最终的代码将如下所示：

```java
public static void main(String[] args)
{
    int b=7; 
    int c=0;
    try
    {
        int k=b/c;
        System.out.println(k);
    }
    catch(Exception e)
    {
        System.out.println("I caught the error/exception")
    }
}
```

输出将如下所示：

```java
I caught the error/exception
```

# 使用 try...catch 机制处理异常

在本节中，我们将使用一个`try`后面跟着多个`catch`块。Java 中有不同类型的异常，对于每个异常，我们可以添加单独的`catch`块。

让我们用之前的例子来解释一下。为之前的代码编写的异常是一个通用异常，因此对于`try`块中的任何错误，都会执行通用异常。现在让我们尝试捕获特定的异常。我们可以在`try`块下添加一个`catch`块，并添加一个特定的异常和一个打印语句来打印`I caught the Arithmeticerror/exception`。特定 catch 块的代码如下：

```java
catch(arithmeticException et)
{
    System.out.println("I caught the Arithmeticerror/exception");
}
```

当我们运行代码时，我们得到以下输出：

```java
I caught the Arithmeticerror/exception
```

我们看到，当我们运行代码时，控制器进入`catch`块，因为`catch`块专门针对算术异常编写，而抛出的错误也属于算术错误。因此，一旦控制器收到错误，`try`块将查看与之相关的`catch`块的类型，并运行它。

Java 中还有许多其他异常：我们可以搜索一下看看它们。

# Java 中 finally 块的重要性

还有一个块就像`try...catch`块一样：就是`finally`块。`finally`块将被执行，无论是否抛出异常。如果程序成功运行，这个块将被执行，即使程序不运行也会执行。

我们将使用在*使用 try...catch 机制处理异常*部分中使用的示例来解释这一点。我们只需在`catch`块后面添加一个`finally`块，并在其中加上一个打印语句，说`delete cookies`。代码块将如下所示：

```java
finally
{
    System.out.println("delete cookie")
}
```

当我们运行代码时，我们得到以下输出：

```java
I caught the Arithmeticerror/exception
delete cookie
```

一个重要的点是`finally`可以与或不与`catch`块一起工作；它只需要在`try`块下面写就可以了。

# 总结

在本章中，我们看了一下`super`和`this`关键字。我们还看了一些例子来解释我们可以在哪些地方使用这些关键字来克服某些障碍。我们学习了异常，并在代码由于错误而失败时在各种情况下实现了它们。我们还学习了`finally`块。

在下一章中，我们将深入研究集合框架，其中包括接口和类。我们还将看一下三个主要的集合：`List`、`Set`和`Map`。


# 第九章：理解集合框架

在本章中，我们将深入研究包含接口和类的集合框架。我们将看一下三个主要的集合：`List`、`Set`和`Map`。本章将讨论`List`集合中的`ArrayList`，`Set`集合中的`HashSet`，以及`Map`集合中的`HashMap`和`HashTable`。我们将通过示例来逐个概念进行讨论。

在本章中，我们将涉及以下主题：

+   集合框架

+   列表集合

+   集合

+   映射集合

# 集合框架

Java 集合框架基本上是一组接口和类。为了高效编程或使用 Java 方法的灵活性，Java 设计了一个框架，其中包含不同的类和接口。集合框架有助于高效存储和处理数据。这个框架有几个有用的类，拥有大量有用的函数，使程序员的任务变得非常容易。

我们已经看到了关于数组和多维数组的很多概念。例如，在一个数组中，如果我们想要删除一个新数组集合中的一个索引，我们可以使用集合框架来做到这一点。比如说在一个数组中有 10 个值，我们想要删除第五个值，或者在第五个和第六个值之间插入一个值——在集合框架中有一些灵活的方法。

在接下来的章节中，将讨论这个集合框架中可用的方法类型以及它们如何有效地使用。所以只是给你一个概念，记住集合是一组类和接口。

我们将看一下这个框架提供的集合。

# 列表集合

第一个是`List`集合/接口。列表是一个有序的集合，有时我们也称之为序列。列表可能包含重复的元素，就像数组一样，但数组和`ArrayList`之间有很多不同之处。你可以将多个值插入到这个`List`容器中，它可能也包含重复的元素。你实际上可以从任何索引添加任何值和删除任何值。比如说你按顺序向列表中添加了 15 个元素，现在你想要删除第 6 个元素，或者在第 10 个和第 11 个元素之间插入一个元素，或者想知道在这 15 个元素中某个元素在哪个索引上。在列表容器中有很多有用的 API 来检索元素，而这些在数组中是得不到的。数组只能被初始化；除此之外，你不能对数组执行任何方法，而`ArrayList`你有很多灵活的方法来玩耍。

`List`接口是一个集合，`ArrayList`、`LinkedList`和`vector`是实现这个接口的三个类。这个接口提供了一组方法。它公开了一些方法，而这三个类使用这些方法在它们的类中。

在这三个中，让我们讨论`ArrayList`。这是最著名的之一，大多数 Java 程序员都在使用。一旦你理解了`ArrayList`，你就可以很容易地理解`LinkedLists`和`vector`。在下一节中，我们将创建一个`ArrayList`类，并实现`List`接口中的方法，以查看这些方法在检索或组织数据时有多灵活。当你有一组数据在一个容器中时，你可以很容易地使用`List`接口来组织这些数据。

# ArrayList 类

让我们从`ArrayList`类开始，它实现了`List`接口。创建一个新的类，命名为`arrayListexample`。我们将首先查看`ArrayList`中的方法，然后讨论数组和`ArrayList`之间的区别。

我们首先声明`ArrayList`如下。如果你在 IDE 中悬停在`ArrayList`上，你会看到一个建议，告诉你要导入`java.util`来使用`ArrayList`：

```java
package coreJava;

public class arrayListexample {

    public static void main(String[] args) {

        ArrayList a=new ArrayList();

    }
}
```

一旦你这样做了，它仍然会显示一个关于`ArrayList`的建议，如果你将鼠标悬停在上面，它会建议添加参数类型。要删除这个建议，你可以给`ArrayList`传递一个参数类型，比如`Integer`或`String`：

```java
        ArrayList<String> a=new ArrayList<String>();
        a.add("rahul");
        a.add("java");
```

在传递了参数类型之后，你可以通过使用`a.`轻松地添加一些字符串实例，它会显示出`ArrayList`支持的不同类型的列表。对于`ArrayList`，我们没有定义特定的数组大小，而在数组中，我们已经明确定义了一个大小。在数组中，一旦我们定义了大小，就不能减少或增加大小。但在`ArrayList`中，你可以随时添加或删除元素，它是一个动态大小的数组。这是数组和`ArrayList`之间的基本区别之一。

如果我们想打印这个`ArrayList`，我们可以通过添加以下代码行来简单地实现：

```java
        System.out.println(a);
```

运行时，它打印出`[rahul, java]`。但如果你想以数组的形式打印出来，我们需要写一个`for`循环。我们添加另一个对象，这次我们指定了我们想要字符串放入的索引：

```java
        a.add("rahul");
        a.add("java");
        System.out.println(a);
        a.add(0, "student");
        System.out.println(a);
```

当我们打印这个时，它会给出以下输出：

```java
[rahul, java]
[student, rahul, java]
```

你可以看到在第二行中，`student`被添加到`rahul`之前的列表中，因为我们已经指定了它的索引为`0`。

如果我们想从列表中删除一个条目，可以通过添加以下代码行来实现：

```java
        a.remove(1);
        a.remove("java");
```

第一行代码将从列表中删除位于第一个索引处的条目，而第二行将在列表中查找并删除字符串。如果你想获取特定索引的条目，可以使用`get`方法来做到这一点：

```java
       a.get(2);
```

上一行代码将打印出`java`作为输出，因为它是在索引`2`处的元素。

假设你有一个包含 50 个元素的列表，并且你需要找出该列表中是否存在特定的字符串/整数。如果你使用数组，你将不得不创建一个`for`循环，并找出元素是否存在，但在`ArrayList`中，我们有一个`contains`方法，它可以为我们检查整个列表，并以`true`或`false`的形式给出输出：

```java
        System.out.println(a.contains("java"));
```

这将打印出`true`作为输出，因为该元素存在于我们的列表中；如果你将它改为，例如，`testing`，它将返回值为`false`，因为它不在我们的列表中。

`ArrayList`中还有另一个有用的方法是`indexOf`方法。如果我们想要找到列表中特定元素的索引值，我们可以使用`indexOf`来知道：

```java
        System.out.println(a.indexOf("rahul"))
```

这将返回这个字符串的索引号。

现在，如果我们想要检查数组是否为空，我们可以使用`ArrayList`中的`isEmpty`方法来做到这一点，它将返回值为`true`或`false`：

```java
        System.out.println(a.isEmpty());
```

这将返回值为`false`，因为我们的列表不是空的。

`ArrayList`中最后一个最重要的方法是`size`方法，它返回列表的长度：

```java
        System.out.println(a.size());
```

关于`ArrayList`，你需要知道的另一件事是，实现`List`接口的所有类都可以接受重复的值。我们知道在集合接口中扩展`List`的类有：`ArrayList`、`LinkedList`和`vector`。所有这些类都可以接受重复的值。

# ArrayList 的例子

假设我们有一个包含重复数字的数组，比如`{4, 5, 5, 5, 4, 6, 6, 9, 4}`，我们想打印出这个数组中的唯一数字，以及这个数字在数组中重复的次数。我们的输出应该是"four is repeated three times, five is repeated three times, six twice, nine once."

让我们在这里引入`ArrayList`的概念来解决这个谜题：

```java
package demopack;
import java.util.ArrayList;
public class collectiondemo {
    public static void main(String[] args) { 
        int a[] ={ 4,5,5,5,4,6,6,9,4}; 
        ArrayList<Integer>ab =new ArrayList<Integer>(); 
        for(int i=0;i<a.length;i++) 
        { 
            int k=0; 
            if(!ab.contains(a[i])) 
            { 
                ab.add(a[i]); 
                k++; 
                for(int j=i+1;j<a.length;j++) 
                { 
                    if(a[i]==a[j]) 
                    { 
                       k++; 
                    } 
                } 
                System.out.println(a[i]); 
                System.out.println(k); 
                if(k==1) 
                    System.out.println(a[i]+"is unique number"); 
            } 
        } 
    }
}
ArrayList with the ab object type. Then we create a for loop, and within it we use an if loop with !ab.contains to check whether the element is present within the loop. We need another for loop within this if loop to iterate through the remaining part of the array. The if loop within this for loop will work as a counter for us to increment the number of times a number is repeated in the array.
```

我们已经完成了`for`和`if`循环。我们打印出数组中的每个元素以及每个元素在数组中出现的次数。要打印出唯一的数字，也就是在数组中不重复的数字，我们使用一个`if`循环并打印它。

就这个例子而言就是这样；你可以尝试用你自己的逻辑编写这个例子。

# 集合 Set

Java 中还有一个重要的集合是`Set`集合/接口。`HashSet`、`TreeSet`和`LinkedHashSet`是实现`Set`接口的三个类。`Set`和`List`之间的主要区别是`Set`不接受重复的值。`Set`和`List`接口之间的另一个区别是没有保证元素按顺序存储。

在本节中，我们主要讨论`HashSet`。我们将以一个示例类来尝试理解这个概念。为本节创建一个名为`hashSetexample`的类，并在类中创建一个对象来使用`HashSet`；它会建议你添加参数类型，在我们的情况下是`String`：

```java
package coreJava;

import java.util.HashSet;

public class hashSetexample {

    public static void main(String[] args) {

       HashSet<String> hs= new HashSet<String>();

    }
}
```

在你的 IDE 中，当你输入`hs.`时，它会显示`HashSet`提供的所有方法：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/43eefee7-fe95-435d-a7c3-e83ec95f6ce2.png)

首先添加一些重复条目的字符串实例：

```java
        HashSet<String hs= new HashSet<String>();
        hs.add("USA");
        hs.add("UK");
        hs.add("INDIA");
        hs.add("INDIA");
        System.out.println(hs);
```

当你打印这个时，输出将如下所示：

```java
[USA, UK, INDIA]
```

我们看到`HashSet`拒绝了`INDIA`的重复条目，我们只看到一个实例。

如果我们希望删除任何对象，我们可以使用`remove`方法，要获取列表的大小，请使用`size`方法：

```java
        System.out.println(hs.remove("UK"));
        System.out.println(hs.isEmpty());
        System.out.println(hs.size());
```

`isEmpty`方法告诉我们列表是否为空——如果为空，它将返回`true`，否则返回`false`。

# 使用迭代器

为了遍历列表中的每个元素，我们使用`iterator`方法。我们需要为这个`Iterator`类创建另一个对象，以及`String`参数类型：

```java
        Iterator<String> i=hs.iterator();
```

假设我们有一组元素，它们按顺序从零、一、二等开始。`iterator`遍历每个元素，从零开始打印每个值。我们创建了一个迭代器对象，并打印了以下值：

```java
        System.out.println(i.next());
        System.out.println(i.next());
```

`i.next()`的第一个实例将打印出零索引处的值，下一个`i.next()`实例打印出索引一处的值。如果我们有一个包含大约 100 个值的集合，我们将不得不使用`while`循环：

```java
        while(i.hasNext())
        {
            System.out.println(i.next());
        }
```

在这里，我们使用了`hasNext`方法，它检查下一个值是否存在。如果下一个索引中存在值，它将返回`true`，如果没有，它将返回`false`。在我们的情况下，它将返回 100 个值的`true`，之后返回`false`，并退出`while`循环。

这就是你如何使用`iterator`遍历`Set`接口中的对象。如果你正在进行自动化测试，比如 Selenium，你会经常使用这个`while`循环。

# 映射集合

我们还有一个叫做`Map`的集合。我们将以一个例子讨论`Map`，并随着代码的进行进行讨论。这个接口以键和值对的形式接受值。

我们创建一个类，`hashMapexample`，在其中定义`HashMap`。`HashMap`需要两种类型的参数，比如`Integer`和`String`：

```java
package coreJava;

import java.util.HashMap;

public class hashMapexample {

    public static void main(String[] args) {

       HashMap<Integer, String> hm= new HashSet<Integer, String>();

    }
}
```

这里，`Integer`是键，`String`是值。现在，如果你在 IDE 中输入`hm.`，你会看到`HashMap`中存在的一些方法；让我们使用`put`方法：

```java
        hm.put(0, "hello");
        hm.put(1, "goodbye");
        hm.put(2, "morning");
        hm.put(3, "evening");
```

`put`方法以键和值的形式接受输入。此外，键的值需要是整数，也可以是字符串。键只是我们为值定义的东西。我们可以使用`remove`方法删除一个值：

```java
        hm.remove(2);
```

`HashMap`中的`entrySet`方法以集合索引的形式存储每个键和值：

```java
        Set sn= hm.entrySet();
```

我们现在将这个`HashMap`转换成一个集合。为了遍历这个集合的每个索引，我们使用`iterator`，就像在前一节中一样，我们使用`while`循环：

```java
        Iterator it= sn.iterator();

        while(it.hasNext())
        {
            Map.Entry mp=(Map.Entry)it.next();
            System.out.println(mp.getKey());
            System.out.println(mp.getValues());
        }
```

在这里，我们需要使用`Map.Entry`，因为每个索引中的元素都包括一个键和一个值，`Map.Entry`帮助我们分离键和值。当你打印这个`while`循环时，你应该得到以下输出：

```java
0
hello
1
goodbye
2
morning
3
evening
```

不使用`Map.Entry`，它会抛出一个错误。这就是`HashMap`的工作原理。

# 哈希表

还有一个集合，叫做`HashTable`，但它与`HashMap`沿着同样的线路。你只需要把`HashMap`改成`HashTable`就可以了。不过`HashMap`和`HashTable`之间有一点小区别。

`HashMap`和`HashTable`之间的区别如下：

+   同步或线程安全

+   空键和空值

+   遍历值

# 同步或线程安全

这是两者之间最重要的区别。`HashMap`是非同步的，不是线程安全的。那么什么是非同步？这意味着如果多个程序同时访问`HashMap`，它会不断更新。现在假设有五个线程在操作`HashMap`。这意味着五个不同的程序或线程可以同时访问`HashMap`，这意味着没有同步。但是在`HashTable`中，如果一个程序正在访问`HashTable`，另一个程序需要等待，直到第一个程序释放`HashTable`资源。这是主要的区别。另一方面，`HashTable`是线程安全和同步的。什么时候应该使用`HashMap`？如果你的应用程序不需要多线程任务，换句话说，`HashMap`对于非线程应用程序更好。`HashTable`应该在多线程应用程序中使用。

# 空键和空值

`HashMap`允许一个空键和任意数量的空值，而`HashTable`不允许`HashTable`对象中的空键和空值。假设你正在将员工记录输入到数据库中，也许在上传员工详细信息到数据库时，你可能觉得你不知道他们的电话号码，但你在一个键值中输入了名为电话号码的字段，并且索引值暂时为空；你可以稍后更新它。这在`HashMap`中可以工作，但当你使用`HashTable`时，它不允许任何空键和空值。如果你觉得你想让你的程序非常安全，并且你想阻止多个线程同时访问它，那么你应该选择`HashTable`。`HashTable`是线程安全的，直到一个程序在`HashTable`上完成操作之前，它不会释放其对象给另一个程序。

# 遍历值

`HashMap`对象的值通过`iterator`进行迭代。`HashTable`是除了向量之外唯一使用枚举器来迭代`HashTable`对象的类。

除了我们刚刚描述的三个区别之外，`HashMap`和`HashTable`的操作是相同的。

# 总结

在本章中，我们看了集合框架和三种类型的集合：`List`，`Set`和`Map`。我们在`List`集合中探索了`ArrayList`，并且也探索了`ArrayList`的一个例子。`Set`集合与`ArrayList`不同——主要的区别是`Set`不接受重复的值。在最后一个集合中，也就是`Map`集合中，我们看到了两种类型，`HashMap`和`HashTable`，以及它们之间的区别。


# 第十章：final 关键字、包和修饰符的重要性

这是我们书中的最后一章。在这里，我们将处理一些更重要的概念，这些概念将帮助我们编写和执行更好的代码。

在本章中，我们将讨论以下概念：

+   final 关键字

+   包

+   Java 中的修饰符

# final 关键字

首先，我们将创建一个新类。如果我们将任何变量声明为`final`，那意味着该值不能再次更改。让我们考虑以下代码：

```java
package coreJava;

public class finaldemo {

    public static void main(String[] args) {
        //TODO Auto-generated method stub
        final int i=4; //constant variables
    }
}
```

正如你所看到的，我们已将整数值声明为`4`。这意味着我们不能将这个值更改为另一个数字。如果我们尝试这样做，它会抛出一个错误，说`Remove 'final' modifier of 'i'`。如果我们希望一个值是常量，这个关键字是有用的。

如果我们将一个类标记为`final`，它会抛出一个错误，因为当我们将访问模式更改为`final`时，我们无法将其用作父类。换句话说，我们将无法从中继承我们的属性。如果我们想要继承我们的属性，我们需要将其改回`public`。final 关键字的关键逻辑是，一旦编写，我们就无法覆盖`final`方法。因此，这些是独一无二的，不能再次使用相同的名称。

final 关键字可以用于方法级别，以确保该方法不被覆盖。它用于变量级别，以确保我们不会更改它，还可以用于类级别，以确保我们不会继承该父类。

但是记住不要混淆`final`和`finally`。`finally`与`try...catch`异常有关。一旦执行`try`或`catch`块，并预先任何错误，控制器仍将来到此日志并执行代码，无论脚本是通过还是失败。`finally`是关于限制访问的，例如我们不能使用它，继承它，甚至更改值。我们已经探讨了包，以及如何将包导入其他类。我们已经探讨了接口的继承，运行时多态，字符串等等。这都是关键字。

在下一节中，我们将学习有关包的知识。

# 包

当为每个 Java 类编写脚本时，会自动出现一个预填的行。它是`package coreJava`。由于我们在 Java 中创建了一个包，并将所有 Java 类放入了`coreJava`包中，我们将其视为`package coreJava`。

包只是一组类和接口。例如，Java 自带了一些内置包，比如`java.length`；如果我们导入这个包，那么我们只能访问基本的基本方法，比如`public static void main`，整数或数组。所有这些类都来自`java.lang`包。定义包名很重要，因为没有它，我们无法访问包内的类。这是因为`java.lang`是一个默认包，它包含在 Java 编译器中。

我们还有另一个包，`java.util`。我们在处理集合时使用了这个包；我们导入了一个`java.util`包。为了使用`ArrayList`，这个类存在于`java.util`包中。因此，如果我们移除`import java.util.ArrayList`，它会抛出一个错误，因为它不属于`java.lang`。所有集合接口都来自`util`包。

但是我们如何知道要使用什么关键字？以下屏幕截图显示了当我们将鼠标悬停在 Eclipse 上时 Eclipse 会显示什么：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/e544ea6b-85b3-4d6d-9a42-d78acde26018.png)

快速修复下拉菜单提供了纠正代码错误的建议

我们正在导入`java.util`包。并且从该包中，我们正在导入`ArrayList`类。其语法将是：

```java
import package.classname
```

在这里，我们在这个 Java 类中使用`ArrayList`的原因是因为我们知道`ArrayList`在`java.util`包中。但是在使用 Eclipse 时，我们不需要记住它。当你只是悬停鼠标时，它会建议我们导入包，我们只需点击它。它将自动导入那个特定的测试。

`HashSet`从同一个`util`包中导入了`HashSet`类。如果我们去`HashMap`，它会带来`HashMap`。因此，每当我们想要处理一些测试时，我们需要导入那个包或类。`System.out.println()`也只来自一个包，但它们来自`java.lang`，这是一个内置的编译器。这些都是 Java 包内置的。

同时，我们也可以定义一个用户定义的 Java 包。在这种情况下，我们所有的测试用例都在一个名为`coreJava`的不同包中。如果有人想要使用我们的类，他们只需要运行`import coreJava.classname`。

在下一节中，我们将看一下 public 修饰符。

# Java 中的修饰符

有四种类型的访问修饰符：

+   `public`

+   `private`

+   `protected`

+   `default`

我们不会在这里讨论理论，因为你可以在 Google 上找到。我们需要一个实际的方法，来看看这些访问修饰符到底在哪里使用，或者包到底在哪里导入。每当我们在这本书中创建一个方法时，我们都只是使用`public`并写下这个方法。其他三种访问修饰符的工作方式也类似。

现在让我们试着理解每种访问修饰符如何帮助我们。

# default

如果我们没有提及任何访问修饰符，我们的 Java 类会自动认为它有一个`default`访问修饰符。如果是`default`，那意味着你可以在你的包中的任何地方访问这个方法。但是如果你离开了这个包，那么你就无法访问这个方法。即使我们将`package.classname`导入到我们的新包中，如果我们没有将其指定为`public`，我们也无法访问这个方法。如果你不指定它，那么默认它认为它是一个`default`访问修饰符。`default`访问修饰符可以在包中的任何地方访问，但在包外部不能访问。

在*Packages*部分，我们导入了这个包并尝试使用它。如下截图所示，第 15 行出现了一个错误：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/d9dfca50-0720-409c-bd0f-5457b9af0d7a.png)

快速修复下拉菜单提供了默认代码错误的建议

如果我们不指定任何东西，我们就无法访问它，因此它与默认功能相同。这也适用于变量：

```java
public class arrayListexample {
    // can accept duplicate values
    //ArrayList, LinkedList, vector- Implementing List interface
    //array has fixed size where arraylist can grow dynamically
    //you can access and insert any value in any index
    int i=5;
```

正如我们所看到的，在前面的代码中我们声明了一个整数。然而，它不会是`public`；它是`default`。因此，我们无法在包外访问这个变量。如果我们导入它，我们将可以访问这个类但不能访问方法。如果我们想要访问，我们必须将其写为`public`。那么`public`访问修饰符是什么作用呢？

# public

将方法或变量设为`public`后，我们将可以在所有的包中访问它。这基本上意味着任何地方。对于这个类的这个包没有限制。在前面的截图中观察到的错误也会在我们将方法/变量设为`public`后消失。

在我们将其设为`public`后，下面的截图显示了`int`值：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/cd7b7481-22ae-445e-bfb6-22257a6f5ef9.png)

快速修复下拉菜单提供了默认代码错误的建议

在下一个类中，我们将看一下`private`和`protected`访问修饰符是什么。在这之后还有两种访问修饰符，让我们看看它们的作用。

# private

如果我们将我们的方法或变量标记为`private`，那么我们就无法在类外访问它们。它们不能在包外或同一个类外被访问。如果我们想在我们的`ArraysDemo`示例中访问它，我们无法这样做。即使我们尝试，它也会抛出一个错误，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/hsn-auto-test-java-bg/img/50710110-dc12-4e9a-8739-6c1ace39fac8.png)

快速修复下拉菜单显示了一个建议，可以纠正私有代码错误

这是因为，如果我们将任何方法或变量标记为`private`，我们就无法在那个特定的类之外访问它。除非我们将它改为其他东西，否则会抛出错误。这也适用于变量。

如果你想要一个实时场景，比如你正在进行支付和购买产品；所有的信用卡细节都会被标记为`private`，因为它们不会在购买类之外被访问。如果它们可以被访问，那就是一个安全漏洞，对吧？所以为了让信用卡细节受限于那个特定的类，开发人员给所有的卡细节都加上了`private`变量，这样其他类就不能使用它。即使它们使用了继承或者导入了一个包，它们也无法访问这些敏感细节。有很多实时场景；如果你正在测试框架上工作，可能会有一些变量你不应该改变，并且总是保持它私有。

# protected

如果我们将一个变量或方法定义为`private`，我们只能在子类中访问它们。这意味着如果我们将它定义为`protected`；那么，无论哪个类继承了父类，只有这些子类才能访问该方法，其他类都不能。这可以通过以下代码片段来理解：

```java
protected void abc() {
    //TODO Auto-generated method stub
    System.out.println("Hello");
    }
```

`default`和`protected`之间的区别在于，在`default`中我们只能在同一个类包内访问一个类。即使`protected`可以访问同一个包内的所有类，除了它还有一个额外的特性。这个额外的特性是，如果我们想在其他包中访问它，只有继承父类属性的子类才能访问它。

相同的概念也适用于变量。

# 总结

在本章中，我们学习了帮助我们理解 Java 中包、修饰符和`final`关键字的重要性的概念。

希望你现在已经阅读了所有章节，对这些概念有了更好的理解。
