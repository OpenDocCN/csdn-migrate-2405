# 面向初学者的 Java 编程（二）

> 原文：[`zh.annas-archive.org/md5/4A5A4EA9FEFE1871F4FCEB6D5DD89CD1`](https://zh.annas-archive.org/md5/4A5A4EA9FEFE1871F4FCEB6D5DD89CD1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：数据结构

在本章中，我们将学习 Java 中一些最重要的数据结构。我们将研究数组是什么，以及当我们需要处理变量序列时它们如何有用。我们将在 NetBeans 中使用数组编写一个程序来理解它们的工作原理。本章还将介绍多维数组的概念。我们将编写一个程序，使用二维数组创建一个棋盘。

接下来，本章将说明 ArrayList 是什么，以及与数组相比，它们如何提供增强功能。最后，我们将看看`Map`数据结构，并在 NetBeans 中实现它。

更具体地，我们将涵盖以下主题：

+   数组及其语法

+   一个打印英文字母表的数组示例

+   多维数组

+   使用 2D 数组创建棋盘的程序

+   ArrayList 及其示例

+   在 NetBeans 中的地图及其实现

# 使用数组

在本节中，我们将学习 Java 数组。数组是 Java 最基本和常用的数据结构。数据结构是一种工具，允许我们存储和访问信息序列，而不是使用单个变量。当我们在本地编程空间中需要一个特定的信息片段时，变量非常有用，但是当我们想要存储大量或复杂的信息集或系列时，就会使用数据结构。我们将从一些视觉学习模式开始本节，然后我们将进入 NetBeans IDE 编写一些实际的 Java 代码并使用数组。

# 声明和初始化数组

让我们首先看一下在 Java 中声明和初始化数组的语法。以下代码行将使一个数组产生，有足够的空间来容纳七个字符：

```java
char[] arrayVar = new char[7]; 
```

在我们的赋值运算符（`=`）的左侧，语法看起来非常熟悉，与声明任何其他原始或对象时使用的语法非常相似。我们首先告诉 Java 我们要在这里声明什么类型的元素。在这种情况下，我们声明了一个字符数组。空方括号让 Java 知道，我们不是要创建一个单个字符变量，而是要声明一个数组类型变量，因为我们的数组就像任何其他变量一样。我们将通过数组的变量名本身访问数组的元素，而不是通过元素的单独变量名，因为它们被存储在数组中，我们不需要分配它们。告诉 Java 我们要创建什么类型的数组后，我们给我们的数组变量一个名称。我把这个叫做`arrayVar`。

在我们的等号运算符右侧，情况看起来有些不同。您可能已经在过去看到`new`关键字的使用，当我们需要创建一个对象的新实例时，而不是原始元素。在 Java 中创建原始元素时，Java 知道需要多少内存空间来存储原始元素，无论其值如何。然而，对象和数组可能具有许多不同的大小要求。因为单个数组变量可以分配给不同长度的数组，所以当我们创建它们时，我们需要告诉 Java 为这些不同长度的数组中的每一个分配多少内存。因此，在创建对象或数组时，我们使用`new`关键字告诉 Java 应该设置多少内存空间来放置我们即将产生的东西，而那个东西是一个长度为七的字符数组。

在声明和初始化我们的七个字符数组之后，我们程序的本地内存中存在以下内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/8d309c8b-43d4-4a06-8e54-171a1043da0e.png)

我们的数组基本上是一个足够大的内存块，可以存储七个单独的字符。

# 为数组分配值

当我们调用`arrayVar`变量时，我们的程序访问数组的位置。这使我们能够运行以下代码行：

```java
arrayVar[2] = 'c'; 
```

我们的`arrayVar`变量基本上让我们可以访问七个不同的字符变量。当我们不想给我们的`arrayVar`变量分配一个新的数组时，我们可能会单独访问这些字符变量。我们只需使用`arrayVar`的变量名，后面跟着方括号，其中包括我们想要访问的单个字符的索引。请记住，当我们的计算机计算索引时，它们几乎总是从**0**开始。因此，在 Java 中，我们的七个字符数组具有这些索引：**0**，**1**，**2**，**3**，**4**，**5**和**6**。如果我们执行上面的代码行，同时将我们的`arrayVar`中索引`2`的值设置为`c`，我们将取出内存的第三个块，并将其值分配给字符`c`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/23e6c8b8-c4a9-4b21-8862-53c6b33889f4.png)

有时，当我们声明一个数组时，我们只想继续在代码中明确地为所有的内存块分配值。当我们想要这样做时，我们可以像明确声明原始类型一样，而不是使用`new`关键字并让计算机告诉它数组的长度，我们可以明确声明一个数组。例如，我们可以使用以下代码为我们的`arrayVar`变量做到这一点：

```java
arrayVar = {'a', 'b', 'c', 'd', 'e', 'f', 'g'}; 
```

前面的语句将创建一个长度为七的数组，因为声明了七个元素，并且当然，它将相应地映射值：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/f96737c2-efd9-4c2f-bdb4-9c62057f3c8f.png)

现在，让我们跳入一些 Java 代码，并让数组开始工作。

# NetBeans 中的数组示例

好了，我想现在是时候运用我们的新知识并编写一个计算机程序了。数组允许我们处理在单个元素级别处理起来会很麻烦的信息量。因此，我们将直接进入重要的内容，并创建一个很酷的计算机程序。数组是一个很大的逻辑步骤，如果你以前没有使用过类似的东西，可能需要一点时间来理解它们。好消息是，如果你通过了 Java 中的数组，你可能会很好地处理语言可以给你带来的其他任何东西。

我想要编写的程序将把英语字母表打印到屏幕上。当然，我们可以自己做所有这些，只需按照以下代码的方式进行：

```java
System.out.println("abcdefg"); 
```

然而，使用这个方法相当令人昏昏欲睡，而且不会教会我们太多东西。相反，我们要编写的程序将学习、存储并打印出英语字母表。

为了做到这一点，我们需要运用我们对数组的新知识，我们对字符如何工作和在 ASCII 表上映射整数值的现有知识，以及一个`for`循环。

# 创建一个数组

让我们开始我们的编程，声明并初始化一个字符数组，用来存储英语语言的字符。因此，我们告诉 Java 我们需要一个变量来指向一个字符数组。我会把这个变量称为`alpha`。然后我们要求 Java 使用`new`关键字为`26`个字符分配内存空间，因为英语语言有 26 个字母：

```java
char[] alpha = new char[26]; 
```

现在，如果你记得，字符值也可以映射到整数值。要找到这些值，我们将查找 ASCII 表。（您可以在[www.asciitable.com](http://www.asciitable.com/)上访问 ASCII 表。）

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/d9f6be8e-6290-44ce-97ce-b9bb46a323d6.jpg)

我们要找的值是**97**，小写字母**a**的整数值，这是英语语言中的第一个字符。因此，让我们在我们的程序中创建一个小注释，并将值`97`存储起来以备后用：

```java
package alphabet; 

public class Alphabet { 
    public static void main(String[] args) { 
        // 97 
        char[] alpha = new char[26]; 
    } 
} 
```

# 创建一个 for 循环

现在让我们开始创建我们的`for`循环。我们的`for`循环将运行 26 次；每次运行时，它将取出英语字母表中的下一个字符，并将其放入我们的字符数组`alpha`中。

为了确保我们的`for`循环运行 26 次，我们应该声明一个计数变量，比如`i`，并将其设置为`0`，即（`i=0`）。接下来，让我们说我们的`for`循环应该继续运行，只要我们的计数变量的值小于`26`，也就是说，它应该在`0`和`25`之间取值（`i<26`）。最后，每次我们的`for`循环运行时，我们需要增加我们的计数变量的值，以便它每次都增加，经过 26 次迭代后，`i<26`语句将不再为真，我们的循环将在（`i++`）处停止： 

```java
for(int i = 0; i < 26; i++) 
{ 

} 
```

现在，在我们的`for`循环内部，我们将逐个为字符数组中的空格赋值。要访问其中一个空格，我们将使用分配给数组的变量的名称，即`alpha`，后跟方括号内的数字（或索引），以告诉 Java 我们想要为数组中的哪个字符赋值。

我们数组的索引应该在每次循环中都不同。这就是`for`循环的美妙之处。通过将我们的计数变量`i`从`0`开始，我们可以使用它来映射到数组的索引。也就是说，我们可以使用`alpha[i]`逐个访问数组的元素。随着循环运行，我们的计数变量的值将从 0 到 25 变化。数组的索引值（因为计算机从零开始计数）也从 0 到 25 变化。

那么，我们为每个字符分配什么值，以便我们的计算机学会字母表呢？嗯，我喜欢这样想：当我们第一次运行循环时，当`i`为`0`时，我们数组的第一个元素的值应该是`97`，这是字符**a**的整数值。现在，当我们应该将`97+i`作为数组中每个字符的值。当我们第二次运行循环时，`i`增加了一，我们将分配值 97 + 1，或**98**，这是字符**b**的整数值：

```java
for(int i = 0; i < 26; i++) 
{ 
    alpha[i] = (char)(97 + i); 
} 
```

在这种情况下，Java 要求我们明确告诉它，我们希望将这个整数值转换为字符，然后存储它。

# 打印字母表

现在，要完成我们的程序，我们需要做的就是打印出我们的`alpha`数组。为此，让我们利用一个始终可访问的对象中的一个巧妙的函数，称为`Arrays`。`Arrays.toString()`函数将转换为字符串的单维数组（这是我们创建的数组的类型），可以转换为字符串：

```java
public class Alphabet { 
    public static void main(String[] args) { 
        //97 
        char[] alpha = new char[26]; 

        for(int i = 0; i < 26; i++) 
        { 
            alpha[i] = (char)(97 + i); 
        } 

        System.out.println(Arrays.toString(alpha)); 
    } 
} 
```

现在，如果我们运行我们的程序，我们将看到 Java 以数组形式表示的英文字母：

！[](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/f64fbff0-7f63-4e4b-bc9b-42930ad80643.jpg)

如果您一直跟着做，那么您应该给自己一个坚实的鼓励。我们刚刚做了一些重活。

# Java 中数组的默认初始化

现在，让我们回到理论中的其余部分。我之前误导了你，让你相信我们新创建的数组是用空内存空间填充的。实际上，当我们声明一个新的原始类型数组，即字符、整数、布尔值、浮点数等时，Java 会用默认值填充它。例如，我们的七个字符的新数组被七个空格字符填充，也就是如果您在键盘上按空格键会得到的结果：

！[](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/83398f87-f920-4c84-9b7d-3a7227bb310a.png)

同样，整数数组将填充七个零：

！[](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/c2e6f3b3-fef4-445f-9385-8a0f2eb177a9.png)

我建议您启动 Java IDE 并创建一些空的原始数组，并使用`println`将它们打印出来，以查看默认值是什么。

现在我们可以创建任何可用对象的数组。但是，与原始类型不同，对象在初始化为数组的一部分时不会设置默认值。这是一个重要的事实。

我们需要使用`new`关键字创建的任何内容都不会在数组中进行默认初始化。

假设出于某种原因，我们决定必须在数组中有七个`Scanner`对象。以下语句并不会为我们创建七个`Scanner`对象；它只是简单地设置了内存空间：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/cc6f82a1-e7e7-4e04-a449-682ff95ee803.png)

我们可以创建`Scanner`对象并将它们分配到这些内存空间，但如果在我们分配`Scanner`对象给内存位置之前尝试调用其中一个内存空间并使用 Scanner 特定的函数，我们的程序将崩溃。我们将得到所谓的`NullReferenceException`，这意味着 Java 要求虚无行为像一个`Scanner`对象。

# 多维数组

在 Java 中，我们最基本的数据结构是数组，它允许我们存储轻类型信息的序列，并通过内存中的单个位置访问这些信息。然而，有时数组不灵活，我们希望使用更强有力的组织数据结构，以便人类更容易理解和编写程序。在这种情况下，通常适合使用多维数组。

“多维数组”听起来是一个相当可怕的名字，但实际上它背后的概念非常基本。问题是如果我们创建一个数组的数组会发生什么？以下代码显示了如何做到这一点的语法：

```java
char[][] twoDimArr = new char[3][7];
```

这行代码将创建一个二维多维数组。你会看到它非常类似于在正常情况下简单创建字符数组的语法，但在我们现在引用数组变量的每个实例中，Java 将需要两个信息（或两个索引）。前面的代码将告诉 Java 创建三个数组，每个数组都有足够的空间来存储七个字符或长度为七的三个数组：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/fb6fae9f-b50e-4a72-bd5a-41c9a46a2c66.png)

为了巩固我们对这个概念的理解，让我们编写一个利用二维数组的 Java 程序。

# 在 NetBeans 中的多维数组示例

我们可以使用多维数组以抽象的方式存储信息，但最容易的学习方法可能是通过用二维数组表示实际的二维对象，比如国际象棋棋盘。

经典的国际象棋棋盘被分成黑色和白色方块；宽度为八个方块，高度为八个方块。我们即将编写的程序将在 Java 中存储一个虚拟棋盘，并正确标记黑色和白色方块。然后，在最后，我们将打印出这个棋盘，以便我们可以检查我们是否正确地编写了程序。

# 创建多维数组

让我们首先声明并初始化我们将要使用的数组。我们将使用字符数组来完成这个任务，给白色方块赋予字符值`W`，给黑色方块赋予字符值`B`。由于国际象棋棋盘是一个八乘八的网格，我们将声明一个包含八个数组的二维数组，每个数组应包含八个字符：

```java
char[][] board = new char[8][8]; 
```

让我们通过将我们棋盘的尺寸存储在一个单独的位置来使某人更难无意中破坏。为此，只需创建一个名为`boardDim`的变量，为棋盘尺寸，将其赋值为`8`，然后在创建数组时引用它。数组将很乐意使用变量中的整数来初始化自己，让我们可以根据需要创建动态链接的数组。现在，如果有人想要扩大我们的国际象棋棋盘，他们只需要改变`boardDim`的值：

```java
int boardDim = 8; 
char[][] board = new char[boardDim][boardDim]; 
```

为了给我们的方块分配适当的值，我们需要循环遍历这个数组，以便到达每个单独的节点并给它赋予我们想要的值。

# 使用嵌套循环进行多维数组

循环和数组非常合适，因为数组总是知道它们的长度，但单个`for`循环不能让我们有意义地循环遍历二维数组。`for`循环实际上只是沿着一个方向进行，而我们的二维数组有两个方向。

为了解决这个问题，我们将利用嵌套的`for`循环，或者`for`循环中的`for`循环。我们的外部`for`循环将依次循环每个数组，而内部`for`循环的工作将是循环遍历这些数组包含的节点。

创建`for`循环时的常见做法是使用整数变量`i`作为初始`for`循环，然后使用`j`、`k`等变量作为后续`for`循环。然而，因为我们正在创建一个实际对象的棋盘，我将选择值`y`作为我们外部循环的计数变量。这是因为我们的循环正在沿着棋盘的*y*轴进行迭代。

如前所述，`for`循环和数组非常合适，因为数组知道它们的长度。我们可以简单地声明我们希望这个循环运行八次（`y<8`），但这不是良好的动态编程，因为如果有人改变了棋盘的大小，我们的程序现在就会出错。我们可以编写这个循环，使其适用于任何大小的棋盘。

为了做到这一点，我们不应该明确地说我们的循环应该运行八次，而是应该让它开始询问我们的数组有多长。要询问数组的长度，我们只需要写`array.length`，这将返回一个整数值。这是一个二维数组，所以简单地调用数组的名称来使用`length`变量将得到数组最外层段的长度。在这种情况下，我们正在询问我们的二维数组，“你有多少个数组？”为了完成这个`for`循环，我们只需要在每次运行后递增`y`。因此，我们的外部`for`循环将循环遍历我们的 2D 数组`board`包含的每个数组：

```java
for(int y = 0; y < board.length; y++) 
{ 
} 
```

现在，让我们对内部循环做类似的事情。因为这个循环将遍历我们行的单个元素，所以对于*x*轴来说，`x`似乎是一个合适的变量名。因为我们的数组目前在两个部分中的长度相同，即一个八乘八的数组，简单地使用`board.length`语句，现在可以工作。但再一次，这不是良好的动态编程。如果有人通过更改我们的棋盘大小为八乘十，这个程序将不再正确执行。相反，在这个内部`for`循环执行的开始，让我们询问我们当前通过外部循环访问的数组有多长。这再次使我们的程序健壮，并允许我们适应棋盘的多种尺寸：

```java
for(int x = 0; x < board[y].length; x++) 
{ 
} 
```

好的，我们程序的下一步是为数组中的每个节点分配字符值：黑色方块为`B`，白色方块为`W`。让我们首先编写代码使所有方块都是白色的。当我们执行双重`for`循环时，它将通过我们的二维数组中的每个节点。因此，每次我们执行内部`for`循环中的代码时，我们都是根据单个二维数组节点来执行的。为了获得这个节点，我们需要询问我们的`board`数组在第`y`行和第`x`列的位置是什么，然后我们将改变该节点的值：

```java
for(int y = 0; y < board.length; y++) 
   { 
      for(int x = 0; x < board[y].length; x++) 
      { 
         board[y][x] = 'W'; 
      } 
   } 
```

# 为我们的棋盘分配不同的颜色

问题是，每次这个内部循环执行时，我们都希望节点的值不同，这样我们就得到了交替的白色和黑色方块的棋盘。为了帮助我们做到这一点，让我们在程序中添加另一个变量。它将是一个布尔变量，我们将其称为`isWhite`。如果`isWhite`为`true`，那么我们添加的下一个方块将是白色；如果`isWhite`为 false，方块将是黑色。

为了编写代码，让我们使用一些`if`语句。首先，`if(isWhite)`代码术语检查`isWhite`是否为`true`。如果是，我们就在方块中放一个`W`。如果`isWhite`是`false`，我们就在方块中放一个`B`代表黑色。要检查某事是否不是真的，我们可以在条件语句之前用感叹号来翻转任何布尔值。这对布尔值甚至条件语句都适用。

接下来，我们只需要翻转`isWhite`的值。好吧，利用我们对感叹号运算符的知识，它可以翻转布尔值的值，我们可以通过简单地将其值设置为其自身的倒数版本，将`isWhite`的值从`true`翻转为`false`或从`false`翻转为`true`：

```java
public static void main(String[] args) { 
   int boardDim = 8; 
   char[][] board = new char[boardDim][boardDim]; 
   boolean isWhite = true; 

   for(int y = 0; y < board.length; y++) 
   { 
       for(int x = 0; x < board[y].length; x++) 
       { 
           if(isWhite) board[y][x] = 'W'; 
           if(!isWhite) board[y][x] = 'B'; 
           isWhite = !isWhite; 
       } 
    } 
} 
```

不幸的是，这个程序还不够完美。事实证明，如果我们这样做，我们的棋盘将每一行都以白色方块开头，而真正的棋盘是每隔一行用不同颜色的方块交替的。

幸运的是，外部循环对棋盘的每一行运行一次。因此，如果我们在每一行的开头简单地给我们的`isWhite`布尔值添加一个额外的翻转，我们也会得到交替的行开头。如果我们这样做，我们需要将`isWhite`的初始值设为`false`，因为当外部循环第一次执行时，它将立即更改为`true`：

```java
public static void main(String[] args) { 

   int boardDim = 8;  
   char[][] board = new char[boardDim][boardDim]; 
   boolean isWhite = false; 

   for(int y = 0; y < board.length; y++) 
   { 
      isWhite = !isWhite; 
      for(int x = 0; x < board[y].length; x++) 
      { 
         if(isWhite) board[y][x] = 'W'; 
         if(!isWhite) board[y][x] = 'B'; 
         isWhite = !isWhite; 
      } 
   } 
```

# 打印棋盘

如果您迄今为止一直在跟进，请继续编写我们程序的最后一部分，一行代码来将我们的棋盘打印到屏幕上。实际上，我们需要的不仅仅是一行代码。我们可以使用`println()`函数以及`arrays.toString()`来将单个数组的内容打印到屏幕上，但是这种技术在二维或更高维数组中效果不佳。

因此，我们需要再次使用`for`循环来依次抓取每个数组，然后将它们打印到屏幕上。这很有效，因为`println`将自动换行，或者在我们打印每一行之间给我们一个新行。在这里，让我们使用传统的语法变量`i`来迭代我们的`for`循环：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/e9febda2-dfd7-4516-9fde-4248e4d90dcb.png)

您会注意到，Java 还不理解前面截图中显示的`Arrays`关键字；这是因为`Arrays`位于`java.lang`包中。当我们调用函数或类时，Java 不知道立即在哪里找到它，我们必须上网在 Google 上找到它时，这可能有点烦人。如果我们在 IDE 中工作，比如 NetBeans，有时会有一个查找常用包的快捷方式。在这种情况下，如果我们右键单击问题语句并转到“修复导入”，NetBeans 将浏览常用包并检查是否可以弄清楚我们在做什么：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/ad6ff3b4-9a65-4431-b208-6bca9a0bfe94.png)

在这种情况下，NetBeans 已经找到了`Arrays`类并为我们添加了导入语句：

```java
import java.util.Arrays; 
```

现在，因为我们不想在每次`for`循环执行时尝试打印二维数组的内容（这样也不会很好），我们将告诉我们的`println`语句打印`board[i]`的内容，或者我们已经访问的二维数组中的单个数组：

```java
public static void main(String[] args) { 
   int boardDim = 8;  
   char[][] board = new char[boardDim][boardDim]; 
   boolean isWhite = false; 

   for(int y = 0; y < board.length; y++) 
   { 
       isWhite = !isWhite; 
       for(int x = 0; x < board[y].length; x++) 
       { 
           if(isWhite) board[y][x] = 'W'; 
           if(!isWhite) board[y][x] = 'B'; 
           isWhite = !isWhite; 
       } 
   } 

   for(int i = 0; i < board.length; i++) 
   { 
       System.out.println(Arrays.toString(board[i])); 
   } 
} 
```

现在，让我们看看我们第一次是否做得对，并运行我们的程序：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/8e6cded2-3f5b-4752-8e51-5bd514db59e9.png)

哇！看起来我们做到了。有一个交替的白色和黑色的棋盘表示，以白色方块开始，并且行以正确的方式开始。现在可能看起来不起眼，但它的意义很大。我们基本上教会了我们的程序棋盘是什么样子。这是我们朝着创建更大的东西迈出的第一步，比如一个下棋的程序。

如果我们创建一个下棋程序（这有点超出了本节的范围，但我们可以在概念上讨论一下），我们可能希望我们的每个方块能够存储更多信息，而不仅仅是它们的颜色。例如，我们可能希望它们知道上面有什么棋子。为了实现这一点，我们可以利用三维数组。我们可以创建一个看起来像下面这样的数组，以便每个方块可以存储一个包含两个信息的数组，一个字符表示它的颜色，另一个字符表示它上面有什么棋子：

```java
char[][][] board = new char[boardDim][boardDim][2]; 
```

这就是 Java 中多维数组的基础。

# ArrayLists

当我们需要一个 Java 数据结构时，我们应该首先问自己是否简单的数组就足够了。如果我们可以使用一个简单的数组轻松整洁地编写我们的程序，那可能是保持程序简单的最佳选择。如果你正在编写必须尽可能快地运行并尽可能高效地使用内存的代码，数组也将几乎没有额外开销。但是，在今天的开发世界中，内存效率和速度对于普通程序来说真的不是问题，有时我们需要使用具有更多内置功能的数据结构，或者可能是为特定目的而设计的数据结构。

具有附加功能的数据结构称为 ArrayList。传统数组的一个弱点是，当我们实例化它们时，我们必须给它们一个特定的长度，因此我们必须知道我们希望数组有多大。ArrayList 基本上是一个包装在一些附加代码中的数组，这些代码导致数组的大小增加或减小，以始终保持与其包含的元素数量相同的大小。

# NetBeans 中的一个 ArrayList 示例

要看到这个实例，让我们编写一个程序，如果我们只使用标准数组而不是 ArrayList，那么编写起来可能会更困难一些。我想编写一个程序，它将从用户那里获取一个输入字符串。它将存储这个输入字符串以及用户以前给它的每个其他输入字符串，然后每次用户输入一个新字符串时都打印它们出来。

这将是非常困难的，因为如果用户输入的字符串比数组设计的容量多一个，数组将在最好的情况下不接受字符串；在最坏的情况下，程序可能会崩溃。但是，我们的 ArrayList 对象将简单地调整大小以适应它当前持有的字符串数量。

# 创建一个 ArrayList

我们需要从导入`java.util`开始，因为`java.util`是`Scanner`类（我们需要获取用户输入）和`ArrayList`类本身所在的地方。一旦我们声明了一个`Scanner`，我们稍后会更多地利用它，现在是时候声明我们的`ArrayList`了：

```java
package echo; 

import java.util.*; 

public class Echo { 
    public static void main(String[] args) { 
        Scanner reader = new Scanner(System.in); 
        ArrayList memory = new ArrayList(); 
    } 
} 
```

简单地声明`ArrayList`看起来很像声明任何其他对象。我们说出我们想创建的对象的类型。我们给它一个名字。我们使用`new`关键字，因为 Java 将不得不设置一些内存来创建这个对象，因为它不是原始的。然后，我们告诉 Java 实际创建对象。即使我们不会为我们的`ArrayList`创建提供任何参数，我们仍然需要在其后跟上双括号。这实际上是我们刚刚编写的有效代码，但通常当我们创建一个`ArrayList`时，我们会做更多的事情。

我们创建的`ArrayList`内存实际上将存储我们放入其中的任何类型的单个实体。这一开始听起来可能非常好，但老实说，在我们的程序中这不是一件好事。如果我们有 ArrayLists，或者任何数据结构，实际上存储了几乎任何东西，很容易感到困惑，如果我们觉得有必要这样做，要么我们正在做一些非常复杂的事情，要么更可能的是我们没有编写我们的代码如我们应该那样清晰。更重要的是，一旦我们在 ArrayList 中存储任何东西，我们就有可能绕过编译器并创建编译正常的代码。然而，另一种可能性是它会在运行时出错，导致那种在商业软件中非常糟糕的 bug，因为它们在人们实际使用时可能会出现问题。

为了解决这个问题，我们可以告诉我们的 ArrayList 只接受特定类型的信息。我们通过在`ArrayList`声明和实例化后跟随双字符括号，并在其中放置一个类型来实现这一点：

```java
ArrayList<String> memory = new ArrayList<String>(); 
```

我们声明并使`ArrayList`数据结构成为可能，它只允许存储字符串。

# 获取用户输入

我们需要一个循环，这样我们的用户可以向程序输入多个字符串。现在，让我们只使用一个无限循环。它将永远运行，但在构建程序和调试程序时，我们总是可以手动停止它：

```java
while(true) 
{ 

} 
```

每次循环运行时，我们都要使用 Scanner 变量`reader`上的`nextLine()`函数，从用户那里获取一个新的输入行，并将其存储在我们的 ArrayList 中。

当我们使用对象数据结构时，也就是说，具有自己的代码包装、函数和方法的数据结构时，通常不需要处理内存的各个索引，这可能非常好。相反，我们使用它们提供的函数来添加、删除和操作其中的信息。

在这种情况下，向 ArrayList 添加内容非常容易。ArrayList 中的`add()`函数将添加我们提供的任何输入，也就是说，只要它是一个字符串，就会将其添加到 ArrayList 包含的数组的末尾。因此，让我们添加以下代码行，它将请求用户输入一个新的字符串，然后将其放在我们的无限`while`循环内的 ArrayList 末尾：

```java
memory.add(reader.nextLine()); 
```

# 打印用户输入的 ArrayList

现在，我们可以简单地使用`println`将我们的 ArrayList 打印给用户。请注意，`println`代码行不知道如何将 ArrayList 作为输入。实际上，它可能知道，但我们应该明确使用`toString()`函数，几乎每个 Java 对象都实现了它：

```java
package echo; 

import java.util.*; 

public class Echo { 
    public static void main(String[] args) { 
        Scanner reader = new Scanner(System.in); 
        ArrayList<String> memory = new ArrayList<String>(); 

        while(true) 
        { 
            memory.add(reader.nextLine()); 
            System.out.println(memory.toString()); 
        } 
    } 
} 
```

现在，当我们运行我们的程序时，我们将被提示输入一些用户输入，并且我们将看到输入被回显。如果我们给 Java 一些更多的输入，我们将看到更多的输入，并且旧的输入将被存储在我们的`ArrayList`中：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/e01f0a61-f15e-4542-b690-6f8bdfa5e77e.png)

所以这很酷！我们已经构建了一个非常基本的程序，使用简单的数组写起来会更困难。

# 将控制权交给用户

ArrayLists 内含有很多强大的功能。我们可以将它们转换为数组，从数组创建它们，以及各种其他操作。如果我们去 Java 文档并在`java.util`下查找 ArrayList，我们可以找到它们的所有方法。让我们给我们的 ArrayList 程序添加一些功能，这样我就可以向您介绍一些常见的 ArrayList 方法。

ArrayLists 有一个不需要输入的函数，称为`clear()`，它将擦除我们的 ArrayList。我们可以利用这个函数来让我们的用户对我们的程序有一些控制。假设如果用户输入字符串`CLEAR`，我们想要擦除 ArrayList 中的所有信息。好吧，这是一个条件语句，所以我们使用`if`语句。我们将在我们的`while`循环内部使用以下`if`语句代码来实现这个功能：

```java
if((memory.get(memory.size()-1)).equals("CLEAR")) memory.clear(); 
```

首先，我们需要检查刚刚添加到我们的 ArrayList 中的项目是否与字符串`CLEAR`相匹配。这个项目将位于最后，也就是说，它将是具有最高索引值的最后一个项目。不幸的是，ArrayList 没有实现`lastItem()`函数，但我们可以通过将两个 ArrayList 函数`get()`和`size()`组合在一起来创建一个自己的函数。

首先，为了从 ArrayList 中获取一个项目，我们利用`get()`函数。请注意，`get()`与我们访问传统数组中的项目时会使用的方括号非常相似。此外，`get()`函数将接受一个整数值，并将该整数映射到包含在我们的 ArrayList 中的数组的索引。

因此，要获取我们的 ArrayList 中的最后一个项目，我们需要知道 ArrayList 中有多少个项目。然后，我们想从该值中减去一个，因为长度为 7 的数组的最后一个索引将是 6，因为数组从零开始计数。要获取我们的 ArrayList 中有多少个项目，我们使用`size()`函数，它不需要参数，只是给我们一个整数，即数组的大小，即它包含多少个项目。我们从该值中减去`1`，以便我们可以正确访问最后一个索引，而不是其后面的索引，它可能包含任何内容。然后，我们将整个`memory.get(memory.size()-1)`块，它访问我们的`ArrayList`的最后一个项目，用括号括起来。

我们刚刚括起来的`if`语句块为我们获取了一个字符串对象。我们知道可以使用`equals()`方法来比较字符串。实际上，我们可以从这个代码块返回的字符串对象中调用该方法，即使我们还没有为它分配一个特定的变量名。对象存在，即使我们没有它们的名称，如果我们刚刚从其他地方返回它们，我们可以调用它们的方法，并且可以做任何我们喜欢的事情。

```java
while(true) 
{ 
    memory.add(reader.nextLine()); 
    if((memory.get(memory.size()-1)).equals("CLEAR")) 
        memory.clear(); 
    System.out.println(memory.toString()); 
} 
```

因此，这是一个我们刚刚写的非常疯狂的语句，但只要我们写得正确，当我们的用户在程序中输入`CLEAR`时，我们将擦除 ArrayList。

写完这段代码后，我们可以编写非常类似的代码，为我们的用户提供不同的功能选项。让我们也允许用户输入`END`。目前，我们处于一个将无限循环直到我们手动关闭它的程序中。但是通过使用`break` Java 关键字，它将使我们跳出我们所在的任何循环，或者如果我们在一个函数中，它将使我们跳出该函数，我们可以使这个循环可以被打破。这样，我们可以让用户基本上关闭我们的程序，因为一旦我们离开这个循环，就没有更多的代码可以执行，我们的程序将结束：

```java
public static void main(String[] args) { 
    Scanner reader = new Scanner(System.in); 
    ArrayList<String> memory = new ArrayList<String>(); 

    while(true) 
    { 
        memory.add(reader.nextLine()); 
        if((memory.get(memory.size()-1)).equals("CLEAR")) { 
            memory.clear(); 
        } 
        if((memory.get(memory.size()-1)).equals("END")) 
        break; 
    } 
    System.out.println(memory.toString()); 
} 
```

在使用`break`语句时要小心。确保这样做是有意义的，因为如果你在阅读别人的代码时，它们可能会让人有点困惑。它们会打破并跳转控制流到各个地方。

所以让我们运行这个程序，看看会发生什么。我们将从给我们的程序一些输入开始，并构建 ArrayList：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/ae823de0-08af-458a-a9c0-062b10bb890b.png)

现在让我们尝试输入`CLEAR`并检查它是否清空了我们的 ArrayList。哦，不！我把它弄坏了：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/daa354cd-4dd8-4f52-ab30-374efe042f27.png)

这实际上是一个非常有趣的错误。我实际上犯了这个错误；这不是预先计划的。我会留下它，因为这对我们来说是一个很好的学习经验。它还表明，即使你是一名经验丰富的程序员，你也会犯错误。例如，我们应该尽可能使用带类型的 ArrayList，这样我们就可以轻松地找出并纠正我们的错误。

# 分析 ArrayIndexOutOfBoundsException

我们的程序抛出了`ArrayIndexOutOfBoundsException`。这意味着我们试图访问我们的`memory`数组没有访问权限的内存。具体来说，我们试图查看数组索引-1 处的内容。由于数组从索引 0 开始，它们没有任何内容在索引-1 处。计算机内存的任何部分都可能在那里，出于安全原因，程序不允许随意查看计算机的内存。那么，为什么会发生这种情况？为什么我们要求查看数组的索引-1，这永远不会是有效的数组索引？

嗯，我们第一个实现清除 ArrayList 功能的`if`语句执行得很好。我们的程序看到了我们的`CLEAR`命令，理解了我们对数组索引的第一次查看，并清空了数组。

紧接着，我们要求程序再次检查添加到数组中的最后一项，使用第二个`if`语句。当我们这样做时，我们执行了`memory.size()-1`。首先，我们询问 Java 关于我们的 ArrayList 的大小。因为我们刚刚清空了 ArrayList，Java 告诉我们 ArrayList 的大小为零，里面什么也没有。然后我们从这个值中减去 1，得到-1。然后，我们在这个-1 值上运行`memory.get()`。因此，我们要求 Java 查看数组索引-1 处的内容，此时 Java 说：“哇！你在干什么？这不好，我要崩溃了！”

那么，我们该如何解决这个问题呢？嗯，我们可以做一些事情。我们应该在运行第二个`if`语句中的函数之前检查并确保我们的数组不为空。这个选项看起来比我想要的代码行数多一些。这并不是不可逆转的，我鼓励你尝试并实现比这更好的解决方案。

目前，为了让我们的程序快速启动并且不崩溃，让我们将一对`if`块改为`if...else`语句如下：

```java
while(true) 
{ 
    memory.add(reader.nextLine()); 
    if((memory.get(memory.size()-1)).equals("CLEAR")) { 
    memory.clear(); 
    } 
    else { 
        if((memory.get(memory.size()-1)).equals("END")) 
        break; 
    } 
    System.out.println(memory.toString()); 
} 
```

我们将第二个`if`语句嵌入了`else`块中。这将阻止我们连续运行两个`if`块。如果我们的第一个`if`语句评估为真并且我们的清除语句被执行，那么我们将不会检查第二个`if`语句。

现在，如果我们运行程序并输入一些胡言乱语来构建我们的 ArrayList，然后输入`CLEAR`，我们将正确地得到一个空的 ArrayList 的响应：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/7adf9ca8-08b9-4c14-9d90-873227e545ea.png)

我们永远不会在大小为 0 的数组上触发第二个`if`语句，因为我们总是会在之前向数组中添加一行。

现在，让我们祈祷并检查`END`输入是否有效：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/4da83cb8-0be7-42ee-998b-1fb11670670b.png)

它确实会！`break`命令专门用于跳出循环和函数，所以即使我们将其嵌套在 if 和 else 语句中，它仍然会将我们从`while`循环中跳出来。

我认为我们遇到的小问题是一个很好的学习经验。我们遇到的错误实际上是一个非常有趣的错误。尽管如此，我希望你已经看到不同的数据结构有不同的用途。

# 地图

在本节中，我们将研究 Java 的`Map`数据结构。我想从一堆已经格式化的信息开始，所以我自己创建了一个小程序。你可以在本书的附属文件中找到以下程序。仔细查看它，确保你理解它的工作原理：

```java
package maps; 
import java.util.*; 
public class Maps { 
    public static void main(String[] args) { 
        String[] allNames =   
            //<editor-fold desc="raw names data"> 
            {"Jane", "Addams", 
            "Muhammad", "Ali", 
            "Stephen", "Ambrose", 
            "Louis", "Armstrong", 
            "Joan", "Baez", 
            "Josephine", "Baker", 
            "Eleanor", "Roosevelt", 
            "Frank", "Sinatra" 
            }; 
            //</editor-fold> 
        String[] firstNames = new String[allNames.length/2]; 
        String[] lastNames = new String[allNames.length/2]; 
        for(int i = 0; i < allNames.length; i++) 
        { 
            /*This if statement checks if we are in an EVEN      
            NUMBERED iteration  
            % is the "mod" or "modulus" operator...  
            it returns the remainder after we divide number1 by      
            number2)*/ 
            if(i % 2 == 0)  
            { 
                //We are in an even number iteration - looking at      
                a first name 
                firstNames[i/2] = allNames[i]; 
            } 
            else 
            { 
                //We are in an odd number iteration - looking at a   
                last name 
                lastNames[i/2] = allNames[i]; 
            } 
        } 
        System.out.println(Arrays.toString(firstNames)); 
        System.out.println(Arrays.toString(lastNames)); 
    } 
} 
```

我假设我们还不熟悉文件输入和输出，所以我把我们通常想要存储在文件中或其他更可管理的地方的所有数据都放在了我们程序的代码中。我创建了一个名为`allNames`的字符串数组，它是一组名人的名字。他们各自的名和姓也被分开。所以`简`，`亚当斯`是数组的前两个元素。她的名`简`是`allNames[0]`的一部分，然后`亚当斯`，她的姓，是在`allNames[1]`，以此类推，数组中的每两个元素是一个人的名和姓。

这也是我向你展示一个很棒的小功能的好机会，这个功能在大多数 IDE 中都可以使用。如果我们的 IDE 经常支持这样的功能，我们可以通过在代码的注释中放置对它们的指令来与它们交流。因为这些指令被注释掉了，它们不会以任何方式影响我们的 Java 代码的编译和运行，但我们可以与 IDE 交流。程序中的以下指令和它的结束指令告诉 NetBeans 我们想要它将它们之间包含的代码分隔开：

```java
//<editor-fold desc="raw names data"> 
. 
. 
. 
//</editor-fold> 
```

现在，我们可以使用左侧的小框来展开和收缩代码块，就像下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/abf0f56c-f800-4b58-ac72-23308b838434.png)

它并没有使代码消失；它只是把它从我们面前隐藏起来，这样我们就可以在不弄乱屏幕的情况下开发它：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/7535308f-d7b1-46cf-8b1a-43623e9b0262.png)

现在，让我们来看一下我写的程序的一个非常快速的解释，以开始这一部分。我们有一个名为`allNames`的字符串数组，其中包含许多名人的名和姓。我写的程序简单地循环遍历这个数组，并确定它是在查看名字还是姓。然后它将这些名字放在它们自己的单独的数组中。最后，当我们打印出这些数组时，我们有两个单独的数组：一个是名字的数组，一个是姓的数组。这些数组的关系是，因为我们将它们按顺序放入了两个单独的数组（`firstNames`和`lastNames`）中，所以数组的索引是匹配的。因此，在`firstNames[0]`和`lastNames[0]`，我们有简·亚当斯的名字和姓。

现在，我想扩展这个程序，并将所有这些信息放在一个单一的数据结构中：一个 Java`Map`。在创建这样一个 Map 时，我们让它知道一个集合之间的关系，我们称之为键，另一个集合，我们称之为值，这样每个键都映射到值。这将允许我们向我们的程序提问，比如，“给定一个名人的姓，与之相关联的名字是什么？”

# 创建一个 Map

首先，我已经导入了`java.util`，那里有`Map`接口。接下来，我将删除打印`firstNames`和`lastNames`数组的最后两个`println`语句。相反，在我们的代码中的这一点上，当我们的`firstNames`和`lastNames`数组已经设置好时，让我们开始构建我们的`Map`。为此，添加以下代码行：

```java
Map<String, String> famousPeople = new HashMap<>(); 
```

我们首先使用`Map`关键字，然后，与大多数数据结构一样，我们告诉 Java 我们的`Map`将要接受什么类型的信息。Map 接受两组信息，所以我们必须给它两个以逗号分隔的信息类型。第一个信息类型是 Map 的键的信息类型，第二个信息类型是 Map 的值的类型。

我们将使用`lastNames`作为我们的键，因为我们不希望我们的`Map`在一个键中存储多个值，而且我们很少会有多个相同的姓氏。此外，对我们来说，询问名为 Addams 的名人的名字比询问名为 Jane 的名人的姓氏更有价值，后者可能更多。无论如何，`lastNames`的数据类型是`String`，`firstNames`的数据类型也是`String`。

接下来，我们给我们的新`Map`变量取一个名字：`famousPeople`。然后，我们通过实例化来使我们的`Map`存在。为了做到这一点，我们使用`new`关键字。`Map`实际上不是一个对象，它是我们称之为接口。在大多数情况下，我们以相同的方式与接口和对象交互，但我们不能简单地声明一个接口的实例。相反，接口是我们放在对象之上的功能的额外包装，就像 ArrayLists 为数组添加了额外的功能一样。

因此，要创建一个新的`Map`，我们需要一个更简单的对象类型，我们可以在其周围包装`Map`接口。这方面的一个很好的候选者是`HashMap`。因此，我们创建我们的`HashMap`并将我们的 Map 变量`famousPeople`分配给它。现在，我们将与这个`famousPeople`变量交互，就像它是一个具有所有`Map`功能的对象一样。此外，如果我们愿意，我们也可以在这个对象上调用`HashMap`功能。

虽然这有点超出了本节的范围，但接口的强大之处在于我们可以将它们分配给不同类型的对象，从而为否则不同的对象类型提供共同的功能。但是，目前，我们主要只对 Java Maps 的功能和功能感兴趣。您会注意到，我们不必明确告诉 Java 我们的`HashMap`将采用什么类型。这实际上是一种风格选择；如果我们愿意，我们可以明确声明`HashMap`将采用的类型：

```java
Map<String, String> famousPeople = new HashMap<String, String>(); 
```

然而，由于我们只会根据其作为`Map`的功能与我们的`HashMap`进行交互，通过变量`famousPeople`与我们的`HashMap`进行交互时，我们只需要保护自己免受添加除字符串以外的任何东西的影响，这样就可以了。

# 为我们的 Map 分配值

一旦我们设置了我们的`Map`，就该是时候填充它的信息了。对此，我认为使用`for`循环是合适的：

```java
for(int i = 0; i < lastNames.length; i++) 
{ 
    famousPeople.put(lastNames[i], firstNames[i]); 
} 
```

我们需要向我们的 Map 添加许多信息对，即一个键和一个值，等于这些数组中的任何一个的项目数。这是因为它们的长度相同。因此，让我们设置一个`for`循环，遍历从`i`到（`lastNames-1`）的每个索引。`i`值将映射到`lastNames`数组的索引，因为`firstNames`数组的长度与`lastNames`数组的长度相同，它们也将映射到`firstNames`数组的索引。

现在，对于每个`i`，我们将执行我们的 Map 的`put()`函数。`put()`函数类似于`add()`函数。它将信息插入到我们的 Map 中。但是，这个函数期望两个信息。首先，它期望我们的键，即我们当前在`lastNames`中查看的值，然后它期望相关的值，即我们在`firstNames`中查看的值。每次我们在我们的`for`循环中执行`famousPeople.put(lastNames[i], firstNames[i]);`这行代码时，我们将向我们的`Map`添加一个新的键值对。

# 从我们的 Map 中获取信息

一旦我们设置了`Map`，程序中已经包含了所有信息，我们只需要问一些问题，确保我们得到正确的回答：

```java
System.out.println(famousPeople.get("Addams")); 
```

我们使用`get()`函数来询问我们的`Map`它设计来回答的基本问题，“与给定键配对的值是什么？”因此，让我们问我们的`Map`，“与`Addams`配对的值是什么？”，或者更容易理解的英语术语，“在我们的 Map 中，姓氏是`Addams`的人的名字是什么？”当我们运行这个程序时，我们得到了预期的结果，即`Jane`。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/0df094d6-336d-4e4a-8b59-fef66961165b.png)

让我们再运行一次，以确保我们没有犯任何愚蠢的错误。让我们看看当我们输入`Sinatra`时，我们的程序是否会回答`Frank`：

```java
System.out.println(famousPeople.get("Sinatra")); 
```

确实如此！

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/8e045ad4-f16e-4761-865b-25557362080d.png)

虽然我们可以通过简单地循环遍历数组来编写这样的程序（当我们获得用户输入时找到`lastName`，存储该索引，并从`firstNames`获取它），但我们的 Map 接口基本上为我们做到了这一点。也许更重要的是，当我们与其他程序员合作或查看我们昨天没有编写的代码时，当我们看到`Map`时，我们立即理解它的预期目的以及它实现的功能。在几乎所有情况下，编写能够正常工作的代码同样重要，因为它是合理的，并且将被未来可能遇到代码的其他人理解。

# 总结

在本章中，我们讨论了数组，并举了一个使用数组打印英文字母表的例子。接下来，我们看了多维数组，并编写了一个创建二维棋盘的程序。

我们介绍了 ArrayList 是什么，以及它如何增强数组的功能。我们还编写了一个使用具有功能的 ArrayList 的程序，这在使用数组实现将会相当困难。最后，我们看了 Maps 并实现了一个例子以更好地理解它。

在下一章中，我们将详细讨论 Java 函数。


# 第五章：函数

在本章中，我们将从讨论 Java 程序基础知识中使用的一些基本概念和术语开始。你将通过简单的程序学习所有这些概念。你将了解到至关重要的 Java 方法。如果你是一名有经验的程序员，你可能以前遇到过函数。随着这些基本概念的进展，你将更多地了解高级 Java 函数。以下是我们计划在本章中涵盖的主题：

+   Java 函数的基础知识

+   方法

+   高级 Java 函数

+   操作 Java 变量

# Java 函数的基础知识

在 Java 中，“函数”和“方法”这两个术语基本上是可以互换使用的，而“方法”是更加技术上正确的术语，你会在文档中看到。

# 方法

**方法**是一种工具，允许我们打破程序的控制流。它们让我们声明一些小的**子程序**，有时我们可以把它们看作更小的程序，我们可以在我们的程序中引用它们，这样我们就不必把我们程序的所有逻辑代码都写在一个单一的块中：

```java
public class TemperatureConverter { 
    public static void main(String[] args) { 
        Scanner reader = new Scanner(System.in); 
        char inputType; 
        char outputType; 
        float inputValue; 
        float returnValue; 

        System.out.print("Input type (F/C/K): "); 
        inputType = reader.next().charAt(0); 
        System.out.print("Output type (F/C/K): "); 
        outputType = reader.next().charAt(0); 
        System.out.print("Temperature: "); 
        inputValue = reader.nextFloat(); 
    } 
} 
```

方法的一个例子是`Scanner`类中的`.next`方法。在我写的这个程序中，我们不必教`Scanner`对象如何获取用户输入的下一组数据，我只需从过去某人编写的类中调用`next`方法。这将把可能是几百行程序的东西转换成大约 22 行，如前面的代码所示。

通过编写我们自己的方法，我们可以通过将复杂的挑战分解成更小、更易管理的部分来解决它们。正确模块化并使用方法的程序也更容易阅读。这是因为我们可以给我们的方法起自己的名字，这样我们的程序就可以更加自解释，并且可以使用更多的英语（或者你的母语）单词。为了向你展示方法的强大之处，我已经计划了一个相当复杂的程序，今天我们要写这个程序。

# 温度转换程序

我们的目标是创建一个温度转换程序，我已经为我们设置了程序的输入部分：

```java
public class TemperatureConverter { 
    public static void main(String[] args) { 
        Scanner reader = new Scanner(System.in); 
        char inputType; 
        char outputType; 
        float inputValue; 
        float returnValue; 

        System.out.print("Input type (F/C/K): "); 
        inputType = reader.next().charAt(0); 
        System.out.print("Output type (F/C/K): "); 
        outputType = reader.next().charAt(0); 
        System.out.print("Temperature: "); 
        inputValue = reader.nextFloat(); 
    } 
} 
```

到目前为止，这个程序从用户那里获取了三条信息。第一条是温度类型：`F`代表华氏度，`C`代表摄氏度，`K`代表开尔文。然后它获取另一种温度类型。这是我们的用户希望我们转换到的类型；再一次，它可以是华氏度、摄氏度或开尔文。最后，我们从用户那里获取初始温度的值。有了这三条输入，我们的程序将把给定的温度值从华氏度、摄氏度或开尔文转换为用户所需的温度类型。

这是一个具有挑战性的程序，原因有两个：

+   首先，因为有两组三个用户输入，所以有六种可能的控制流情况。这意味着在最坏的情况下，我们可能不得不写六个`if...else`块，这将很快变得笨拙。

+   第二个挑战是进行实际的转换。我已经提前查找了三种温度转换的转换数学，即华氏度到摄氏度，摄氏度到开尔文，和开尔文到华氏度：

```java
package temperatureconverter; 

import java.util.*; 

// F to C: ((t-32.0f)*5.0f)/9.0f 
// C to K: t+273.15f 
// K to F: (((t-273.15f)*9.0f)/5.0f)+32.0f 

public class TemperatureConverter { 
    public static void main(String[] args) { 
        Scanner reader = new Scanner(System.in); 
        char inputType; 
        char outputType; 
        float inputValue; 
        float returnValue; 
```

正如你所看到的，虽然这不是困难的数学问题，但它肯定是笨拙的，如果我们开始在程序中到处复制和粘贴公式，我们的程序看起来会非常疯狂。你还应该注意，在前面的评论部分中，有三种转换，我们可以做出这个程序将被要求做的任何可能的转换。这是因为这三种转换创建了一个转换的循环，我们可以通过其中一个中间方程从一个特定类型到任何其他类型。

说了这么多，让我们直接开始编写我们的程序吧。

# 设置控制流

我们需要做的第一件事是设置一些控制流。正如我之前提到的，有六种可能的情况，可能会诱人地为每种可能的输入和输出类型设置六个`if`语句。不过这会有点笨拙，所以我有一个稍微不同的计划。我将不同的情况转换为每种可能的类型配对，首先要做的是将用户给出的初始温度值转换为摄氏度值。在我这样做之后，我们将把摄氏度值转换为用户最初寻找的类型。可以使用以下代码块来完成这个操作：

```java
System.out.print("Input type (F/C/K): "); 
inputType = reader.next().charAt(0); 
System.out.print("Output type (F/C/K): "); 
outputType = reader.next().charAt(0); 
System.out.print("Temperature: "); 
inputValue = reader.nextFloat(); 
```

设置控制流的优势在于让我们完全独立地处理两个用户输入。这使得我们的程序更加模块化，因为我们在开始下一个任务之前完成了一个任务。

因此，为了进行这个初始转换，我们需要利用`switch`语句：

```java
public static void main(String[] args) { 
    Scanner reader = new Scanner(System.in); 
    char inputType; 
    char outputType; 
    float inputValue; 
    float returnValue; 

    System.out.print("Input type (F/C/K): "); 
    inputType = reader.next().charAt(0); 
    System.out.print("Output type (F/C/K): "); 
    outputType = reader.next().charAt(0); 
    System.out.print("Temperature: "); 
    inputValue = reader.nextFloat(); 

    switch(inputType) 
} 
```

我们将在`inputType`字符变量之间切换，该变量告诉我们用户给出的温度类型是华氏度、摄氏度还是开尔文。在`switch`语句内部，我们将操作`inputValue`，其中存储着温度的值。

# 探索单独的情况-C、K 和 F

所以我想我们需要为每种可能或有效的输入类型编写单独的情况，即大写`F`代表华氏度，`C`代表摄氏度，`K`代表开尔文。我们可能还需要处理一个`default`情况。让我们先写`default`情况。我们将使用`System.exit`并以`1`退出，这在技术上是一个错误代码：

```java
switch(inputType) 
{ 
    case 'F': 
    case 'C': 
    case 'K': 
    default: 
        System.exit(1); 
```

`System.exit`基本上退出我们的程序。它告诉程序停止执行并传递给操作系统或者更高级的东西。

在这种情况下，程序将停止。因为这是`default`情况，我们只期望在用户未能输入`F`、`C`或`K`时进入它，这些是我们有效的输入类型。现在，让我们处理每种输入类型。

# 摄氏类型

我们将在所有情况下使用摄氏度作为我们的第一个转换点，所以如果用户输入了摄氏值，我们可以直接跳出这种情况，因为`inputValue`的值对我们来说已经可以了。

```java
switch(inputType) 
{ 
    case 'F': 
    case 'C': 
        break; 
    case 'K': 
        default: 
            System.exit(1); 
```

如果用户给出了华氏值怎么办？好吧，让我们滚动到代码的顶部；你会看到我们有一个明确的从华氏到摄氏的转换：

```java
// F to C: ((t-32.0f)*5.0f)/9.0f 
// C to K: t+273.15f 
// K to F: (((t-273.15f)*9.0f)/5.0f)+32.0f 
```

我们可以采用前面的代码块，我已经使其非常适合 Java，并只需更改此输入变量的值为其值上运行的转换语句。因此，我们将用输入变量替换`t`占位符：

```java
switch(inputType) 
{ 
    case 'F': 
        inputValue = ((inputValue-32.0f)*5.0f)/9.0f; 
        break; 
    case 'C': 
        break; 
    case 'K': 
    default: 
        System.exit(1); 
} 
```

这将正确地存储原始华氏值的摄氏等价值在这个变量中。

# 开尔文类型

我们可以对开尔文情况做类似的事情。我们没有一个明确的从开尔文到摄氏的转换，但我们知道如何将开尔文转换为华氏，然后再将华氏转换为摄氏。所以我们可以用以下方式做一些事情：

```java
switch(inputType) 
{ 
     case 'F': 
         inputValue = ((inputValue-32.0f)*5.0f)/9.0f; 
         break; 
     case 'C': 
         break; 
     case 'K': 
         inputValue = ((((((inputValue-273.15f)*9.0f)/5.0f)+32.0f) -   
         32.0f)*5.0f)/9.0f; 
     default: 
         System.exit(1); 
} 
```

在前面的代码中，我们将开尔文值转换为华氏值，用括号括起来，并对其进行华氏到摄氏的转换。

现在这在技术上是一行功能性的代码。如果我们运行程序并输入一个开尔文输入情况，它将正确地将开尔文值转换为摄氏度值。但是，让我说，如果我是一个程序员，我在工作中遇到这样一行代码，特别是没有任何解释的代码，我是不会很高兴的。这里有很多魔术数字-数字在一般情况下真的是信息；这并不是以任何方式自解释的。当然，作为原始程序员，至少当我们写它时，我们记得我们的目标是将开尔文值转换为摄氏度值；然而，对于任何没有时间坐下来查看整个程序的其他人来说，这真的是不可理解的。那么有没有更好的方法来做到这一点？是的，绝对有。

# 华氏度类型

现在让我们尝试理解华氏温度的情况。考虑以下代码：

```java
inputValue = ((inputValue-32.0f)*5.0f)/9.0f; 
```

上面的代码行比我们的开尔文情况好一点，因为它包含的数字更少，但从任何意义上来说，它仍然不够友好。那么，如果在我们最初实现这个程序时，我们可以提供真正对程序员友好的通信，会怎么样呢？如果我们不是在那里打印出等式，而是把等式放在程序的其他地方并调用一个华氏度到摄氏度的函数呢？

```java
inputValue = fToC(inputValue); 
```

现在我们只需输入 `fToC` 来保持简洁。这对于查看我们的程序的人来说更有意义。

我们可以在这里做类似的事情来处理开尔文情况：

```java
inputValue = fToC(kToF(inputValue)) 
```

如果我们想的话，我们可以调用一个开尔文到摄氏度的函数（`kToC`），或者如果我们甚至不想写那个，我们可以在我们的 `inputValue` 变量上调用一个开尔文到华氏度的函数，然后在此基础上调用 `fToC` 函数。这就是我们最初所做的所有数学概念上的事情，只是我们已经抽象出了那些数字，并把它们放在了程序的其他地方。这对程序员来说更友好。假设我们在数学上犯了一个错误，另一个程序员想要检查它。他们只需要找到我们即将编写的函数，比如 `fToC` 和 `kToF`，然后他们就可以深入了解所有的细节。因此，当然，我们确实需要编写这些函数。

当我们创建一个新函数时，我们实际上是在当前的函数或方法之外进行的：

```java
public static void main(String[] args) { 
```

目前，我们在程序的 `main` 方法中，这是一个特殊的方法，程序从这里开始执行。因此，为了编写我们的华氏度到摄氏度函数，我们将退出该方法并声明一个全新的方法；基本上，我们正在教我们的程序如何运行一个名为 `fToC` 的新程序：

```java
public static fToC() 
```

现在，继续在你的方法前面使用 `public static` 关键字。一旦我们真正进入 Java 的面向对象的特性，这些关键字将非常重要，但现在，我们将在我们声明的所有方法上使用它们。

关于我们接下来计划如何处理程序的更详细解释，让我们尝试更详细地分割程序，分成两部分。

# 执行程序的第一部分

您标准的 Java 方法在我们给它一个名称之前还有一个关键字，那就是这个方法将返回的信息类型：

```java
public static float fToC() 
{ 
} 
```

例如，我们希望能够在我们的开尔文到华氏度函数上调用`fToC`。当我们这样做时，我们基本上将我们的开尔文到华氏度函数的结果视为自己的浮点变量。这表明我们在这些函数中寻找的返回类型是`float`数据类型。这意味着当这些小程序执行完毕时，它们将向我们调用它们的`main`方法抛出一个浮点值。在命名函数之后，我们在其前面的函数声明中跟随两个括号。在这些括号之间，我们将告诉我们的程序这个函数需要运行的信息。我们通过基本上创建一些变量来做到这一点，如下面的代码块所示：

```java
public static float fToC(fVal) 
```

我们将需要一个变量，我将其称为`fVal`，因为我们从华氏度值开始。在每个输入变量之前，我们还需要告诉我们的程序那将是什么类型的信息；这样人们就无法不正确地调用我们的函数并传递诸如字符串之类的东西，这是毫无意义的。

```java
public static float fToC(float fVal) 
{ 
} 
```

因此，我们要告诉我们的函数，为了运行，它需要以给定的`float`信息作为输入进行调用。在我们之前编写的函数中，它们实际上存在于程序中。您会看到我们这样做：我们将`inputValue`或用户最初给我们的温度值的值作为这些函数的输入。

现在，我们需要我们的`fToC`函数，我们的华氏度到摄氏度函数，在代码中对`fVal`变量执行一些计算，其中将包含用户输入的温度值。由于我们从华氏度到摄氏度，我们可以只需复制并粘贴程序顶部的字符串，并将`fVal`替换为`t`：

```java
public static float fToC(float fVal) 
{ 
    fVal = ((fVal-32.0f)*5.0f)/9.0f; 
} 
```

现在，我们可能会诱惑我们的函数执行此操作来更改此变量的值。虽然我们当然可以这样做，但这不会给我们带来我们需要的结果。当我们的程序执行`inputValue = fToC(inputValue);`这行代码并运行我们的`fToC`函数时，将`inputValue`作为其输入变量，这个变量实际上不会降到我们函数的代码行中。相反，Java 只是复制`inputValue`的值并将其存储在我们的新变量中，如下面的代码块所示：

```java
public static float fToC(float fVal) 
{ 
    fVal = ((fVal-32.0f)*5.0f)/9.0f; 
} 
```

因此，我们对这个`fVal`变量所做的更改不会映射到我们的`inputValue`变量。幸运的是，我们明确地将`inputValue`的值更改为我们现在编写的函数返回的值。一旦我们准备退出函数的执行，我们可以让它丢弃任何与我们告诉 Java 此函数将返回的值类型相等的值。我们使用`return`关键字来做到这一点，后面跟着计算为我们的情况下浮点值的任何语句。因此，当我们的`fToC`函数在`inputValue`上运行时，它将打印出与存储在输入变量中的初始华氏值等效的浮点数：

```java
public static float fToC(float fVal) 
{ 
    return ((fVal-32.0f)*5.0f)/9.0f; 
} 
```

一旦我们编写了其中一个函数，编写其他类似的函数就变得非常容易。要编写我们的开尔文到华氏度的函数，我们只需要做同样的事情，但在这种情况下，我们需要采用我们的开尔文到华氏度转换方程并更改变量的名称。如果我们愿意，我们可以称之为`fVal`-`kVal`只是更具说明性，并返回该结果：

```java
public static float fToC(float fVal) 
{ 
    return ((fVal-32.0f)*5.0f)/9.0f; 
} 
public static float kToF(float kVal) 
{ 
    return (((kVal-273.15f)*9.0f)/5.0f)+32.0f; 
} 
```

这是我们程序的第一部分，我们将用户提供的任何值转换为摄氏度值。到目前为止，这比使用六个`if`语句更加优雅，但我们只写了程序的一半。

# 执行程序的第二部分

一旦我们完成了摄氏度的转换，我们将使用另一个`switch`语句。这一次，我们将在`outputType`上使用它，用户告诉我们他们想要看到等值的温度类型，或者在哪种温度类型下看到等值。我们的情况将看起来非常类似于`switch`语句的前半部分；然而，这里我们不是将所有东西转换为摄氏度，而是总是从摄氏度转换。同样，这意味着`C`情况可以在我们转换为摄氏度的任何情况下简单地中断，然后我们不再需要从摄氏度转换：

```java
// F to C: ((t-32.0f)*5.0f)/9.0f 
// C to K: t+273.15f 
// K to F: (((t-273.15f)*9.0f)/5.0f)+32.0f 
```

现在，我们明确的情况是摄氏度到开尔文的转换。我们知道这个公式，多亏了我们在代码顶部的小抄；我们可以很快地构建一个函数来做到这一点。我们将这个函数称为`cToK`；这是我们的变量名，这是逻辑：

```java
public static float fToC(float fVal) 
{ 
    return ((fVal-32.0f)*5.0f)/9.0f; 
} 
public static float kToF(float kVal) 
{ 
    return (((kVal-273.15f)*9.0f)/5.0f)+32.0f; 
} 
public static float cToK(float cVal) 
{ 
    return cVal+273.15f; 
} 
```

一旦我们声明了我们的`cToK`函数，我们可以在`inputValue`上调用它，因为`inputValue`现在存储了修改后的原始输入值，这将是一个摄氏度数字，要转换为开尔文值：

```java
case 'K': 
    inputValue = cToK(inputValue); 
```

类似于我们将开尔文转换为华氏度再转换为摄氏度的方式，当我们将所有东西都转换为摄氏度时，我们可以通过从摄氏值获取一个开尔文值来获得一个华氏输出。然后，我们可以使用开尔文转换为华氏度的函数将这个开尔文值转换为华氏度：

```java
case 'F': 
    inputValue = kToF(cToK(inputValue)); 
    break; 
case 'C': 
    break; 
case 'K': 
    inputValue = cToK(inputValue); 
    break; 
default: 
    System.exit(1);  
```

这是我们程序的第二部分。仍然只有两行真正的代码可能会让任何人停下来，它们都相当容易理解。然而，我们程序的所有逻辑和功能对于一个好奇的程序员来说仍然是可访问的，他想要重新访问它们：

```java
    } 
    System.out.println(inputValue); 
} 
```

# 程序的最后一步

我们可以使用 `println` 来结束我们的程序，输出 `inputValue`，它现在应该包含正确的转换。让我们运行这个程序，输入一些值并输出，看看我们的表现如何：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/3b90ab5d-c1a0-43a7-8c85-c9edc4df9cda.png)

因此，当我们运行我们的程序时，它会询问我们要给它什么`inputType`。让我们给它一个华氏值。现在让我们说我们想要得到一个摄氏值作为输出。让我们看看`32`华氏度对应的摄氏值是多少。我们看到输出结果是`0`。`32`华氏度是`0`摄氏度，这是一个好迹象。让我们尝试一些更极端的情况。如果我们试图将摄氏度转换为摄氏度，我们得到的值与下面的截图中显示的值相同，这是我们所期望的：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/470f1c0c-7f71-4fc9-a40f-09378870ebfa.png)

让我们看看`1`开尔文度对应的华氏值是多少：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/ab570c83-a707-4b65-952f-471542ba6293.png)

好消息是，这也是前面截图中的预期值。我们使用函数使一个本来非常复杂和难以阅读的程序变得更加可管理。我们在这里编写的程序有些复杂。它进行了一些数学和多功能语句，所以如果你第一次没有完全理解，我鼓励你回去检查是什么让你困惑。还有其他方法来解决这个问题，如果你有灵感，我鼓励你去探索一下。

# 高级 Java 函数

在这一部分，我希望你深入了解 Java 方法，并学习一些关于编程语言如何思考和操作信息的非常有价值的东西。为了帮助我们做到这一点，我想进行一种实验，并且为了开始这个实验，我写了一个非常基本的 Java 程序：

```java
package advancedmethods; 

public class AdvancedMethods { 
    public static void main(String[] args) { 
        int x = 5; 
        magic(x); 
        System.out.println("main: " + x); 
    } 
    public static void magic(int input) 
    { 
        input += 10; 
    } 
} 
```

在这个 Java 程序的核心是`magic`方法，它是在`main`方法之后用户自定义的。当我们遇到一个新的 Java 方法时，有三件事情我们应该注意：

1.  首先，我们应该问，“它的输入值是什么？”在我们的`magic`方法中，它只期望一个整数作为输入。

1.  然后，我们可能想问，“这个方法返回什么？”。在我们的情况下，该方法标记为返回`void`。Void 方法实际上根本不返回任何值；它们只是执行它们的代码并完成。您会注意到，当我们在程序的主要部分引用`magic`时，我们并没有尝试将其返回值存储在任何位置。这是因为当然没有返回值可以存储。

1.  然后，关于我们的方法要注意的第三件事是“它做什么？”。在我们的`magic`方法的情况下，我们只是取得我们作为`input`得到的值，并将该值增加`10`。

我想现在要求你做的是花一分钟时间，仔细看看这个程序，并尝试弄清楚当我们到达这个`println`语句时，程序的输出将是什么。这里的挑战性问题是当我们运行`magic(x)`代码行并调用我们的`magic`方法时，变量`x`的值会发生什么变化？当我们将其作为值传递给`magic`方法时，变量`x`是否保持不变，或者变量`x`是否被`magic`方法中的输入代码行修改，以至于我们打印出`15`而不是`5`的值？

要回答这个问题，我们只需要运行我们的程序，如果我们这样做，我们将看到我们得到了`5`的值，这让我们知道运行`magic`方法并没有修改主方法中变量`x`的值：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/d0223233-6d3c-4f27-845e-94b6d995826e.png)

实际上，如果我们根本不运行`magic`方法，我们将得到相同的输出。那么这告诉我们什么？这为我们提供了一个非常重要的见解，即 Java 如何处理方法输入。要完全理解这里发生了什么，我们需要更深入地了解 Java 变量的操作。

# 操作 java 变量

以下是我们的变量`x`存储的信息的表示，即我们 Java 程序的`main`方法中的变量：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/c151dbad-8fa2-482a-8226-0c0cbddfbb44.png)

您会注意到这个变量有三个核心组件；让我们快速浏览一下：

+   在左侧，我放置了这个变量的名称，这是我们在范围内引用它所使用的关键字，以及一个内存位置。我们的变量指向一个内存位置，在这个内存位置中，我们存储变量的值。

+   我们可以将名称和内存位置视为非常静态的；在我们程序执行过程中，这个单独的变量标识符不会真正改变。然而，我们可以自由地更改变量引用的内存位置中存储的值。

那么这为什么重要呢？好吧，在我们的程序过程中，我们将不得不将存储在变量`x`中的信息转换为我们的`magic`方法试图使用的变量输入中存储的信息。如果我们仔细看看变量的设置方式，我们很快就会发现有两种可能的方法来做到这一点：

1.  首先，我们可以简单地创建一个名为`input`的全新变量，具有其自己独特的内存位置，然后简单地将我们在`x`引用的内存位置中找到的相同值放置在该内存位置中的值中：![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/a1dc02e8-ffbb-4715-80f2-2b985061044c.png)

当我们将变量`x`传递给一个方法时，这是 Java 用来创建变量`input`的技术，我们可以说 Java 通过值传递了我们的变量`x`。这是因为只有值在创建新变量时被保留。

1.  另一个选项是我们创建一个全新的变量`input`，但是我们不仅仅是将变量`x`的值复制到变量`input`，我们可以使`input`引用与`x`相同的内存位置。这将被称为通过引用传递变量`x`。在这种情况下，因为`x`和`input`都共享一个内存位置来存储它们的值，修改变量`input`的值也会修改变量`x`的值。

因此，根据您刚刚了解的关于 Java 变量的知识，并考虑到在`magic(x)`代码行上执行`magic`方法不会修改变量`x`的值，我们可以正确地得出结论，Java 选择通过值而不是通过引用将变量传递给其方法。

然而，这并不是故事的结束，或者说，这个事实可能对我们来说并不立即显而易见。如果我们重写我们的程序，使我们的`magic`方法接受字符输入、布尔输入或任何其他原始类型，我们将看到与我们已经看到的相同的行为。即使在`magic`方法的范围内修改此`input`变量的值，也不会修改`main`方法的范围内的变量`x`的值。所以，事情并不总是那么简单。

# 在程序中使用变量

为了看到这一点，让我们创建一个全新的方法，在它的声明中，我们将它与我们现有的`magic`方法相同。但是，我们将以整数数组的形式提供它作为输入：

```java
package advancedmethods;
public class AdvancedMethods {
    public static void main(String[] args) {
        int[] x = 5;
        magic(x);
        System.out.println("main: " + x);
    }

    public static void magic(int input)
    {
        input += 10;
    }
    public static void magic(int[] input)
    {
        input += 10;
    }
}
```

记住，我们的数组将被命名为一个单一的变量，所以我们需要做的就是让 Java 知道我们想要将一个数组传递给函数，通知它给定的变量是某种类型的数组。您还会注意到，我们现在在程序中有两个名为`magic`的方法。这被称为**方法重载**，只要 Java 有办法区分这些方法，这样做就是完全合法的。在这种情况下，Java 可以区分这些方法，因为这两个方法将被赋予不同的对象作为输入。

如果给`magic`调用的输入是单个整数，则我们的`magic`方法之一将执行，如果给方法的输入是整数数组，则我们的新`magic`方法将执行。现在，让我们编写一个快速的`for`循环，这样我们的新`magic`方法将将输入数组中的每个整数的值增加`10`：

```java
public static void magic(int[] input) 
{ 
    for(int i = 0; i < input.length; i++) 
    input[i] += 10; 
} 
```

这与我们最初编写的`magic`方法非常相似，只是它不是操作单个整数，而是操作任意数量的整数。然而，当我们修改我们的`main`方法以利用`magic`方法的新实现时，可能会发生一些奇怪的事情。为了实现这一点，我们需要对我们的程序进行一些快速修改。

让我们将变量`x`从整数更改为整数数组，这样我们的程序将知道如何利用新编写的`magic`方法，当我们给定整数数组作为输入时，它将运行：

```java
package advancedmethods; 

import java.util.*; 

public class AdvancedMethods { 
    public static void main(String[] args) { 
        int[] x = {5,4,3,2,1}; 
        magic(x); 
        System.out.println("main: " + Arrays.toString(x)); 
    } 
    public static void magic(int input) 
    { 
        input += 10; 
    } 
    public static void magic(int[] input) 
    { 
        for(int i = 0; i < input.length; i++) 
        input[i] += 10; 
    } 
} 
```

我们还需要修改我们的`println`语句，以利用`Arrays.toString`来正确显示`x`数组中存储的值。我们将导入`java.util`，以便 Java 知道`Arrays`库：

```java
import java.util.*; 

public class AdvancedMethods { 
    public static void main(String[] args) { 
        int[] x = {5,4,3,2,1}; 
        magic(x); 
        System.out.println("main: " + Arrays.toString(x)); 
    } 
```

现在是时候问自己另一个问题了：当我们在整数数组上运行`magic`函数时，我们是否会看到与我们在单个整数值上运行`magic`函数时看到的相同结果，即原始类型？要回答这个问题，我们只需要运行我们的程序，我们很快就会看到，存储在`x`数组中的输出或最终值与我们最初分配给`x`数组的值不同：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/0496807d-3c0e-4732-88a6-d5d773dc9050.png)

这让我们知道我们的`magic`方法确实修改了这些值。这有点奇怪。为什么我们的`magic`方法会根据我们给它的是单个原始类型还是原始类型数组而有不同的操作？为了回答这个问题，让我们看看当变量`x`被声明为整数数组而不是我们之前的单个整数时会发生什么：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/bcccfc80-e74f-404e-8fa1-3c2a3a78c4da.png)

请注意，`x`作为一个整数数组，而不是单个原始类型，仍然具有名称和内存位置来标识它以及它可以存在的位置；但是，它的值字段看起来与以前大不相同。当`x`只是一个整数时，我们可以简单地将一个显式整数存储在`x`的值字段中，但是作为数组，`x`意味着能够引用许多不同的值；这就是它成为数据结构的原因。为了实现这一点，数组-实际上每个比原始类型更复杂的元素-指向内存中的一个位置，而不是单个显式值。对于数组，我们只需要指向内存中数组的 0 索引。然后，通过从该索引开始，我们可以存储许多不同的值，我们的变量`x`知道如何访问。那么这为什么重要呢？

# 理解传递参数

好吧，让我们看看当我们按值传递`x`到方法时会发生什么。我们知道，当我们按值传递一个变量时，我们告诉 Java 在方法的上下文中创建一个新变量，该变量将具有自己独特的名称和内存位置：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/4b8e10e2-4b1b-4d2e-83ab-b27a38e1475d.png)

然而，在我们的例子中，这个新变量-`input`-获取了旧变量的值作为自己的值。当我们处理原始类型时，这些值是完全独立的，但现在`input`和`x`都具有相同内存位置的值。因此，修改输入的值不会改变`x`的值，但修改输入指向的内存位置仍会改变`x`查看时的内存位置。

在方法的上下文中，如果我们明确引用一个输入变量，然后修改该变量，我们将只修改函数上下文中的变量，就像我们在第一个`magic`方法中所做的那样。但是，如果我们必须采取额外的步骤来访问我们正在修改的值，就像我们在声明数组的索引时必须做的那样，那么我们可能必须通过内存位置或引用来修改它。在这种情况下，我们可能会影响为我们函数变量提供值的变量：

```java
package advancedmethods; 

import java.util.*; 

public class AdvancedMethods { 
    public static void main(String[] args) { 
        int[] x = {5,4,3,2,1}; 
        magic(x); 
        System.out.println("main: " + Arrays.toString(x)); 
    } 
    public static void magic(int input) 
    { 
        input += 10; 
    } 
    public static void magic(int[] input) 
    { 
        input = new int[] {2,2,2,2,2}; 
    } 
} 
```

如果我们的接受数组的`magic`函数尝试将我们的整数数组的值设置为全新的整数值集合，并具有全新的起始内存位置，我们会发现当我们在其上运行此函数时，我们将不再修改`x`的值：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/3917bd79-b30a-405d-94ea-38d819081037.png)

这是因为创建一个新的整数数组导致我们明确改变了输入的值。在这行代码之后，`input`和`x`不再共享值。非常感谢您的时间。希望您学到了一些东西。

# 总结

您还在吗？如果是的，恭喜。我们从一些基本的 Java 函数开始，比如方法，然后继续理解高级 Java 函数。我们刚刚讨论了一些复杂的东西。随着您成为更有经验的程序员，您将开始内化这些概念，当您编写日常代码时，您不必明确考虑它们。不过，现在有一些逻辑快捷方式可以帮助我们避免太多的困扰。

在下一章中，您将详细了解使用面向对象的 Java 程序进行建模。


# 第六章：用面向对象的 Java 建模

在本章中，你将学习如何在 Java 中创建类和对象。面向对象编程使我们能够向计算机和自己解释高度复杂的系统。此外，关于对象如何相互配合、它们可以有哪些关系以及我们可以如何使用对象来使我们的程序更容易编写，还有很多要学习的关于面向对象编程的内容。我们还将讨论创建自定义类、成员变量和成员函数的主题。最后，我们将研究分配给我们自定义类的一个非常特殊的成员，即构造函数，以及构造函数的类型。

在本章中，我们将涵盖以下主题：

+   创建类和对象

+   创建自定义类

+   创建成员变量

+   创建成员函数

+   创建构造函数

+   构造函数的类型

# 创建类和对象

在这一部分，你将迈出学习 Java 面向对象编程的第一步。所以我想问的第一个问题是，“什么是面向对象编程？”嗯，在高层次上，面向对象编程是创建对象的过程，这些对象是独特的、相互独立的代码和逻辑实体，但它们之间可以有复杂的关系。

当我们编写面向对象的代码时，我们开始将代码看作一组物理部件或对象。Java 本质上是一种面向对象的语言。因此，如果你一直在学习 Java，至少你已经在使用对象而没有意识到。

要看到面向对象编程的威力，看一下下面的程序（`GettingObjectOriented.java`）：

```java
package gettingobjectoriented; 

import java.util.*; 

public class GettingObjectOriented { 
    public static void main(String[] args) { 
        Scanner reader = new Scanner(System.in); 

        System.out.println(reader.next()); 
    } 
} 
```

这个程序是一个非常基本的输入/输出程序，如果你一直在学习 Java，你可能已经写过这种程序。在这个程序中，我们使用了一个名为`Scanner`的对象，我们称之为`reader`，你会注意到我们在两行上使用了`reader`：在一行上，我们声明并初始化了`reader`，在另一行上，我们调用了`reader`的`next()`函数来获取一些用户输入。

我希望你注意到这两行代码之间的关系的重要之处是，当我们声明`reader`时，我们为它提供了除了简单地创建一个新的`Scanner`对象的命令之外的一些额外信息。这很有趣，因为当我们后来使用`reader`的`next()`函数时，我们不需要重新告诉它应该从哪个流中读取；相反，这些信息会被`reader`对象自动存储和调用。

这就是面向对象编程的美妙之处：我们创建的实体或对象可以被构造成这样一种方式，不仅它们知道如何处理给予它们的信息并为我们提供额外的功能，而且它们也知道要询问什么信息来执行它们以后的任务。

让我们确保我们的术语准确。首先，让我们分析我们代码中的`new Scanner(System.in)`部分。这个命令告诉 Java 为我们的程序创建一个新对象，一个新的`Scanner`对象。这个对象有它所在的位置和内存，这个位置由`reader`变量引用。我们可以创建多个变量，它们都指向同一个`Scanner`对象；然而，在这个简单程序的上下文中，`reader`是我们指向对象内存位置的唯一入口点。因此，我们通常可以通过它的变量名来简单地引用一个对象。

最后，不同的对象以不同的方式运行。我们可以创建多个`Scanner`对象；它们在内存中的位置可能不同，但它们会共享类似的功能。声明对象具有什么功能以及该功能如何运行的代码和逻辑称为对象的类。在这种情况下，我们正在创建一个`Scanner`类的对象，并用`reader`变量指向它。

这一切都很好，我们可以简单地使用 Java 提供的默认标准库创建许多程序；然而，为了真正打开大门，我们需要能够创建自定义的类。让我们开始并创建一个。

# 创建自定义类

现在，我们可以在我们已经在工作的文件中创建一个新的类；然而，类声明代码与像执行的`main()`方法之类的逻辑上是不同的，其中代码行是按顺序依次执行的。相反，我们要创建的类将更多地作为代码行的参考，比如`Scanner reader = new Scanner(System.in);`这行代码。通常，在面向对象的语言中，像 Java 这样的高级面向对象的语言，我们只需将我们创建的每一个新类放在自己单独的文件中。

要为我们的类创建一个新的 Java 文件，只需右键单击屏幕左侧的包名，即`gettingobjectoriented`。然后，选择新建，然后选择 Java 类。之后，我们只需提示给它一个名称。

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/88f2915e-e554-4960-845e-e813202442d0.png)

在这种情况下，我们将创建一个类来提供和存储有关一个人的一些基本信息。我们将称之为`Person`类，它创建人物对象：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/ea693725-8198-41c4-97bc-b9b55944f955.png)

当我们按下“完成”时，NetBeans 非常方便，为我们设置了一些非常基本的代码行。它声明这个类在我们的本地包中。这意味着当我们从我们的`main()`方法中引用它时，我们不必像引用标准库那样导入这个类。NetBeans 很友好地为我们创建了类声明。这只是一行代码，让 Java 编译器知道我们将要声明一个新的类，如下面的屏幕截图所示：

```java
package gettingobjectoriented;
public class Person {
}
```

现在，我们将忽略`public`关键字，但知道它在这里是非常必要的。`class`关键字让我们知道我们将要声明一个类，然后就像我们创建并需要在将来引用的一切一样，我们给类一个名称或一个唯一的关键字。

现在是时候编写代码来设置我们的`Person`类了。请记住，我们在这里所做的是教会程序的未来部分如何创建`Person`对象或`Person`类的实例。因此，我们在这里编写的代码将与我们在一个简单地执行从头到尾的方法中所写的代码非常不同。

我们在类声明中放置的信息将属于这两类之一：

+   第一类是我们告诉 Java `Person`类应该能够存储什么信息

+   第二类是我们教 Java`Person`对象应该暴露什么功能

# 创建成员变量

让我们从第一类开始。让我们告诉 Java 我们想在`Person`中存储什么信息：

```java
package gettingobjectoriented; 

public class Person { 
    public String firstName; 
    public String lastName; 
} 
```

告诉 Java 要存储的信息很像在任何其他代码中声明变量。在这里，我们给`Person`类两个成员变量；这些是我们可以在任何`Person`对象中访问的信息。

在类声明中，几乎我们声明的每一样东西都需要给予保护级别。当我们成为更高级的 Java 用户时，我们将开始使用不同的保护级别，但现在，我们只是简单地声明一切为“public”。

因此，正如我们在这里设置的那样，每个`Person`对象都有`firstName`和`lastName`。请记住，这些成员变量对于`Person`对象的每个实例都是唯一的，因此不同的人不一定共享名字和姓氏。

为了让事情变得更有趣，让我们也给人们分配生日。我们需要导入`java.util`，因为我们将使用另一个类`Calendar`类：

```java
package gettingobjectoriented; 
import java.util.*; 
public class Person { 
    public String firstName; 
    public String lastName; 
    public Calendar birthday; 
} 
```

日历基本上是点和时间或日期，具有大量功能包装在其中。很酷的是`Calendar`是一个独立的类。因此，我们在`Person`类中放置了一个类；`String`也是一个类，但 Java 认为它有点特殊。

现在，让我们回到`GettingObjectOriented.java`文件中的`main()`方法，看看创建一个全新的人是什么样子。现在，我们将保留这行代码，以便将其用作模板。我们想要创建我们的`Person`类的一个新实例或创建一个新的`Person`对象。为此，我们首先要告诉 Java 我们想要创建什么类型的对象。

因为我们在使用的包中声明了`Person`类，Java 现在将理解`Person`关键字。然后，我们需要给我们将分配新人的变量一个名字；让我们将这个人命名为`john`。创建一个新人就像创建一个新的`Scanner`对象一样简单。我们使用`new`关键字让 Java 知道我们正在创建一些全新的尚不存在的东西，然后要求它创建一个人：

```java
package gettingobjectoriented; 

import java.util.*; 

public class GettingObjectOriented { 
    public static void main(String[] args) { 
        Scanner reader = new Scanner(System.in); 
        Person john = new Person(); 
        System.out.println(reader.next()); 
    } 
} 
```

在这里，`Person john = new Person ();`将导致变量`john`指向的人，我们将简单地认为是一个人 John，出现。现在`john`已经具有一些基本功能，因为我们已经为`Person`类声明了一些成员变量，因此即使我们对`Person`类的基本声明也给了 John 一些我们可以使用的成员变量。

例如，`john`有`firstName`，我们可以使用点(`.`)运算符作为变量进行访问，并且我们可以继续为这个变量分配一个值。我们也可以用同样的方法处理 John 的姓和当然是他的生日：

```java
package gettingobjectoriented;
import java.util.*;
public class GettingObjectOriented {
    public static void main(String[] args) {
        Scanner reader = new Scanner(System.in);
        Person john = new Person();
        john.firstName = "John";
        john.lastName = "Doe";
        john.birthday = 
        System.out.println(reader.next());
    }
}
```

现在，我已经提到`birthday`在我们到达这一点时会与`firstName`和`lastName`有些不同。虽然字符串在 Java 中在技术上是类，但 Java 也赋予它们能够被分配给显式值或字符串显式的特权。当然，日历没有这种独特的特权，因此我们需要创建一个新的`Calendar`对象放在我们的对象中，也就是`john`。

现在，`Calendar`是我们可以分配实例的类之一；但是，当我们想要创建一个全新的实例时，我们需要创建一个更具体的也是日历的东西。因此，对于这个实例，我们将使用`GregorianCalendar`。然后，让我们将`birthday`分配给`john`，比如`1988,1,5`。然后，为了查看一切是否按预期分配，只需打印出 John 的名和姓。

我们运行以下程序时：

```java
package gettingobjectoriented;
import java.util.*;
public class GettingObjectOriented {
    public static void main(String[] args) {
        Scanner reader = new Scanner(System.in);
        Person john = new Person();
        john.firstName = "John";
        john.lastName = "Doe";
        john.birthday = new GregorianCalendar(1988,1,5);
        System.out.println(john.firstName + john.lastName);
    }
}
```

我们看到`John Doe`并没有真正格式化，但是按预期打印到屏幕上：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/de2afc61-669a-4365-bb7b-e1a0074faf72.png)

我们已经成功地将信息存储在我们的`john`对象中。如果我们愿意，我们可以创建一个全新的人“Jane”，她将拥有自己的`firstName`、`lastName`和`birthday`；她的成员变量完全独立于 John 的。

# 创建成员函数

让我们回到我们的`Person`类，也就是`Person.java`文件，并为人们提供更多功能。因此，面向对象的 Java 的美妙之处在于，我们已经开始将我们的`Person`类的实例视为物理对象。这使得预期将会问到他们的问题变得更容易。

例如，当我遇到一个新的人时，我大多数情况下要么想知道他们的名字，要么想知道他们的全名。所以，如果我们的人存储了一个名为`fullName`的字符串，人们可以直接询问而不必单独获取他们的名字和姓氏，这不是很好吗？

当然，简单地添加另一个成员变量是不方便的，因为创建`Person`的新实例的人需要设置`fullName`。而且，如果人的名字、姓氏或全名发生变化，他们的`fullName`、`firstName`和`lastName`变量可能不会正确匹配。但是，如果我们提供一个成员方法而不是成员变量呢？

当我们在类的上下文中创建方法时，我们可以访问类的成员变量。如果我们想要修改它们，或者像我们刚刚做的那样，我们可以简单地利用它们的值，比如返回这个人动态构造的全名。

```java
package gettingobjectoriented; 
import java.util.*; 
public class Person { 
    public String firstName; 
    public String lastName; 
    public Calendar birthday; 
    public String fullName() 
    { 
         return firstName + " " + lastName; 
    } 
} 
```

我预计这个人会被问到另一个问题，那就是你多大了？这将很像我们刚刚写的方法，只有一个例外。为了知道这个人多大了，这个人需要知道今天的日期，因为这不是这个人已经存储的信息。

为了做到这一点，我们将要求人们在调用这个方法时传递这些信息，然后我们将简单地返回今天年份与这个人的生日年份之间的差异。

现在，从日历中获取年份的语法有点奇怪，但我认为我们应该能够理解。我们只需使用`get`方法，它有许多用途，然后我们需要告诉方法我们想从中获取什么，我们想从中获取一个日历年(`Calendar.YEAR`)。所以，让我们确保保存这个文件，跳转到我们的`main`方法，并利用我们刚刚添加到`Person`实例的新方法之一：

```java
package gettingobjectoriented;
import java.util.*;
public class Person {
    public String firstName;
    public String lastName;
    public Calendar birthday;
    public String fullName()
    {
         return firstName + " " + lastName;
    }
    public int age(Calendar today)
    {
         return today.get(Calendar.YEAR) - birthday.get(Calendar.YEAR);
    }
}
```

所以，我们设置了`john`。他有一个生日。让我们在这里的`println`语句中问 John 他多大了。为了做到这一点，我们只需调用 John 的`age`方法，并创建一个新的`Calendar`对象传递进去。我认为新的`GregorianCalendar`实例将默认设置为当前日期和时间。

如果我们运行以下程序：

```java
package gettingobjectoriented;
import java.util.*;
public class GettingObjectOriented {
    public static void main(String[] args) {
        Scanner reader = new Scanner(System.in);
        Person john = new Person();
        john.firstName = "John";
        john.lastName = "Doe";
        john.birthday = new GregorianCalendar(1988,1,5);
        System.out.println(john.age(new GregorianCalendar()));
    }
}
```

我们看到 John 今年`29`岁：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/f5c7490e-f32d-4a9f-9d4e-ebbcc7d3829c.png)

这就是我们的基本介绍了。这是我们对面向对象的 Java 的基本介绍，但最终都会归结为你刚学到的基础知识。

# 创建构造函数

在这一部分，你将学习到我们可以分配给自定义类的一个非常特殊的成员，那就是构造函数。首先，让我们看一下下面的代码：

```java
package gettingobjectoriented; 

import java.util.*; 

public class GettingObjectOriented { 
    public static void main(String[] args) { 
        Scanner reader = new Scanner(System.in); 
        Person john = new Person(); 
        john.firstName = "John"; 
        john.lastName = "Doe"; 
        john.birthday = new GregorianCalendar(1988,1,5); 
        System.out.println( 
            "Hello my name is " +            
            john.fullName() + 
            ". I am " + 
            john.age(new GregorianCalendar()) + 
            " years old."); 
    } 
} 
```

这个程序创建了我们自定义类`Person`的一个实例，并立即为`Person`的成员变量`firstName`、`lastName`和`birthday`赋值。然后，我们利用`Person`的一些成员函数打印出我们刚刚分配的一些信息。

虽然这是一个不错的程序，但很容易看到即使是这样一个简单的程序，也可能出现错误。例如，如果我忘记了或者根本没有意识到`birthday`是`Person`的成员变量之一会怎么样？如果我不立即为一个人分配生日，然后尝试使用`age()`成员方法，就像下面的代码块中所示的那样：

```java
package gettingobjectoriented; 

import java.util.*; 

public class GettingObjectOriented { 
    public static void main(String[] args) { 
        Person john = new Person(); 
        john.firstName = "John"; 
        john.lastName = "Doe"; 
        //john.birthday = new GregorianCalendar(1988,1,5); 
        System.out.println( 
        "Hello my name is " + 
        john.fullName() + 
        ". I am " + 
        john.age(new GregorianCalendar()) + 
        " years old."); 
    } 
} 
```

当程序尝试访问尚未设置任何内容的生日变量时，我们的程序将崩溃，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/0f2b5fbb-e447-4ac9-810c-03b55d08602b.png)

对于程序员来说，这是一个非常合理的错误，既不知道他们应该将这个成员变量设置为一个值，也假设这个成员变量会有一个值，因为什么样的人没有生日呢？幸运的是，我们有一个系统，可以在允许用户创建对象实例之前要求用户提供信息。因此，让我们进入声明`Person`类的代码，并设置这个类，以便只有在一开始就提供了所有必要的信息时才能创建一个人。为此，我们将使用构造函数。

构造函数声明看起来很像普通方法声明，除了一点。普通方法会有一个返回值，甚至如果它不打算返回任何东西，也会有一个 null 值；构造函数甚至没有那个。此外，构造函数方法的名称与我们分配给类的名称相同；然而，就像普通方法一样，我们可以给构造函数传入参数。

首先，让我们假设所有人都有“名”、“姓”和“生日”；否则，他们根本就不应该存在。当我们创建`Person`类的新实例并且`Person`类已经定义了构造函数时，我们将始终使用`Person`构造函数创建类的实例：

```java
package gettingobjectoriented; 

import java.util.*; 

public class Person { 
    public String firstName; 
    public String lastName; 
    public Calendar birthday; 

    public Person(String firstName, String lastName, Calendar birthday) 
    { 

 } 

    public String fullName() 
    { 
         return firstName + " " + lastName; 
    } 

    public int age(Calendar today) 
    { 
         return today.get(Calendar.YEAR) - birthday.get(Calendar.YEAR); 
    } 
} 
```

如果我们保存了对`Person`类声明的这个更新，然后回到我们程序的`main`方法，我们将得到一个编译器错误，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/f3ccf2f3-6332-408f-82f2-fd6311238cf4.png)

这是因为我们修改了`Person`类，要求我们使用新创建的构造函数。这个构造函数接受三个输入值：一个字符串，一个字符串和一个日历。因此，我们不会在这三行代码中修改`Person`的成员变量，而是将这三个变量作为参数传递给我们的构造函数方法：

```java
package gettingobjectoriented; 

import java.util.*; 

public class GettingObjectOriented { 
    public static void main(String[] args) { 
        Person john = new Person("John", "Doe", newGregorianCalendar(1988,1,5)); 

        System.out.println( 
        "Hello my name is " + john.fullName() + ". I am " + john.age(new 
        GregorianCalendar()) + 
        " years old."); 
    } 
} 
```

现在，就我们的程序中的`main`方法而言，程序的语法再次是有效的。当然，如果我们运行这个程序，我们将遇到一些麻烦，因为虽然我们将这些参数传递给`Person`构造函数，但我们还没有对它们做任何处理。

现在，这里的工作应该是我们的`Person`构造函数的工作，而不是我们 Java 程序中的`main`方法，将这些参数转换为`Person`的成员变量的值。所以，让我们这样做。让我们将`Person`类的`firstName`更改，或者说将其值设置为传递给这个函数的变量：

```java
package gettingobjectoriented;
import java.util.*;
public class Person {
    String firstName;
    String lastName;
    Calendar birthday;
    public Person(String firstName, String lastName, Calendar birthday)
    {
         firstName = firstName;
    }
    public String fullName()
    {
         return firstName + " " + lastName;
    }

    public int age(Calendar today)
    {
         return today.get(Calendar.YEAR) - birthday.get(Calendar.YEAR);
    }
}
```

现在，这是一个技术上正确的语法；它将做我们想要做的事情。

`firstName = firstName`这行代码真的很奇怪，如果你仔细阅读它，它是相当模糊的。毕竟，在每个实例中，我们在谈论哪个`firstName`变量？我们是在谈论`Person.firstName`，这个类的成员变量，还是在谈论作为构造函数方法参数传递的`firstName`？为了消除这种歧义，我们可以做一些事情。

首先，我们可以简单地更改我们分配给方法参数的名称，使其不与本地成员名称相同；然而，有时明确要求`firstName`是有意义的。对于将要使用构造函数的人来说，这可能更容易。当我们需要明确告诉我们的程序，我们正在使用`Person`类的成员变量之一时，我们应该正确地为其提供路径。`this`关键字将允许我们在程序运行时访问我们当前操作的类，或者说它的对象实例。因此，`this.firstName`将始终引用成员变量，而不是作为参数传递的变量。现在我们有了语法，我们可以快速地将参数值分配给我们的成员变量的值：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/7fe7dc9b-4335-4baa-8a59-3b6f1594e465.png)

现在，当我们保存这个文件并返回到我们的`main`方法——也就是`GettingObjectOriented.java`——并运行我们的程序时，我们将得到原始输出，显示我们的`Person`构造函数已经正确地将这些输入值映射到我们`Person`对象中存储的值：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/c3d6ffb7-b1f5-472c-992b-75ea6c0f336d.png)

所以这很酷。我们修改了我们的`Person`类，使得程序员更难犯一个明显的错误并在它们注定失败时调用这些方法。如果程序员在创建我们的人之后修改了成员变量中的一个，他们仍然可能遇到麻烦。

然而，如果我们选择的话，有一个系统可以保护我们的类，使其成员不能在没有经过适当协议的情况下被修改。假设我们想要更改我们的`Person`类，以便这些成员只在构造函数调用时被修改一次。如果你记得的话，我们一直在给我们的类的所有成员打上`public`保护标签。被标记为`public`的东西基本上可以被我们程序中任何有权访问其容器的部分随时查看。

然而，我们可以使用一些其他不同的保护标签。如果我们将所有成员变量标记为`private`，那么它们只能在其当前类的上下文中查看。因此，我们仍然可以在我们的`Person`构造函数和我们的`fullName`和`age`方法中使用成员变量，但是当我们尝试在实际类声明之外访问`lastName`时，它将是无效的：

```java
package gettingobjectoriented; 

import java.util.*; 

public class Person { 
    private String firstName; 
    private String lastName; 
    private Calendar birthday; 
```

我们可以将成员标记为`private`，然后创建公共方法在适当的时候修改它们的值。通过这样做，我们将保护我们的对象免受无效值的影响。

# 构造函数的类型

现在，让我们回到谈论构造函数，然后结束。与普通方法一样，我们可以重写构造函数，并为程序员提供多个选择。

例如，假设在我们的程序中有时我们想要创建刚出生的新人。在这种情况下，我们可能会通过简单地将`firstName`和`lastName`传递给我们的构造函数，然后将`birthday`设置为`new Gregorian Calendar`来构造一个人，这将默认为今天的日期：

```java
package gettingobjectoriented; 

import java.util.*; 

public class Person { 
    private String firstName; 
    private String lastName; 
    private Calendar birthday; 
    public Person(String firstName, String lastName) 
    { 
         this.firstName = firstName; 
         this.lastName = lastName; 
         this.birthday = new GregorianCalendar(); 
    } 

    public Person(String firstName, String lastName, Calendar 
    birthday) 
    { 
         this.firstName = firstName; 
         this.lastName = lastName; 
         this.birthday = birthday; 
    } 
```

如果我们想在我们的程序中使用这个构造函数，我们只需调用只有两个字符串参数的构造函数。这将映射到我们在这里声明的新创建的构造函数。

考虑以下程序：

```java
package gettingobjectoriented; 

import java.util.*; 

public class GettingObjectOriented { 
    public static void main(String[] args) { 
            Person john = new Person("John", "Doe"); 

            System.out.println( 
                    "Hello my name is " +            
                    john.fullName() + 
                    ". I am " + 
                    john.age(new GregorianCalendar()) + 
                    " years old."); 
    } 
} 
```

当我们运行它时，由于出生日期已设置为当前日期和时间，我们将看到`John Doe`现在是`0`岁，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/f0b459ab-c172-4e9d-b095-c0f2c08f85d3.png)

最后，我们可以让某人选择使用我们的构造函数之一，或者只需创建一个不做任何事情的类的实例，只需声明一个空的构造函数。然后，语法看起来就像我们之前参与的 John 的创建一样：

```java
public Person() 
{ 

} 
```

一般来说，我们不想这样做。如果我们有一个空的或默认的构造函数，我们想要做的是为我们的成员变量分配默认值，这样至少，我们仍然不会破坏我们的程序。因此，我们的默认构造函数可能会将空字符串和今天的日期分配给我们的`firstName`、`lastName`和`birthday`字段：

```java
public Person() 
    { 
        firstName = ""; 
        lastName = ""; 
        birthday = new GregorianCalendar(); 
    } 
```

然后，即使我们的程序员在创建 John 的字段后没有正确地为它们分配值，这些字段中仍然会有一些有效的值，以保护我们免受在运行以下程序时实际抛出错误的影响：

```java
package gettingobjectoriented; 

import java.util.*; 

public class GettingObjectOriented { 
    public static void main(String[] args) { 
            Person john = new Person(); 

            System.out.println( 
                    "Hello my name is " +            
                    john.fullName() + 
                    ". I am " + 
                    john.age(new GregorianCalendar()) + 
                    " years old."); 
    } 
} 
```

以下是前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/1d692259-00c3-473d-b8f1-3f01ff311b19.png)

这就是构造函数的要点，它是另一个帮助我们保护和使我们已经编写的代码更加健壮的工具。

# 总结

在本章中，我们看到了如何创建类和对象，以及如何创建成员变量和函数，这将使我们的代码变得不那么复杂。您还学习了关于创建分配给类的构造函数和构造函数类型的知识。


# 第七章：更多面向对象的 Java

在本章中，我们将通过创建超类和子类，理解它们之间的“is-a”关系，使用覆盖、数据结构、抽象方法和受保护方法等概念，来探讨 Java 中的继承。

我们将详细介绍以下概念：

+   继承

+   抽象

# 继承

与其从一个高层描述开始，我认为最好的方法是我们直接解决一个问题。

为了让我们开始，我创建了一个基本的 Java 程序，我们可以从给定的代码文件中访问。在这个程序中，我们声明了两个 Java 类：一个`Book`类和一个`Poem`类。`Book`和`Poem`类都存储了许多属性；例如，Book 可以有一个标题，一个作者，一个出版商和一个流派。它将所有这些属性作为构造函数输入，并提供一个`public`方法；我们可以在我们的主程序中使用`Print`方法来打印出我们创建的任何书籍的信息。

诗歌方法做的事情非常相似。它有一些属性和一个`Print`方法，我们通过它的构造函数设置它的属性。我匆匆忙忙地写了一个利用`Book`和`Poem`类的主函数。这个函数创建了一本新书和一首新诗，然后将它们打印出来：

```java
package inheritance;
public class Inheritance {
    public static void main(String[] args) {
        Book a = new Book(
                "The Lord Of The Rings", 
                "J.R.R. Tolkein",
                "George Allen and Unwin", 
                "Fantasy");
        Poem b = new Poem(
                "The Iliad",
                "Homer",
                "Dactylic Hexameter");

        a.Print();
        b.Print();
    }
}
```

前面的程序运行良好，但比必要的要复杂得多。

如果我们一起看看我们的`Book`和`Poem`类，并只看它们的成员变量，我们会发现`Book`和`Poem`都共享两个成员变量，即`title`和`author`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/b9086a15-f8b6-4599-808e-fdf716624758.png)

他们对成员变量所采取的操作，即将它们打印到屏幕上，都是以非常相似的方式在两个类中执行和实现的：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/4816972c-9adc-4bb7-91d4-3ca04ae260cd.png)

`Book`和`Poem`从一个共同的类继承是一个好迹象。当我们将书籍和诗歌视为它们所代表的物体时，我们很容易看到这一点。我们可以说书籍和诗歌都是文学形式。

# 创建一个超类

一旦我们得出结论，即书籍和诗歌共享某些基本属性，所有文学作品的属性，我们就可以开始将这些类分解为组成部分。例如，我们的`Book`类有两个真实变量。它有一个`title`变量和一个`author`变量，这些是我们与所有文学作品相关联的属性。它还有一个`publisher`变量和一个`genre`变量，这些可能不仅仅是书籍独有的，我们也不一定认为所有形式的文学作品都具有这些属性。那么我们如何利用这些知识呢？嗯，我们可以构建我们的`Book`和`Poem`类，使它们在基本层面上共享它们作为文学作品的本质。但是，要实现这一点，我们首先需要教会我们的程序什么是一部文学作品。以下是一个逐步的过程：

1.  我们将创建一个全新的类，并将其命名为`Literature`。

1.  我们将为这个类分配我们迄今为止声明的文学作品共享的属性。在我们的情况下，书籍和诗歌已经被声明为作品，具有共享的标题和作者。将所有文学作品都具有标题和作者是有一定逻辑意义的：

```java
package inheritance;
public class Literature {
    protected String title;
    protected String author;
```

1.  从这里开始，我们将像处理任何其他类一样完善我们的`Literature`类。我们将给它一个构造函数；在这种情况下，我们的构造函数将接受两个变量：`title`和`author`。然后，我们将它们分配给字段，就像我们对`Poem`和`Book`类所做的那样：

```java
package inheritance;
public class Literature {
  protected String title;
  protected String author;

  public Literature(String title, String author)
  {
     this.title = title;
     this.author = author;
   }
```

1.  在这个过程中，让我们给`Literature`一个类似的`Print`方法，就像我们为`Book`和`Poem`类分配的那样：

```java
public void Print()
{
   System.out.println(title);
   System.out.println("\tWritten By: " + author);
 }
```

现在，如果我们愿意，我们可以去我们的`main`方法，并声明一个`Literature`类的对象，但这不是重点。这不是我们创建`Literature`类的原因。相反，我们的目标是利用这个`Literature`类作为一个基础，我们将在其上声明更多特定类型的文学作品，比如诗歌或书籍。为了利用我们的`Literature`类，让我们看看它如何适用于现有的`Poem`类。

# 是一个关系

我们的`Literature`类包含了管理文学作品标题和作者的声明和所有功能。如果我们让 Java 知道`Poem`和`Literature`之间存在继承关系，我们应该能够删除以下`Poem`类的标题和作者的所有真实引用：

```java
package inheritance;
public class Poem extends Literature{
    private String title;
    private String author;
    private String style;
```

首先，让我们谈谈我们修改过的`Poem`类的声明。当我们说一个类扩展另一个类时，我们是在说它们之间存在一个是关系，以至于我可以逻辑地说出这样的陈述：“一首诗是一种文学作品。”更多的是 Java 术语，我们是在说`Poem`子类扩展或继承自`Literature`类。这意味着当我们创建一个`Poem`对象时，它将拥有它扩展的类的所有成员和功能：

```java
package inheritance;
public class Poem extends Literature {
    private String style;

    public Poem(String title, String author, String style)
```

在我们的情况下，其中两个成员是`title`和`author`。`Literature`类声明了这些成员，并且在整个类的功能中很好地管理它们。因此，我们可以从我们的`Poem`类中删除这些成员，我们仍然可以在`Poem`类的方法中访问它们。这是因为`Poem`类只是从`Literature`继承了它的声明。但是，我们需要进行轻微修改，以使`Poem`类按预期工作。当我们构造从另一个类继承的类的对象时，默认情况下，子类的构造函数将首先调用超类的构造函数：

```java
package inheritance;
public class Literature {
    protected String title;
    protected String author;

    public Literature(String title, String author)
    {
         this.title = title;
         this.author = author;
    }
```

这让 Java 感到困惑，因为我们现在设置的是`Poem`构造函数接受三个变量作为输入，而`Literature`构造函数只期望两个。为了解决这个问题，在`Poem`构造函数中显式调用`Literature`构造函数，使用以下步骤：

1.  当我们在子类中时，我们可以使用`super`关键字调用我们超类的方法。因此，在这种情况下，我们将通过简单地调用`super`构造函数，或者`Literature`构造函数来开始我们的`Poem`构造函数，并向它传递我们希望它知道的属性：

```java
public Poem(String title, String author, String style)
{
     super(title, author);
     this.style = style;
 }
```

1.  我们可以在我们的`Print`方法中做类似的事情，因为我们的`Literature`类，我们的超类，已经知道如何打印标题和作者。`Poem`类没有实现这个功能是没有理由的：

```java
 public void Print()
 {
      super.Print();
      System.out.println("\tIn The Style Of: " + style);
 }
```

如果我们开始通过调用`super.Print`来开始`Print`方法，而不是在前面的截图中显示的原始显式打印行，我们将从我们的`Print`方法中获得相同的行为。现在，当`Poem`的`Print`方法运行时，它将首先调用超类的，也就是`Literature.java`类的`Print`方法。最后，它将打印出`Poem`类的风格，这种风格并不适用于所有文学作品。

虽然我们的`Poem`构造函数和`Literature`构造函数具有不同的名称，甚至不同的输入样式，但`Poem`和`Literature`之间共享的两个`Print`方法是完全相同的。我们稍后会详细讨论这一点，但现在你应该知道我们在这里使用了一种叫做**覆盖**的技术。

# 覆盖

当我们声明一个子类具有与其超类方法相同的方法时，我们已经覆盖了超类方法。当我们这样做时，最好使用 Java 的`Override`指示符：

```java
@Override public void Print()
```

这是对未来编码人员和我们编译套件的一些更深奥的元素的一个指示，即给定在前面的截图中的方法下隐藏了一个方法。当我们实际运行我们的代码时，Java 会优先考虑方法的最低或子类版本。

所以让我们看看我们是否成功声明了我们的`Poem`和`Literature`关系。让我们回到我们程序的`Inheritence.java`类的`main`方法，看看这个程序的诗歌部分是否像以前一样执行：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/a8018c55-7173-4c5e-aa28-0bf9b697cc82.png)

当我们运行这个程序时，我们得到了与之前完全相同的输出，这表明我们已经以合理的方式设置了我们的`Poem`类从`Literature`继承。

现在我们可以跳到我们的`Book`类。我们将按照以下步骤将其设置为`Book`和`Literature`类之间的 is-a 关系：

1.  首先，我们将声明`Book`扩展`Literature`类；然后，我们将在我们的`Book`类中删除对标题和作者的引用，因为现在`Literature`类，即超类，将负责这一点：

```java
        package inheritance;
        public class Book extends Literature{
        private String publisher;
        private String genre;
```

1.  与`Poem`类一样，我们需要显式调用`Literature`类的构造函数，并将`title`和`author`传递给它：

```java
        public Book(String title, String author, String publisher, String
        genre)
        {
             super(title, author);
             this.publisher = publisher;
             this.genre = genre;
         }
```

1.  然后，我们可以利用我们的超类的`Print`方法来简化我们的`Book`类的打印：

```java
        @Override public void Print()
        {
             super.Print();
             System.out.println("\tPublished By: " + publisher);
             System.out.println("\tIs A: " + genre);
```

1.  再次，让我们跳回到我们的`main`方法并运行它，以确保我们已经成功完成了这个任务！[](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/269c7dd3-0d67-4a9f-99cd-9bdae0783358.png)

我们成功了：“指环王”的输出，就像我们以前看到的那样。在风格上，这个改变真的很棒。通过添加`Literature`类，然后对其进行子类化以创建`Book`和`Poem`类，我们使得我们的`Book`和`Poem`类更加简洁，更容易让程序员理解发生了什么。

然而，这种改变不仅仅是风格上的。通过声明`Book`和`Poem`类继承自`Literature`类的 is-a 关系，我们给自己带来了实际上以前没有的功能。让我们看看这个功能。如果我们回到我们的`main`方法，假设我们不是处理单个`Book`和`Poem`类，而是处理一个需要存储在某种数据结构中的庞大网络。使用我们最初的实现，这将是一个真正的挑战。

# 数据结构

没有一个易于访问的数据结构可以愉快地存储书籍和诗歌。我们可能需要使用两种数据结构或打破强类型，这正是 Java 的全部意义所在：

```java
Book[] books = new Book[5];
```

然而，通过我们的新实现，`Book`和`Poem`都继承自`Literature`，我们可以将它们存储在相同的数据结构中。这是因为继承是一种 is-a 关系，这意味着一旦我们从某物继承了，我们可以宣称书是文学，诗歌也是文学。如果这是真的，那么`Literature`对象的数组应该能够在其中存储`Book`和`Poem`。让我们按照以下步骤来说明这一点：

1.  创建一个`Literature`对象的数组：

```java
 Literature[] lits = new Literature[5];
 lits[0] = a;
 lits[1] = b;
```

当我们构建这个项目时没有编译错误，这是一个非常好的迹象，表明我们正在做一些合法的事情。

1.  为了进行演示，让我们在这里扩展我们的数组，以包含书籍和诗歌的数量：

```java
 Literature[] lits = new Literature[5];
 lits[0] = a;
 lits[1] = b;
 lits[2] = a;
 lits[3] = b;
 lits[4] = a;
```

我们将修改我们的`main`方法，直接从数组中打印出来。现在，当我们像使用它们的超类对象一样使用我们的子类时，我们必须意识到我们现在是将它们作为该超类的对象引用。例如，当我们遍历并从我们的`Literature`数组中获取一个元素时，无论该元素是`Book`类，我们仍然无法访问诸如其`genre`字段之类的东西，即使这个字段是`public`：

```java
 Literature[] lits = new Literature[5];
 lits[0] = a;
 lits[1] = b;
 lits[2] = a;
 lits[3] = b;
 lits[4] = a;
 for(int i=0; i< lits.length; i++)
 {
      lits[i].Print(); 
 }
```

这是因为我们现在使用的`Literature`类作为一个对象（如前面的截图所示）没有`genre`成员变量。但我们可以调用超类中被子类重写的方法。

1.  我们可以在我们的`for`循环中调用`Literature`类的`Print`方法。Java 将优先考虑我们子类的`Print`方法：

```java
for(int i=0; i< lits.length; i++)
{
     lits[i].Print(); 
 }
```

这意味着，当我们运行这个程序时，我们仍然会得到我们归因于`Book`和`Poem`的特殊格式化输出，而不是我们存储在`Literature`类中的简化版本：

```java
public void Print()
{
     System.out.println(title);
     System.out.println("\tWritten By: " + author);
 }
```

# 抽象方法

我们有时会看到一些方法只存在于被子类重载。这些方法什么也不做，我们可以在超类（`Literature.java`）中使用`abstract`关键字标记它们，即`public abstract void Print()`。当然，如果一个类有声明为`abstract`的方法，这可能是一个好迹象，即这样的类的实例应该永远不会被显式创建。如果我们的`Literature`类的`Print`方法是抽象的，我们就不应该声明只是`Literature`的对象。我们应该只使用`Literature`的子类的对象。如果我们要走这条路，我们也应该将`Literature`声明为一个`abstract`类：

```java
package inheritance;
public abstract class Literature {
```

当然，如果我们这样做，我们就必须摆脱对`Literature`类的超级方法的引用，所以现在让我们撤销这些更改。

让我们看一下我们在最初构建这个程序时犯的一个小错误。在创建我们的 Literature 类时，我们声明了`title`和`author`为`public`成员变量。你可能知道，通常情况下，如果没有充分的理由，我们不会声明成员变量为 public。一旦宣布了，文学作品改变其作者并没有太多意义，所以`author`和`title`应该是`private`成员变量，它们在`Literature`类的构造函数中设置，其值不应该改变。不幸的是，如果我们对我们的 Literature 类进行这种更改，我们将限制我们的 Poem 和 Book 类的功能。

比如说，我们想要修改`Poem`类的`Print`函数，这样它就不必显式调用`Literature`类的`Print`函数了：

```java
@Override public void Print()
{
     System.out.println(title);
     System.out.println("\tWritten By: " + author);
     System.out.println("\tIn The Style Of: " + style);
 }
```

也许我们想要通过声明在这里创建一个`Poem`类来开始它：

```java
System.out.println("POEM: " + title);
```

不幸的是，因为我们已经将`title`和`author`私有化到`Literature`类中，即使`Poem`类是`Literature`的子类，也无法在其显式代码中访问这些成员变量。这有点烦人，似乎在`private`和`public`之间有一种保护设置，它对于类的子类来说是私有的。实际上，有一种保护设置可用。

# 受保护的方法

`protected`方法是受保护的保护设置。如果我们声明成员变量为`protected`，那么它意味着它们是私有的，除了类和它的子类之外，其他人都无法访问：

```java
package inheritance;
public class Literature {
    protected String title;
    protected String author;
```

只是为了让自己放心，我们在这里所做的一切都是合法的。让我们再次运行我们的程序，确保输出看起来不错，事实也是如此。之后，我们应该对继承有相当好的理解。我们可以开发很多系统，这些系统真正模拟它们的现实世界对应物，并且我们可以使用继承和小类编写非常优雅和功能性的代码，这些小类本身并不做太多复杂的事情。

# 抽象

在这一部分，我们将快速了解与 Java 中继承相关的一个重要概念。为了理解我们要讨论的内容，最好是从系统中的现有项目开始。让我们来看看代码文件中的代码。

到目前为止，我们已经做了以下工作：

+   我们程序的`main`方法创建了一个对象列表。这些对象要么是`Book`类型，要么是`Poem`类型，但我们将它们放在`Literature`对象的列表中，这让我们相信`Book`和`Poem`类必须继承或扩展`Literature`类。

+   一旦我们建立了这个数组，我们只需使用`for`循环迭代它，并在每个对象上调用这个`for`循环的`Print`方法。

+   在这一点上，我们处理的是`Literature`对象，而不是它们在最低级别的书籍或诗歌。这让我们相信`Literature`类本身必须实现一个`Print`方法；如果我们跳进类，我们会看到这确实是真的。

然而，如果我们运行我们的程序，我们很快就会看到书籍和诗歌以稍有不同的方式执行它们的`Print`方法，为每个类显示不同的信息。当我们查看`Book`和`Poem`类时，这一点得到了解释，它们确实扩展了`Literature`类，但每个类都覆盖了`Literature`类的`Print`方法，以提供自己的功能。这都很好，也是一个相当优雅的解决方案，但有一个有趣的案例我们应该看一看并讨论一下。因为`Literature`本身是一个类，我们完全可以声明一个新的`Literature`对象，就像我们可以为`Book`或`Poem`做的那样。`Literature`类的构造函数首先期望文学作品的`title`，然后是`author`。一旦我们创建了`Literature`类的新实例，我们可以将该实例放入我们的`Literature`类列表中，就像我们一直在做的`Book`和`Poem`类的实例一样：

```java
Literature l= new Literature("Java", "Zach");
Literature[] lits = new Literature[5];
lits[0] = a;
lits[1] = b;
lits[2] = l;
lits[3] = b;
lits[4] = a;
for(int i=0; i< lits.length; i++)
{
     lits[i].Print(); 
 }
```

当我们这样做并运行我们的程序时，我们将看到`Literature`类的`Print`方法被执行，我们创建的新`Literature`对象将显示在我们的书籍和诗歌列表旁边：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java-prog-bg/img/a451f7d1-909e-45b3-a3bc-52665ed6e47b.png)

那么问题在哪里呢？嗯，这取决于我们试图设计的软件的真正性质，这可能有很多道理，也可能没有。假设我们正在作为图书馆系统的一部分进行这项工作，只提供某人所谓的 Java 是由某个叫 Zach 的人写的这样的信息，而不告诉他们它是一本书还是一首诗或者我们决定与特定类型的文学相关联的任何其他信息。这可能根本没有用，而且绝对不应该这样做。

如果是这样的话，Java 为我们提供了一个可以用于继承目的的类创建系统，但我们将永远无法合法地单独实例化它们，就像我们以前做的那样。如果我们想标记一个类为那种类型，我们将称其为`abstract`类，并且在类的声明中，我们只需使用`abstract`关键字。

```java
public abstract class Literature {
```

一旦我们将一个类标记为`abstract`，实例化这个类就不再是一个合法的操作。乍一看，这是一件非常简单的事情，主要是一种“保护我们的代码免受自己和其他程序员的侵害”的交易，但这并不完全正确；它是正确的，但这并不是将一个类声明为`abstract`的唯一目的。

一旦我们告诉 Java，我们永远不能创建一个单独的`Literature`实例，只能使用`Literature`作为它们的超类的类，当设置`Literature`类时，我们就不再受到限制。因为我们声明`Literature`是一个抽象类，我们和 Java 都知道`Literature`永远不会单独实例化，只有当它是一个正在实例化的类的超类时才会实例化。在这种情况下，我们可以不需要大部分 Java 类必须具有的这个类的部分。例如，我们不需要为`Literature`实际声明构造函数。如果`Literature`是一个标准的 Java 类，Java 不会接受这一点，因为如果我们尝试实例化`Literature`，它将不知道该怎么做。将没有构造函数可供调用。但是因为`Literature`是抽象的，我们可以确信`Literature`的子类将有自己的构造函数。当然，如果我们做出这个改变，我们将不得不摆脱子类中对`Literature`构造函数的引用，也就是删除子类中的`super`方法。因此，这个改变肯定是有所取舍的。这需要更多的代码在我们的子类中，以减少我们的`Literature`超类中的代码。在这种特定情况下，这种权衡可能不值得，因为我们在`Book`和`Poem`构造函数之间重复了代码，但如果可以假定`Literature`子类的构造函数做的事情非常不同，不声明一个共同的基础构造函数就是有意义的。

因此，简而言之，当我们设计我们的程序或更大的解决方案时，我们应该将那些在架构目的上非常合理但永远不应该单独创建的类声明为`abstract`。有时，当某些常见的类功能，比如拥有构造函数，对于这个类来说根本就没有意义时，我们真的会知道我们遇到了这样的类。

# 摘要

在本章中，我们了解了面向对象编程的一些复杂性，通过精确地使用继承的概念，创建了一个称为超类和子类的东西，并在它们之间建立了“是一个”关系。我们还讨论了一些关键方面的用法，比如覆盖子类和超类、数据结构和`protected`方法。我们还详细了解了`abstract`方法的工作原理。

在下一章中，您将了解有用的 Java 类。
