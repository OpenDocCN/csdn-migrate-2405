# C# 面向对象编程实用指南（二）

> 原文：[`zh.annas-archive.org/md5/ADAC00B29224B3ED5BF1EE522FE998CB`](https://zh.annas-archive.org/md5/ADAC00B29224B3ED5BF1EE522FE998CB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：异常处理

让我们从两个词开始：异常和处理。在英语中，**exception**一词指的是不经常发生的异常情况。在编程中，异常一词有类似的含义，但与软件代码有关。根据它们的性质，计算机程序应该只执行我们指示它们执行的操作，当计算机不能或无法遵循我们的指示时，这被认为是异常。如果计算机程序无法遵循我们的指示，它在软件世界中被归类为异常。

**错误**是编程中经常使用的另一个词。重要的是我们要明白错误和异常不是同一回事。错误指的是软件甚至无法运行的情况。更具体地说，错误意味着编写的代码包含错误，这就是为什么编译器无法编译/构建代码。另一方面，异常是发生在运行时的事情。区分这两个概念的最简单方法是：如果代码无法编译/构建，那么你的代码中有错误。如果代码编译/构建了，但当你运行它时出现了一些异常行为，那么这就是一个异常。

**异常处理**意味着在运行程序时处理/控制/监督发生的异常。本章我们将探讨以下主题：

+   为什么我们需要在编程中处理异常

+   C#编程中的异常处理

+   异常处理的基础知识

+   `try`和`catch`

+   如果不处理异常会发生什么

+   多个`catch`块

+   `throw`关键字的用途

+   `finally`块的作用

+   异常类

+   一些常见的异常类

+   异常处理最佳实践

# 为什么我们需要在编程中处理异常

想象一下你已经写了一些代码。代码应该按照你的指示执行，对吧？但由于某种原因，软件无法执行你给出的命令。也许软件面临一些问题，使得它无法运行。

例如，假设您已经指示软件读取文件，收集数据并将其存储在数据库中。然而，软件无法在文件应该存在的位置找到文件。文件找不到的原因可能有很多：文件可能已被某人删除，或者可能已被移动到另一个位置。现在，你的软件会怎么做？它不够聪明以自动处理这种情况。如果软件对自己的工作不清楚，它会抛出异常。作为软件开发人员，我们有责任告诉软件在这种情况下该怎么做。

软件会通过传递消息告诉我们它被卡住了，无法解决这种情况。但它应该对我们说什么？“救命！救命！”不是一个合适的消息，这种消息不会让开发人员的生活变得更容易。我们需要更多关于情况的信息，以便我们可以指导计算机相应地工作。因此，.NET 框架创建了一些在编程中经常发生的非常常见的异常。如果软件面临的问题有预定义的异常，它会抛出该异常。例如，假设有一个程序试图将一个数字除以零。从数学上讲，这是不可能的，但计算机必须这样做，因为你已经指示它这样做。现在计算机陷入了大麻烦；它感到困惑和无助。它试图按照你的指示将数字除以零，但编译器会阻止它并说“向程序先生求助！”，这意味着“向你的主人抛出一个`DivideByZeroException`来寻求帮助”。程序将抛出一个`DivideByZeroException`，并期望程序员编写的一些代码来处理它。这就是我们实际上会知道我们需要在程序中处理哪些异常。这就是为什么我们在编程中需要异常。

# C#编程中的异常处理

.NET 框架和 C#编程语言已经开发了一些强大的方法来处理异常。`System.Exceptions`是.NET 中的一个类，在系统命名空间下具有一些功能，可以帮助您管理运行时发生的异常，并防止程序崩溃。如果您在代码中没有正确处理异常，您的软件将崩溃。这就是为什么异常处理在软件开发中非常重要。

现在，您可能想知道如何在代码中处理异常。异常是意外的事情。您如何知道在您的代码中会发生哪种异常并导致程序崩溃？这是一个很好的问题，我相信在设计语言时也会提出这个问题。这就是为什么他们为.NET 提出了一个解决方案，它创建了一个非常美妙的机制来处理异常。

# 异常处理的基础知识

C#中的异常处理主要通过四个关键字实现：`try`、`catch`、`throw`和`finally`。稍后，我们将详细讨论这些关键字。但是，为了让您对这些关键字的含义有一个基本的了解，让我们简要讨论一下：

+   `try`：当您不确定代码的预期行为或存在异常可能性时，应将该代码放入`try`块中。如果该块内部发生异常，`try`块将抛出异常。如果没有异常发生，`try`块将像普通代码块一样。`try`块实际上是设计用来抛出异常的，这是它的主要任务。

+   `catch`：当捕获到异常时，将执行`catch`块。`try`块抛出的异常将由接下来的`catch`块处理。对于`try`块可以有多个`catch`块。每个`catch`块可以专门处理特定的异常。因此，我们应该为不同类型的异常编写不同的`catch`块。

+   `throw`：当您希望手动抛出异常时使用。可能存在您希望控制特定情况的情况。

+   `finally`：这是一段代码，将被强制执行。不管`try`块是否抛出异常，`finally`块都将被执行。这主要用于编写一些在任何情况下都必须处理的任务。

# 尝试和捕获

`try`和`catch`关键字是 C#异常处理中最重要的两个关键字。如果您编写一个没有`catch`块的`try`块，那么它就没有任何意义，因为如果`try`块抛出异常而没有`catch`块来处理它，那么有什么好处呢？异常仍然未处理。`catch`块实际上依赖于`try`块。如果没有与之关联的`try`块，`catch`块就不能存在。让我们看一下如何编写`try`-`catch`块：

```cs
try 
{
  int a = 5 / 0; 
} 
catch(DivideByZeroException ex)
{
  Console.WriteLine(“You have divided by zero”);
}
```

我们也可以为`try`块有更多的`catch`块。让我们看一个例子：

```cs
try 
{
  int a = 5 / 0; 
} 
catch(DivideByZeroException ex)
{ 
  Console.WriteLine(“You have divided by zero”); 
} 
catch(Exception ex) 
{ 
  Console.WriteLine(“Normal exception”); 
}
```

# 如果不处理异常会发生什么？

异常真的很重要吗？在逻辑中存在大量复杂性时，处理它们是否值得花费时间？是的，它们非常重要。让我们探讨一下如果不处理异常会发生什么。当触发异常时，如果没有代码处理它，异常将传递到系统运行时。

此外，当系统运行时遇到异常时，它会终止程序。所以，现在您明白为什么您应该处理异常了。如果您未能这样做，您的应用程序可能会在运行中间崩溃。我相信您个人不喜欢在使用它们时程序崩溃，所以我们必须小心编写无异常的软件。让我们看一个例子，看看如果未处理异常会发生什么：

```cs
Using system;

class LearnException {
    public static void Main()
    {
        int[] a = {1,2,3,4};
        for (int i=0; i<10; i++)
        {
            Console.WriteLine(a[i]);
        }
    }
}
```

如果我们运行这段代码，那么前四次运行时，它将完美执行并打印出从一到四的一些数字。但之后，它将抛出`IndexOutOfRangeException`的异常，并且系统运行时将终止程序。

# 多个 catch 块

在一个`try`块中获得不同类型的异常是正常的。但是你该如何处理它们呢？您不应该使用通用异常来做这个。如果您抛出通用异常而不是抛出特定异常，您可能会错过有关异常的一些重要信息。因此，C#语言为`try`块引入了多个`catch`块。您可以指定一个`catch`块，它将被一个类型的异常调用，并且您可以创建其他`catch`块，每个后面都有不同的异常类型。当抛出特定异常时，只有那个特定的`catch`块将被执行，如果它有一个专门的`catch`块来处理这种类型的异常。让我们看一个例子：

```cs
using System;

class ManyCatchBlocks 
{     
    public static void Main()
    {
        try
        {
            var a = 5;
            var b = 0;
            Console.WriteLine("Here we will divide 5 by 0");
            var c = a/b;
        }
        catch(IndexOutOfRangeException ex)
        {
            Console.WriteLine("Index is out of range " + ex);
        }
        catch(DivideByZeroException ex)
        {
            Console.WriteLine("You have divided by zero, which is not correct!");
        }
    }
}
```

如果运行上述代码，您将看到只有第二个`catch`块被执行。如果您打开控制台窗口，您将看到以下行已被打印出来：

```cs
You have divided by zero, which is not correct!
```

因此，我们可以看到，如果有多个`catch`块，只有与抛出的异常类型匹配的特定`catch`块将被执行。

现在你可能会想，“你说我们不应该使用通用异常处理程序。但为什么呢？是的，我们可能会错过一些信息，但我的系统没有崩溃！这样做不是更好吗？”实际上，这个问题的答案并不直接。这可能因系统而异，但让我告诉你为什么有时候你希望系统崩溃。假设你有一个处理非常复杂和敏感数据的系统。当这样的系统发生异常时，允许客户继续使用软件可能非常危险。客户可能会对数据造成严重破坏，因为异常没有得到适当处理。但是，如果你认为即使出现未知异常，如果允许用户继续使用系统也不会有问题，你可以使用通用的`catch`块。现在让我告诉你如何做到这一点。如果你希望`catch`块捕获任何类型的异常，无论异常类型如何，那么你的`catch`块应该接受`Exception`类作为参数，如下面的代码所示：

```cs
using System;

namespace ExceptionCode
{
  class Program
  {
    static void Main(string[] args)
    {
      try
      {
        var a = 0;
        var b = 5;
        var c = b / a;
      }
      catch (IndexOutOfRangeException ex)
      {
        Console.WriteLine("Index out of range " + ex);
      }
      catch (Exception ex)
      {
        Console.WriteLine("I will catch you exception! You can't hide from me!" + ex);
      }

      Console.WriteLine("Hello");
      Console.ReadKey();
     }
   }
}
```

或者，您还可以向`catch`块传递一个`no`参数。这也将捕获每种类型的异常并执行主体中的代码。以下代码给出了一个示例：

```cs
using System;

namespace ExceptionCode
{
  class Program
  {
    static void Main(string[] args)
    {
      try
      {
        var a = 0;
        var b = 5;
        var c = b / a;
      }
      catch (IndexOutOfRangeException ex)
      {
        Console.WriteLine("Index out of range " + ex);
      }
      catch
      {
        Console.WriteLine("I will catch you exception! You can't hide from me!");
      }

      Console.WriteLine("Hello");
      Console.ReadKey();
     }
   }
}
```

但是，请记住，这必须是最后一个`catch`块，否则将会出现运行时错误。

# 使用 throw 关键字

有时，在您自己的程序中，您必须自己创建异常。不，不是为了报复用户，而是为了您的应用程序。有时，有些情况下，您需要抛出异常来绕过困难，记录一些东西，或者只是重定向软件的流程。不用担心：通过这样做，您不会成为坏人；实际上，您是在拯救程序免受麻烦的英雄。但是，您如何创建异常呢？为此，C#有一个名为`throw`的关键字。这个关键字将帮助您创建异常类型的实例并抛出它。让我给你一个`throw`关键字的例子：

```cs
using System;

namespace ExceptionCode
{
 class Program
 {
 public static void Main(string[] args)
 {
 try
 {
 Console.WriteLine("You are the boss!");
 throw new DivideByZeroException();
 }
 catch (IndexOutOfRangeException ex)
 {
 Console.WriteLine("Index out of range " + ex);
 }
 catch (DivideByZeroException ex)
 {
 Console.WriteLine("Divide by zero " + ex);
 }
 catch
 {
 Console.WriteLine("I will catch you exception! You can't hide from me!");
 }

 Console.WriteLine("See, i told you!");
 Console.ReadKey();
 }
 }
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/19a3ed57-7485-4785-872d-de991b0338f1.png)

您可以看到，如果运行上述代码，将执行`DivideByZeroException` `catch`块。

因此，如果你想抛出异常（因为你希望上层的`catch`块来处理它，例如），你只需抛出一个新的异常实例。这可以是任何类型的异常，包括系统异常或自定义异常。只需记住有一个`catch`块将处理它。

# finally 块是做什么的？

当我们说“最后”，我们指的是我们一直在等待的或者将要结束进程的东西。在异常处理中也是差不多的。`finally` 块是一段无论 `try` 或 `catch` 块中发生了什么都会执行的代码。无论抛出了什么类型的异常，或者是否被处理，`finally` 块都会执行。现在你可能会问，"*为什么我们需要* `finally` *块呢？如果程序中有任何异常，我们会用* `catch` *块来处理它！我们不能把代码写在* `catch` *块里而不是* `finally` *块里吗？*"

是的，你可以，但是如果抛出了异常而 `catch` 块没有被触发会发生什么？这意味着 `catch` 块内的代码将不会被执行。因此，`finally` 块很重要。无论是否有异常，`finally` 块都会运行。让我给你展示一个 `finally` 块的例子：

```cs
using System;

namespace ExceptionCode
{
 class Program
 {
 static void Main(string[] args)
 {
 try
 {
 int a = 0;
 int b = 5;
 int c = b / a;
 }
 catch (IndexOutOfRangeException ex)
 {
 Console.WriteLine("Index out of range " + ex);
 }
 catch (DivideByZeroException ex)
 {
 Console.WriteLine("Divide by zero " + ex);
 }
 catch
 {
 Console.WriteLine("I will catch you exception! You can't hide from me!");
 }
 finally
 {
 Console.WriteLine("I am the finally block i will run by hook or by crook!");
 }
 Console.ReadLine();
 }
 }
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/32173a85-0984-4cbd-acbb-cb9eb559c8e1.png)

`finally` 块的一个重要用例可能是在 `try` 块中打开数据库连接！你必须关闭它，否则该连接将一直保持打开状态，会占用大量资源。此外，数据库可以建立的连接数量是有限的，所以如果你打开了一个连接却没有关闭它，那么这个连接字符串就浪费了。最佳实践是在完成与连接的工作后立即关闭连接。

`finally` 块在这里发挥了最好的作用。不管在 `try` 块中发生了什么，`finally` 块都会关闭连接，如下面的代码所示：

```cs
using System;

namespace ExceptionCode
{
  class Program
  {
    static void Main(string[] args)
    {
      try
      {
        // Step 1: Established database connection

        // Step 2: Do some activity in database
      }
      catch (IndexOutOfRangeException ex)
      {
        // Handle IndexOutOfRangeExceptions here
      }
      catch (DivideByZeroException ex)
      {
        // Handle DivideByZeroException here
      }
      catch
      {
        // Handle All other exception here
      }
      finally
      {
        // Close the database connection
      }
    }
  }
}
```

在这里，我们在 `try` 块中执行了两个主要任务。首先，我们打开了数据库连接，其次，我们在数据库中执行了一些活动。现在，如果在执行任何这些任务时发生了异常，那么异常将被 `catch` 块处理。最后，`finally` 块将关闭数据库连接。

`finally` 块不是处理异常必须要有的东西，但如果需要的话，应该使用它。

# 异常类

`exception` 简单来说就是 C# 中的一个类。它有一些属性和方法。最常用的四个属性如下：

| **属性** | **描述** |
| --- | --- |
| `Message` | 这包含了异常的内容。 |
| `StackTrace` | 这包含了方法调用堆栈信息。 |
| `TargetSite` | 这提供了一个包含发生异常的方法的对象。 |
| `InnerException` | 这提供了引起异常的异常实例。 |

异常类的属性和方法

这个类中最受欢迎的方法之一是 `ToString()`。这个方法返回一个包含异常信息的字符串。当以字符串格式表示时，异常更容易阅读和理解。

让我们看一个使用这些属性和方法的例子：

```cs
using System;

namespace ExceptionCode
{
 class Program
 {
 static void Main(string[] args)
 {
 try
 {
 var a = 0;
 var b = 5;
 var c = b / a;
 }
 catch (DivideByZeroException ex)
 {
 Console.WriteLine("Message:");
 Console.WriteLine(ex.Message);
 Console.WriteLine("Stack Trace:");
 Console.WriteLine(ex.StackTrace);
 Console.WriteLine("String:");
 Console.WriteLine(ex.ToString());
 }

 Console.ReadKey();
 }
 }
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/9295d985-106f-47ac-9530-b2818991d2b0.png)

在这里，我们可以看到异常的 `message` 属性包含了信息 `Attempted to divide by zero`。此外，`ToString()` 方法提供了大量关于异常的信息。这些属性和方法在处理程序中处理异常时会帮助你很多。

# 一些常见的异常类

.NET Framework 中有许多异常类可用。.NET Framework 团队创建了这些类来简化开发人员的生活。.NET Framework 提供了关于异常的具体信息。以下是一些常见的异常类：

| **异常类** | **描述** |
| --- | --- |
| `DivideByZeroException` | 当任何数字被零除时，会抛出此异常。 |
| `IndexOutOfRangeException` | 当应用程序尝试使用不存在的数组索引时，会抛出此异常。 |
| `InvalidCastException` | 当尝试执行无效转换时，会引发此异常。 |
| `NullReferenceException` | 当尝试使用或访问空引用类型时，会引发此异常。 |

.NET 框架的不同异常类

让我们看一个示例，其中使用了这些异常类中的一个。在这个例子中，我们使用了`IndexOutOfRange`异常类：

```cs
using System;

namespace ExceptionCode
{
 class Program
 {
 static void Main(string[] args)
 {
 int[] a = new int[] {1,2,3};

 try
 {
 Console.WriteLine(a[5]);
 }
 catch (IndexOutOfRangeException ex)
 {
 Console.WriteLine("Message:");
 Console.WriteLine(ex.Message);
 Console.WriteLine("Stack Trace:");
 Console.WriteLine(ex.StackTrace);
 Console.WriteLine("String:");
 Console.WriteLine(ex.ToString());
 }

 Console.ReadKey();
 }
 }
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/2ae2fd64-2e62-4365-aa7c-23b2e7104ae7.png)

# 用户定义的异常

有时，您可能会遇到一种情况，认为预定义的异常不满足您的条件。在这种情况下，您可能希望有一种方法来创建自己的异常类并使用它们。值得庆幸的是，在 C#中，实际上有一种机制可以创建自定义异常，并且可以编写适用于该类型异常的任何消息。让我们看一个创建和使用自定义异常的示例：

```cs
using System;

namespace ExceptionCode
{

 class HelloException : Exception
 {
 public HelloException() { }
 public HelloException(string message) : base(message) { }
 public HelloException(string message, Exception inner) : base(message, inner) { }
 }

 class Program
 {
 static void Main(string[] args)
 {
 try
 {
 throw new HelloException("Hello is an exception!");
 }
 catch (HelloException ex)
 {
 Console.WriteLine("Exception Message:");
 Console.WriteLine(ex.Message);
 }

 Console.ReadKey();
 }
 }
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/b38a2822-1170-4403-8bfe-b6e93aea6a89.png)

因此，我们可以从上面的示例中看到，您只需创建一个将扩展`Exception`类的类。该类应该有三个构造函数：一个不应该带任何参数，一个应该带一个字符串并将其传递给基类，一个应该带一个字符串和一个异常并将其传递给基类。

使用自定义异常就像使用.NET Framework 提供的任何其他内置异常一样。

# 异常筛选器

在撰写本文时，异常筛选器功能并不是很古老——它是在 C# 6 中引入的。其主要好处是可以在一个块中捕获更具体的异常。让我们看一个例子：

```cs
using System;

namespace ExceptionCode
{
 class Program
 {
 static void Main(string[] args)
 {

 int[] a = new int[] {1,2,3};

 try
 {
 Console.WriteLine(a[5]);
 }
 catch (IndexOutOfRangeException ex) when (ex.Message == "Test Message")
 {
 Console.WriteLine("Message:");
 Console.WriteLine("Test Message");
 }
 catch (IndexOutOfRangeException ex) when (ex.Message == "Index was outside the bounds of the array.")
 {
 Console.WriteLine("Message:");
 Console.WriteLine(ex.Message);
 Console.WriteLine("Stack Trace:");
 Console.WriteLine(ex.StackTrace);
 Console.WriteLine("String:");
 Console.WriteLine(ex.ToString());
 }

 Console.ReadKey();
 }
 }
}
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/0742e721-1391-4da1-89eb-707e2c898206.png)

要筛选异常，必须在`catch`声明行的旁边使用`when`关键字。因此，当抛出任何异常时，它将检查异常的类型，然后检查`when`关键字之后提供的条件。在我们的示例中，异常类型是`IndexOutOfRangeException`，条件是`ex.Message == "Index was outside the bounds of the array."`。我们可以看到，当代码运行时，只有满足所有条件的特定`catch`块被执行。

# 异常处理最佳实践

正如您所看到的，处理异常有不同的方式：有时可以抛出异常，有时可以使用`finally`块，有时可以使用多个`catch`块。因此，如果您对异常处理没有足够的经验，可能会在开始时感到困惑。但幸运的是，C#社区为异常处理提供了一些最佳实践。让我们看看其中一些：

+   使用`finally`块关闭/清理可能会在将来引起问题的依赖资源。

+   捕获特定异常并正确处理。如果需要，可以使用多个`catch`块。

+   如有需要，创建并使用自定义异常。

+   尽快处理异常。

+   如果可以使用特定处理程序处理异常，则不要使用通用异常处理程序。

+   异常消息应该非常清晰。

# 总结

我们都梦想着一个没有错误或意外情况的完美世界，但现实中这是不可能的。软件开发也不免于错误和异常。软件开发人员不希望他们的软件崩溃，但意外异常时有发生。因此，处理这些异常对于开发出色的软件是必要的。在本章中，我们熟悉了软件开发中异常的概念。我们还学习了如何处理异常，为什么需要处理异常，如何创建自定义异常以及许多其他重要主题。在应用程序中实施异常处理时，请尽量遵循最佳实践，以确保应用程序运行顺畅。


# 第六章：事件和委托

事件和委托可能看起来像复杂的编程主题，但实际上并不是。在本章中，我们将首先通过分析它们各自名称的含义来学习这些概念。然后我们将把这些词的一般含义与编程联系起来。在本章中，我们将看到很多示例代码，这将帮助我们轻松理解这些概念。在我们深入讨论之前，让我们先看一下本章将涵盖的主题：

+   如何创建和使用委托

+   方法组转换

+   多播

+   协变和逆变

+   事件和多播事件

+   .NET 事件指南

# 什么是委托？

**委托**是一个代理，一个替代者，或者某人的代表。例如，我们可能在报纸上看到另一个国家的代表来到我们国家会见高级官员。这个人是一个代表，因为他们来到我们国家代表他们自己的国家。他们可能是总统、总理或者那个国家的任何其他高级官员的代表。让我们想象一下，这个代表是总统的代表。也许总统因某种原因无法亲自出席这次会议，这就是为什么派遣了一个代表代表他们。这个代表将会做总统应该在这次旅行中做的工作，并代表总统做出决定。代表不是一个固定的个人；可以是总统选择的任何合格的人。

委托的概念在软件开发中是类似的。我们可以有一个功能，其中一个方法不执行它被要求执行的实际工作，而是调用另一个方法来执行那项工作。此外，在编程中，那个不执行实际工作而是将其传递给另一个方法的方法被称为**委托**。因此，委托实际上将持有一个方法的引用。当调用委托时，引用的方法将被调用和执行。

现在，你可能会问，*"如果委托要调用另一个方法，为什么我不直接调用这个方法呢？"* 好吧，我们这样做是因为如果你直接调用方法，你会失去灵活性，使你的代码耦合在一起。你在代码中硬编码了方法名，所以每当那行代码运行时，该方法就会被执行。然而，使用委托，你可以在运行时决定调用哪个方法，而不是在编译时。

# 如何创建和使用委托

要创建一个委托，我们需要使用`delegate`关键字。让我向你展示如何以一般形式声明一个委托：

```cs
delegate returnType delegateName(parameters)
```

现在让我给你展示一些真实的示例代码：

```cs
using System;

namespace Delegate1
{
  delegate int MathFunc(int a, int b);

  class Program
  {
    static void Main(string[] args)
    {
      MathFunc mf = new MathFunc(add);

      Console.WriteLine("add");
      Console.WriteLine(mf(4, 5));

      mf = new MathFunc(sub);

      Console.WriteLine("sub");
      Console.WriteLine(mf(4, 5));

      Console.ReadKey();
    }

    public static int add(int a, int b)
    {
      return a + b;
    }

    public static int sub(int a, int b)
    {
      return (a > b) ? (a - b) : (b - a);
    }
  }
}
```

上述代码的输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/ec78bb93-f19d-4cd4-9c4b-3234205bb9c7.png)

现在让我们讨论上述代码。在命名空间内的顶部，我们可以看到委托的声明，如下所示：

```cs
delegate int MathFunc(int a, int b);
```

我们使用了`delegate`关键字来告诉编译器我们在声明一个`delegate`。然后我们将返回类型设置为`int`，并命名了委托为`MathFunc`。我们还在这个委托中传递了两个`int`类型的参数。

之后，`program`类开始运行，在该类中，除了主方法外，我们还有两个方法。一个是`add`，另一个是`sub`。如果你仔细观察这些方法，你会发现它们与委托具有相同的签名。这是故意这样做的，因为当方法具有与委托相同的签名时，方法可以使用`delegate`。

现在，如果我们看一下主方法，我们会发现以下有趣的代码：

```cs
MathFunc mf = new MathFunc(add);
```

在主方法的第一行，我们创建了一个代理对象。在这样做时，我们将`add`方法传递给构造函数。这是必需的，因为你需要传递一个你想要使用代理的方法。然后我们可以看到，当我们调用代理`mf(4,5)`时，它返回`9`。这意味着它实际上调用了`add`方法。之后，我们将`sub`分配给`delegate`。在调用`mf(4,5)`时，这次我们得到了`1`。这意味着调用了`sub`方法。通过这种方式，一个`delegate`可以用于具有相同签名的许多方法。

# 方法组转换

在上一个例子中，我们看到了如何创建一个代理对象并在构造函数中传递方法名。现在我们将看另一种实现相同目的的方法，但更简单。这被称为**方法组转换**。在这里，你不需要初始化`delegate`对象，而是可以直接将方法分配给它。让我给你举个例子：

```cs
using System;

namespace Delegate1
{
 delegate int MathFunc(int a, int b);

 class Program
 {
 static void Main(string[] args)
 {
 MathFunc mf = add;

 Console.WriteLine("add");
 Console.WriteLine(mf(4, 5));

 mf = sub;

 Console.WriteLine("sub");
 Console.WriteLine(mf(4, 5));
 Console.ReadKey();
 }

 public static int add(int a, int b)
 {
 return a + b;
 }

 public static int sub(int a, int b)
 {
 return (a > b) ? (a - b) : (b - a);
 }
 }
}
```

在这里，我们可以看到，我们直接将方法分配给它，而不是在构造函数中传递方法名。这是在 C#中分配代理的一种快速方法。

# 使用静态和实例方法作为代理

在之前的例子中，我们在代理中使用了静态方法。然而，你也可以在代理中使用实例方法。让我们看一个例子：

```cs
using System;

namespace Delegate1
{
  delegate int MathFunc(int a, int b);

  class Program
  {
    static void Main(string[] args)
    {
      MyMath mc = new MyMath();

      MathFunc mf = mc.add;

      Console.WriteLine("add");
      Console.WriteLine(mf(4, 5));

      mf = mc.sub;

      Console.WriteLine("sub");
      Console.WriteLine(mf(4, 5));

      Console.ReadKey();
    }
  }
  class MyMath
  {
    public int add(int a, int b)
    {
      return a + b;
    }

    public int sub(int a, int b)
    {
      return (a > b) ? (a - b) : (b - a);
    }
  }
}
```

在上面的例子中，我们可以看到我们在`MyMath`类下有实例方法。要在代理中使用这些方法，我们首先必须创建该类的对象，然后简单地使用对象实例将方法分配给代理。

# 多播

**多播**是代理的一个很好的特性。通过多播，你可以将多个方法分配给一个代理。当执行该代理时，它依次运行所有被分配的方法。使用`+`或`+=`运算符，你可以向代理添加方法。还有一种方法可以从代理中删除添加的方法。要做到这一点，你必须使用`-`或`-=`运算符。让我们看一个例子来清楚地理解多播是什么：

```cs
using System;

namespace MyDelegate
{
  delegate void MathFunc(ref int a);

  class Program
  {
    static void Main(string[] args)
    {
      MathFunc mf;
      int number = 10;
      MathFunc myAdd = MyMath.add5;
      MathFunc mySub = MyMath.sub3;

      mf = myAdd;
      mf += mySub;

      mf(ref number);

      Console.WriteLine($"Final number: {number}");

      Console.ReadKey();
    }
  }

  class MyMath
  {
    public static void add5(ref int a)
    {
      a = a + 5;
      Console.WriteLine($"After adding 5 the answer is {a}");
    }

    public static void sub3(ref int a)
    {
      a = a - 3;
      Console.WriteLine($"After subtracting 3 the answer is {a}");
    }
  }
}
```

上面的代码将给出以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/9e13be43-8af9-4cc0-84fb-356853c3a9e3.png)

在这里，我们可以看到我们的代理依次执行了两种方法。我们必须记住它的工作原理就像一个队列，所以你添加的第一个方法将是第一个执行的方法。现在让我们看看如何从代理中删除一个方法：

```cs
using System;

namespace MyDelegate
{
  delegate void MathFunc(ref int a);

  class Program
  {
    static void Main(string[] args)
    {
      MathFunc mf;
      MathFunc myAdd = MyMath.add5;
      MathFunc mySub = MyMath.sub3;
      MathFunc myMul = MyMath.mul10;

      mf = myAdd;
      mf += mySub;
      int number = 10;

      mf(ref number);

      mf -= mySub;
      mf += myMul;
      number = 10;

      mf(ref number);

      Console.WriteLine($"Final number: {number}");

      Console.ReadKey();
    }
  }

  class MyMath
  {
    public static void add5(ref int a)
    {
      a = a + 5;
      Console.WriteLine($"After adding 5 the answer is {a}");
    }

    public static void sub3(ref int a)
    {
      a = a - 3;
      Console.WriteLine($"After subtracting 3 the answer is {a}");
    }

    public static void mul10(ref int a)
    {
      a = a * 10;
      Console.WriteLine($"After multiplying 10 the answer is {a}");
    }
  }
}
```

上面的代码将给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/375ab662-d4d2-4e43-98e7-77e000cf9870.png)

在这里，我们首先向代理添加了两种方法。然后，我们删除了`sub3`方法并添加了`mul10`方法。在进行了所有这些更改后，当我们执行了代理时，我们看到`5`被加到了数字上，然后`10`被乘以数字。没有发生减法。

# 协变和逆变

有两个重要的代理特性。到目前为止，我们学到的是通常情况下，要向代理注册一个方法，该方法必须与代理的签名匹配。这意味着方法和代理的返回类型和参数必须相同。然而，通过协变和逆变的概念，你实际上可以向代理注册不具有相同返回类型或参数的方法。然后在调用时，代理将能够执行它们。

**协变**是指当你将一个返回类型是委托返回类型的派生类型的方法分配给委托时。例如，如果类`B`是从类`A`派生出来的，并且如果委托返回类`A`，那么可以向委托注册返回类`B`的方法。让我们看看以下代码中的例子：

```cs
using System;

namespace EventsAndDelegates
{
 public delegate A DoSomething();

 public class A
 {
 public int value { get; set; }
 }

 public class B : A {}

 public class Program
 {
 public static A WorkA()
 {
 A a = new A();
 a.value = 1;
 return a;
 }

 public static B WorkB()
 {
 B b = new B();
 b.value = 2;
 return b;
 }

 public static void Main(string[] args)
 {
 A someA = new A();

 DoSomething something = WorkB;

 someA = something();

 Console.WriteLine("The value is " + someA.value);

 Console.ReadLine();
 }
 }
}
```

上面代码的输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/a25f3142-a1f1-4a9a-b26d-b33aa0902724.png)

另一方面，**逆变**是指当一个方法传递给委托时，该方法的参数与委托的参数不匹配。在这里，我们必须记住，方法的参数类型至少必须派生自委托的参数类型。让我们看一个逆变的例子：

```cs
using System;

namespace EventsAndDelegates
{
 public delegate int DoSomething(B b);

 public class A
 {
 public int value = 5;
 }

 public class B : A {}

 public class Program
 {
 public static int WorkA(A a)
 {
 Console.WriteLine("Method WorkA called: ");
 return a.value * 5;
 }

 public static int WorkB(B b)
 {
 Console.WriteLine("Method WorkB called: ");
 return b.value * 10;
 }

 public static void Main(string[] args)
 {
 B someB = new B();

 DoSomething something = WorkA;

 int result = something(someB);

 Console.WriteLine("The value is " + result);

 Console.ReadLine();
 }
 }
}
```

上面的代码将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/8c0d2d79-d593-41b5-acac-a4a38caeab8e.png)

在这里，我们可以看到委托以类型`B`作为参数。然而，当`WorkA`方法被注册为委托中的一个方法时，它并没有给出任何错误或警告，尽管`WorkA`方法的参数类型是`A`类型。它能够工作的原因是因为`B`类型是从`A`类型派生出来的。

# 事件

你可以将**事件**看作是在某些情况下执行的一种方法，并通知处理程序或委托有关该事件的发生。例如，当你订阅电子邮件时，你会收到来自网站的关于最新文章、博客帖子或新闻的电子邮件。这些电子邮件可以是每天、每周、每月、每年，或者根据你选择的其他指定时间段。这些电子邮件不是由人手动发送的，而是由自动系统/软件发送的。可以使用事件来开发这种自动电子邮件发送器。现在，你可能会想，为什么我需要一个事件来做这个，我不能通过普通方法发送电子邮件给订阅者吗？是的，你可以。但是，假设在不久的将来，你还想引入一个功能，即在移动应用程序上收到通知。你将不得不更改代码并添加该功能。几天后，如果你想进一步扩展你的系统并向特定订阅者发送短信，你又必须再次更改代码。不仅如此，如果你使用普通方法编写代码，那么你编写的代码将非常紧密耦合。你可以使用`event`来解决这类问题。你还可以创建不同的事件处理程序，并将这些事件处理程序分配给一个事件，这样，每当该事件被触发时，它将通知所有注册的处理程序来执行它们的工作。现在让我们看一个例子来使这一点更清晰：

```cs
using System;

namespace EventsAndDelegates
{
  public delegate void GetResult();

  public class ResultPublishEvent
  {
    public event GetResult PublishResult;

    public void PublishResultNow()
    {
      if (PublishResult != null)
      {
        Console.WriteLine("We are publishing the results now!");
        Console.WriteLine("");
        PublishResult();
      }
    }
  }

  public class EmailEventHandler
  {
    public void SendEmail()
    {
      Console.WriteLine("Results have been emailed successfully!");
    }
  }

  public class Program
  {
    public static void Main(string[] args)
    {
      ResultPublishEvent e = new ResultPublishEvent();

      EmailEventHandler email = new EmailEventHandler();

      e.PublishResult += email.SendEmail;
      e.PublishResultNow();

      Console.ReadLine();
    }
  }
}
```

上面代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/4c7feacb-1170-499c-b38e-72151467b6f4.png)

在上面的代码中，我们可以看到，当调用`PublishResultNow()`方法时，它基本上触发了`PublishResult`事件。此外，订阅了该事件的`SendMail()`方法被执行，并在控制台上打印出`Results have been emailed successfully!`。

# 多播事件

在事件中，你可以像在委托中一样进行多播。这意味着你可以注册多个事件处理程序（订阅事件的方法）到一个事件中，当事件被触发时，所有这些处理程序都会依次执行。要进行多播，你必须使用`+=`符号来注册事件处理程序到事件中。你也可以使用`-=`运算符从事件中移除事件处理程序。当应用多播时，首先注册的事件处理程序将首先执行，然后是第二个，依此类推。通过多播，你可以在应用程序中轻松扩展或减少事件处理程序而不需要做太多工作。让我们看一个多播的例子：

```cs
using System;

namespace EventsAndDelegates
{
 public delegate void GetResult();

 public class ResultPublishEvent
 {
 public event GetResult PublishResult;

 public void PublishResultNow()
 {
 if (PublishResult != null)
 {
 Console.WriteLine("");
 Console.WriteLine("We are publishing the results now!");
 Console.WriteLine("");
 PublishResult();
 }
 }
 }

 public class EmailEventHandler
 {
 public void SendEmail()
 {
 Console.WriteLine("Results have been emailed successfully!");
 }
 }

 public class SmsEventHandler
 {
 public void SmsSender()
 {
 Console.WriteLine("Results have been messaged successfully!");
 }
 }

 public class Program
 {
 public static void Main(string[] args)
 {
 ResultPublishEvent e = new ResultPublishEvent();

 EmailEventHandler email = new EmailEventHandler();
 SmsEventHandler sms = new SmsEventHandler();

 e.PublishResult += email.SendEmail;
 e.PublishResult += sms.SmsSender;

 e.PublishResultNow();

 e.PublishResult -= sms.SmsSender;

 e.PublishResultNow();

 Console.ReadLine();
 }
 }
}
```

上面代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/fd85efc4-6818-457e-ab15-3c69366339d0.png)

现在，如果我们分析上面的代码，我们可以看到我们创建了另一个类`SmsEventHandler`，这个类有一个名为`SmsSender`的方法，它的签名与我们的委托`GetResult`相同，如下面的代码所示：

```cs
public class SmsEventHandler
{
  public void SmsSender()
  {
    Console.WriteLine("Results have been messaged successfully!");
  }
}
```

然后，在主方法中，我们创建了这个`SmsEventHandler`类的一个实例，并将`SmsSender`方法注册到事件中，如下面的代码所示：

```cs
e.PublishResult += sms.SmsSender;
```

触发事件一次后，我们使用`-=`运算符从事件中移除`SmsSender`事件处理程序，如下所示：

```cs
e.PublishResult -= sms.SmsSender;
```

当我们再次触发事件时，可以在输出中看到只有电子邮件事件处理程序被执行。

# .NET 中的事件准则

为了更好的稳定性，.NET Framework 提供了一些在 C# 中使用事件的准则。并不是说你一定要遵循这些准则，但遵循这些准则肯定会使你的程序更加高效。现在让我们看看需要遵循哪些准则。

事件应该有以下两个参数：

+   生成事件的对象的引用

+   `EventArgs` 的类型将保存事件处理程序所需的其他重要信息

代码的一般形式应该如下：

```cs
void eventHandler(object sender, EventArgs e)
{
}
```

让我们看一个遵循这些准则的例子：

```cs
using System;

namespace EventsAndDelegates
{
  class MyEventArgs : EventArgs
  {
    public int number;
  }

  delegate void MyEventHandler(object sender, MyEventArgs e);

  class MyEvent
  {
    public static int counter = 0;

    public event MyEventHandler SomeEvent;

    public void GetSomeEvent()
    {
      MyEventArgs a = new MyEventArgs();

      if (SomeEvent != null)
      {
        a.number = counter++;
        SomeEvent(this, a);
      }
    }

  }

  class X
  {
    public void Handler(object sender, MyEventArgs e)
    {
      Console.WriteLine("Event number: " + e.number);
      Console.WriteLine("Source Object: " + sender);
      Console.WriteLine();
    }
  }

  public class Program
  {
    public static void Main(string[] args)
    {
      X x = new X();

      MyEvent myEvent = new MyEvent();

      myEvent.SomeEvent += x.Handler;

      myEvent.GetSomeEvent();
      myEvent.GetSomeEvent();

      Console.ReadLine();
    }
  }
}
```

上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/0eb0b9af-e892-43c3-ab91-1f574877789d.png)

如果我们分析上述代码，我们会看到我们使用 `EventArgs` 参数传递了计数器的值，使用 `object` 参数传递了对象的引用。

# 摘要

在本章中，我们学习了委托和事件。这些主题在软件开发中非常重要，因为它们提供了在特定场合自动化代码的功能。这些概念在 Web 开发领域都被广泛使用。

在下一章中，我们将学习 C# 中的泛型和集合。这些是 C# 编程语言非常有趣的特性，你可以使用它们在程序中编写通用的委托。


# 第七章：C#中的泛型

泛型是 C#编程语言中非常重要的一个主题。据我所知，很难找到任何不使用泛型的 C#编写的现代软件。

本章中我们将涵盖的主题如下：

+   什么是泛型？

+   我们为什么需要泛型？

+   泛型的不同约束

+   泛型方法

+   泛型中的协变和逆变

# 什么是泛型？

在 C#中，泛型用于创建不特定但通用的类、方法、结构和其他组件。这使我们能够为不同的原因使用通用组件。例如，如果您有一种通用的肥皂，您可以用它来进行任何类型的清洗。您可以用它来洗手，洗衣服，甚至洗脏碗。但是，如果您有一种特定类别的肥皂，比如洗衣粉，它只能用来洗衣服，而不能用来做其他事情。因此，泛型为我们的代码提供了一些额外的可重用性，这对于应用程序是有益的，因为会有更少的代码来执行类似的工作。泛型并不是新开发的；它们自 C# 2 以来就已经可用。因此，经过这么多年的使用，泛型已经成为程序员常用的工具。

让我们来看一个`Generic`类的例子：

```cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Chapter7
{
  class Price<T>
  {
    T ob;

    public Price(T o)
    {
      ob = o;
    }

    public void PrintType()
    {
      Console.WriteLine("The type is " + typeof(T));
    }

    public T GetPrice()
    {
      return ob;
    }
  }

  class Code_7_1
  {
    static void Main(string[] args)
    {
      Price<int> price = new Price<int>(55);

      price.PrintType();

      int a = price.GetPrice();

      Console.WriteLine("The price is " + a);

      Console.ReadKey();
    }
  }
}
```

前面代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/140f13d4-7a65-4ca8-aec5-3d936a425256.png)

如果您对泛型的语法完全不熟悉，您可能会对在`Price`类旁边看到的尖括号`<>`感到惊讶。您可能还想知道`<>`中的`T`是什么。这是 C#中泛型的语法。通过将`<>`放在类名旁边，我们告诉编译器这是一个泛型类。此外，`<>`中的`T`是一个类型参数。是的，我知道您在问：“'什么是类型参数？'”**类型参数**就像 C#编程中的任何其他参数一样，只是它传递的是类型而不是值或引用。现在，让我们分析前面的代码。

我们创建了一个泛型`Price`类。为了使它成为泛型，我们在类名旁边放置了`<T>`。这里，`T`是一个类型参数，但它并不是固定的，您可以使用任何东西来表示类型参数，而不一定非要使用`T`。但是，传统上使用`T`来表示类型参数。如果有更多的类型参数，会使用`V`和`E`。在使用两个或更多参数时，还有另一种常用的约定，即将参数命名为`TValue`和`TKey`，而不仅仅是`V`和`E`，这样做可以提高可读性。但是，正如您所看到的，我们在`Value`和`Key`之前加了`T`前缀，这是为了区分类型参数和一般参数。

在`Price<T>`类中，我们首先创建了一个名为`ob`的变量，它是`T`类型的：

```cs
T ob;
```

当我们运行前面的代码时，我们在类中传递的类型将是这个对象的类型。因此，我们可以说`T`是一个占位符，在运行时将被一些其他具体的 C#类型（`int`、`double`、`string`或任何其他复杂类型）替换。

在接下来的几行中，我们创建了一个构造函数：

```cs
public Price(T o)
{
    ob = o;
}
```

在构造函数中，我们传递了一个`T`类型的参数，然后将传递的参数`o`的值分配给局部变量`ob`。我们可以这样做是因为在构造函数中传递的参数也是`T`类型。

然后，我们创建了第二个方法：

```cs
public void PrintType()
{
    Console.WriteLine("The type is " + typeof(T));
}

public T GetPrice()
{
    return ob;
}
```

这里，第一个方法打印`T`的类型。这将有助于在运行程序时识别类型。另一个方法是返回局部变量`ob`。在这里，我们注意到我们从`GetPrice`方法中返回了`T`。

现在，如果我们专注于我们的主方法，我们会看到在第一行中我们正在用`int`作为类型参数实例化我们的泛型类`Price`，并将整数值`55`传递给构造函数：

```cs
Price<int> price = new Price<int>(55);
```

当我们这样做时，编译器将`Price`类中的每个`T`视为`int`。因此，局部参数`ob`将是`int`类型。当我们运行`PrintType`方法时，应该在屏幕上打印 System.Int32，当我们运行`GetPrice`方法时，应该返回一个`Int`类型的值。

现在，由于`Price`方法是泛型的，我们也可以将此`Price`方法用于字符串类型。为此，我们必须将类型参数设置为`string`。让我们在前面的例子中添加一些代码，这将创建一个处理字符串的`Price`对象：

```cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Chapter7
{
  class Price<T>
  {
    T ob;

    public Price(T o)
    {
      ob = o;
    }

    public void PrintType()
    {
      Console.WriteLine("The type is " + typeof(T));
    }

    public T GetPrice()
    {
      return ob;
    }
  }

  class Code_7_2
  {
    static void Main(string[] args)
    {
      Price<int> price = new Price<int>(55);

      price.PrintType();

      int a = price.GetPrice();

      Console.WriteLine("the price is " + a);

      Price<string> priceStr = new Price<string>("Hello People");

      priceStr.PrintType();

      string b = priceStr.GetPrice();

      Console.WriteLine("the string is " + b);

      Console.ReadKey();
    }
  }
}
```

上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/6dc6301a-d676-4bdc-8179-1c371c2e0321.png)

# 我们为什么需要泛型？

看到前面的例子后，您可能会想知道为什么我们需要泛型，当我们可以使用`object`类型时。`object`类型可以用于 C#中的任何类型，并且可以通过使用`object`类型实现前面的例子。是的，可以通过使用对象类型实现前面的例子，但不会有类型安全。相反，泛型确保了在代码执行时存在类型安全。

如果你和我一样，肯定想知道什么是类型安全。**类型安全**实际上是指在程序执行任何任务时保持类型安全或不可更改。这有助于减少运行时错误。

现在，让我们使用对象类型而不是泛型来编写前面的程序，看看泛型如何处理类型安全，而对象类型无法处理：

```cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Chapter7
{
  class Price
  {
    object ob;

    public Price(object o)
    {
      ob = o;
    }

    public void PrintType()
    {
      Console.WriteLine("The type is " + ob.GetType());
    }

    public object GetPrice()
    {
      return ob;
    }
  }

  class Code_7_3
  {
    static void Main(string[] args)
    {
      Price price = new Price(55);

      price.PrintType();

      int a = (int)price.GetPrice();

      Console.WriteLine("the price is " + a);

      Console.ReadKey();
    }
  }
}
```

上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/1a223402-1e51-43ed-97e4-ea3c0aea78f4.png)

# 泛型的不同约束

在 C#泛型中有不同类型的约束：

+   基类约束

+   接口约束

+   引用类型和值类型约束

+   多个约束

最常见和流行的类型是基类约束和接口约束，因此我们将在以下部分重点关注它们。

# 基类约束

这种约束的想法是只有扩展基类的类才能用作泛型类型。例如，如果您有一个名为`Person`的类，并且将此`Person`类用作`Generic`约束的基类，那么只有`Person`类或继承`Person`类的任何其他类才能用作该泛型类的类型参数。让我们看一个例子：

```cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Chapter7
{
  public class Person
  {
    public void PrintName()
    {
      Console.WriteLine("My name is Raihan");
    }
  }

  public class Boy : Person
  {

  }

  public class Toy
  {

  }

  public class Human<T> where T : Person
  {
    T obj;

    public Human(T o)
    {
      obj = o;
    }

    public void MustPrint()
    {
      obj.PrintName();
    }
  }

  class Code_7_3
  {
    static void Main(string[] args)
    {
      Person person = new Person();
      Boy boy = new Boy();
      Toy toy = new Toy();

      Human<Person> personTypeHuman = new Human<Person>(person);
      personTypeHuman.MustPrint();

      Human<Boy> boyTypeHuman = new Human<Boy>(boy);
      boyTypeHuman.MustPrint();

      /* Not allowed
      Human<Toy> toyTypeHuman = new Human<Toy>(toy);
      toyTypeHuman.MustPrint();
      */

      Console.ReadKey();
    }
  }
}
```

# 接口约束

与基类约束类似，当您的泛型类约束设置为接口时，我们看到接口约束。只有实现该接口的类才能在泛型方法中使用。

# 引用类型和值类型约束

当您想要区分泛型类和引用类型和值类型时，您需要使用此约束。当您使用引用类型约束时，泛型类将只接受引用类型对象。为了实现这一点，您必须使用`class`关键字扩展您的泛型类：

```cs
... where T : class
```

此外，当您想要使用值类型时，您需要编写以下代码：

```cs
... where T : struct
```

正如我们所知，`class`是引用类型，`struct`是值类型。因此，当您设置值类型约束时，这意味着泛型只能用于值类型，如`int`或`double`。不会有任何引用类型，如字符串或任何其他自定义类。

# 多个约束

在 C#中，可以在泛型类中使用多个约束。当这样做时，需要注意顺序。实际上，您可以包含多少约束都没有限制；您可以使用您需要的多少个。

# 泛型方法

像`Generic`类一样，可以有泛型方法，泛型方法不一定要在泛型类中。泛型方法也可以在非泛型类中。要创建泛型方法，必须在方法名之后和括号之前放置类型参数。一般形式如下：

```cs
access-modifier return-type method-name<type-parameter>(params){ method-body }
```

现在，让我们看一个泛型方法的例子：

```cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Chapter7
{
  class Hello
  {
    public static T Larger<T>(T a, T b) where T : IComparable<T>
    {
      return a.CompareTo(b) > 0 ? a : b;
    }
  }

  class Code_7_4
  {
    static void Main(string[] args)
    {
      int result = Hello.Larger<int>(3, 4);

      double doubleResult = Hello.Larger<double>(4.3, 5.6);

      Console.WriteLine("The Large value is " + result);
      Console.WriteLine("The Double Large value is " + doubleResult);

      Console.ReadKey();
    }
  }
}
```

上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/e51e658f-c3b2-4124-afc4-89e61c35953d.png)

在这里，我们可以看到我们的`Hello`类不是一个泛型类。然而，`Larger`方法是一个泛型方法。这个方法接受两个参数并比较它们，返回较大的值。这个方法还实现了一个约束，即`IComparable<T>`。在主方法中，我们多次调用了这个泛型方法，一次使用`int`值，一次使用`double`值。在输出中，我们可以看到该方法成功地比较并返回了较大的值。

在这个例子中，我们只使用了一种类型的参数，但是在泛型方法中可以有多个参数。在这个示例代码中，我们还创建了一个`static`方法，但是泛型方法也可以是非静态的。静态/非静态与是否为泛型方法无关。

# 类型推断

编译器变得更加智能。一个例子就是泛型方法中的类型推断。**类型推断**意味着调用泛型方法而不指定类型参数，并让编译器确定使用哪种类型。这意味着在前面的例子中，当调用方法时，我们无法指定类型参数。

让我们看一些类型推断的示例代码：

```cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Chapter7
{
  class Hello
  {
    public static T Larger<T>(T a, T b) where T : IComparable<T>
    {
      return a.CompareTo(b) > 0 ? a : b;
    }
  }

  class Code_7_5
  {
    static void Main(string[] args)
    {
      int result = Hello.Larger(3, 4);

      double doubleResult = Hello.Larger(4.3, 5.6);

      Console.WriteLine("The Large value is " + result);
      Console.WriteLine("The Double Large value is " + doubleResult);

      Console.ReadKey();
    }
  }
}
```

上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/465f1489-acd9-43d6-aaa3-d0ad0c2c2728.png)

在这段代码中，我们可以看到在泛型方法中没有指定类型参数。然而，代码仍然编译并显示正确的输出。这是因为编译器使用类型推断来确定传递给方法的参数类型，并执行方法，就好像参数类型已经给编译器了。因此，当使用类型推断时，不允许在泛型方法中提供不同类型的参数。如果需要传递不同类型的参数，应该明确指定。也可以对可以应用于类的方法应用约束。

# 泛型中的协变和逆变

如果你学过委托，我相信你一定听说过协变和逆变。这些主要是为非泛型委托引入的。然而，从 C# 4 开始，这些也适用于泛型接口和委托。泛型中的协变和逆变概念几乎与委托中的相同。让我们通过示例来看一下。

# 协变

这意味着具有`T`类型参数的通用接口可以返回`T`或任何派生自`T`的类。为了实现这一点，参数应该与`out`关键字一起使用。让我们看看通用形式：

```cs
access-modifier interface-name<out T>{}
```

# 逆变

逆变是泛型中实现的另一个特性。"逆变"这个词听起来可能有点复杂，但其背后的概念非常简单。通常，在创建泛型方法时，我们传递给它的参数与`T`的类型相同。如果尝试传递另一种类型的参数，将会得到编译时错误。然而，使用逆变时，可以传递类型参数实现的基类。此外，要使用逆变，我们必须遵循一种特殊的语法。让我们看看泛型语法：

```cs
access-modifier interface interface-name<in T>{}
```

如果分析上述语句，会发现在`T`之前使用了一个关键字，即`in`。这个关键字告诉编译器这是逆变。如果不包括`in`关键字，逆变将不适用。

现在，让我们看一些示例代码，以便更清楚地理解我们的理解：

```cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Chapter7
{
  public interface IFood<in T>
  {
    void PrintMyName(T obj);
  }

  class HealthyFood<T> : IFood<T>
  {
    public void PrintMyName(T obj)
    {
      Console.WriteLine("This is " + obj);
    }
  }

  class Vegetable
  {
    public override string ToString()
    {
      return "Vegetable";
    }
  }

  class Potato : Vegetable
  {
    public override string ToString()
    {
      return "Potato";
    }
  }

  class Code_7_6
  {
    static void Main(string[] args)
    {
      IFood<Potato> mySelf = new HealthyFood<Potato>();
      IFood<Potato> mySelf2 = new HealthyFood<Vegetable>();

      mySelf2.PrintMyName(new Potato());

      Console.ReadKey();
    }
  }
}
```

上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/74ef526e-0505-4898-9e7e-e1df617488ad.png)

如果现在分析这段代码，会发现我们创建了一个名为`IFood`的接口，它使用了逆变。这意味着如果这个接口在一个泛型类中实现，该类将允许提供的类型参数的**基类**。

`IFood`接口有一个方法签名：

```cs
void PrintMyName(T obj);
```

这里，`T`被用作方法的参数。

现在，一个名为`HealthyFood`的类实现了接口，而类中实现的方法只打印一个字符串：

```cs
class HealthyFood<T> : IFood<T>
{
  public void PrintMyName(T obj)
  {
    Console.WriteLine("This is " + obj);
  }
}
```

然后，我们创建了两个类：`Vegetable`和`Potato`。`Potato`扩展`Vegetable`。两个类都重写了`ToString()`方法，并且如果类是`Potato`，则返回`Potato`，如果类是`Vegetable`，则返回`Vegetable`。

在主方法中，我们创建了一个`Potato`类的对象和一个`Vegetable`类的对象。这两个对象都保存在`IFood<Potato>`变量中：

```cs
IFood<Potato> mySelf = new HealthyFood<Potato>();
IFood<Potato> mySelf2 = new HealthyFood<Vegetable>();
```

有趣的部分在于`mySelf2`变量是`IFood<Potato>`类型，但它持有`HealthyFood<Vegetable>`类型的对象。这只有因为逆变性才可能。

请查看以下语句：

```cs
mySelf2.PrintMyName(new Potato());
```

当我们执行它时，可以看到输出如下：

```cs
This is Potato
```

如果删除`in`关键字并尝试再次运行程序，您将失败，并且编译器将抛出错误，表示这是不可能的。之所以能够运行代码，仅仅是因为逆变性。

# 摘要

C#中的泛型是一个非常强大的功能，它减少了代码重复，使程序更加结构化，并提供了可扩展性。一些重要的数据结构是基于泛型概念创建的；例如，List（集合）是 C#中的一种泛型类型。这是现代开发中最常用的数据结构之一。

在下一章中，我们将学习如何使用图表来设计和建模我们的软件，以便更好地进行沟通。在开发软件时，如果软件设计没有清晰地传达给开发人员，那么软件很可能无法达到其建立的目的。因此，理解重要的模型和图表非常重要。


# 第八章：软件建模和设计

随着土木工程的出现和大型结构的创建，建模和设计实践变得非常重要。软件开发也是如此。如今，软件无处不在：在你的电脑、手机、电视、汽车等等。随着软件的使用范围扩大，软件开发变得越来越复杂和昂贵，需要时间和金钱。

软件建模和设计是软件开发生命周期的重要部分。如果你有一个想法，计划开始一个软件项目，你应该做的第一件事是设计和建模软件，而不是直接开始编写代码。这将为你提供软件的高层视图，并有机会以便于扩展和修改的方式设计架构。如果你不事先进行建模，可能会陷入需要重构软件架构的情况，这可能非常昂贵。

本章将涵盖的主题如下：

+   设计图的重要性

+   不同的**统一建模语言**（**UML**）图

+   类图

+   用例图

+   序列图

# 设计图的重要性

UML 是一种设计语言，是用于软件建模和设计的标准语言。它最初由 Grady Booch，Ivar Jacobson 和 James Rumbaugh 于 1994-1995 年在 Rational Software 开发。1997 年，**对象管理组**（**OMG**）将其采纳为建模的标准语言。后来，2005 年，**国际标准化组织**（**ISO**）批准 UML 作为 ISO 标准，自那时起，它已被每个软件社区采用。

UML 图允许开发人员向其他人传达软件设计。这是一种具有一套规则的语言，鼓励简单的交流。如果你学会了阅读 UML，你就能理解任何用 UML 编写的软件模型。用普通英语解释软件模型将会非常困难。

# 不同的 UML 图

有许多类型的 UML 图，但在本章中我们只讨论最重要的几种。UML 图分为以下两个主要类别：

+   结构图

+   行为图

以下列表显示了属于结构图类别的图表：

+   类图

+   组件图

+   组合结构图

+   部署图

+   对象图

+   包图

+   配置文件图

行为图包括以下内容：

+   活动图

+   通信图

+   交互概述图

+   序列图

+   状态图

+   时序图

+   用例图

# 类图

类图是一种结构图，主要用于提供面向对象软件的设计。该图表演示了软件的结构，类的属性和方法，以及系统中类之间的关系。它可用于开发和文档编写；软件开发人员经常使用该图表快速了解代码，并帮助其他开发人员理解系统。它也偶尔被公司业务方面的员工使用。

以下是类图的三个主要部分：

+   类名

+   属性部分

+   方法部分

类图由不同的类组成，表示为方框或矩形。矩形通常分为上述部分。第一部分包含类的名称，第二部分包含属性，第三部分包含方法。

让我们来看一个类图的例子：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/ef5d873d-d509-4bac-9c81-2c9cbd5ab909.jpg)

在这里，我们可以看到一个名为`Car`的类，如顶部框所示。在下面，我们有该类的属性。我们可以看到`color`是一个属性的名称，前面有一个`+`号，表示它是一个公共变量。我们还可以看到变量名称旁边有一个`:`（冒号），这是一个分隔符。冒号后面给出的内容表示变量的类型。在这种情况下，我们可以看到`color`变量是`string`类型。下一个属性是`company`，也是`string`类型的变量。它前面有一个`-`号，表示它是一个私有变量。第三个属性是`fuel`，我们可以看到这是一个`integer`类型的私有变量。

如果我们查看属性下面，我们会看到`Car`类的方法。我们可以看到它有三个方法：`move(direction: string)`，`IsFuelEmpty()`和`RefilFuel(litre: int)`。与属性一样，我们可以看到方法后面有一个`:`（冒号）。在这种情况下，冒号后面给出的类型是方法的返回类型。第一个方法`move`不返回任何东西，所以类型是 void。在`IsFuelEmpty()`方法中，返回类型是布尔值，第三个方法也是如此。这里要注意的另一件事是方法的参数，它们放在方法名后的括号中。例如，`move`方法有一个名为`direction`的`string`类型参数。`RefilFuel(litre: int)`方法有一个`int`类型参数，即`litre`。

在前面的例子中，我们看到了类在类图中的表示。通常，一个系统有多个相互关联的类。类图也展示了类之间的关系，这给观察者提供了系统对象关系的完整图景。在第四章中，*对象协作*，我们学习了面向对象软件中类和对象之间的不同关系。现在让我们看看如何使用类图表示这些不同的对象关系。

# 继承

**继承**是一种类似于另一个类的关系，就像 BMW i8 Roadster 是一种汽车一样。这种关系使用一条线和一个空心箭头表示。箭头从类指向超类，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/6d761b9e-3e8e-4ac7-928b-22d8608d8bbd.png)

# 关联

关联关系是对象之间最基本的关系。当一个对象与另一个对象有某种逻辑或物理关系时，称为**关联关系**。它由一条线和一个箭头表示。如果两侧都有箭头，表示双向关系。关联的一个例子可能是以下内容：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/b837ef58-3cb9-42eb-ae29-7f9946b74e7a.png)

# 聚合

**聚合** **关系**是一种特殊类型的关联关系。这种关系通常被称为**拥有** **关系**。当一个类包含另一个类/对象时，这是一种聚合关系。这是用一条线和一个空心菱形表示的。例如，一辆车有一个轮胎。轮胎和车有一个聚合关系，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/99938797-f7b0-452b-931f-267d243a720d.png)

# 组合

当一个类包含另一个类，并且依赖类不能没有超类而存在时，这是一种**组合关系**。例如，银行账户不能没有银行而存在，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/5383a622-97ff-488d-8ae1-4a4f5f3e561e.png)

# 依赖

当一个类有一个依赖类，但是这个类本身不依赖于它自己的依赖类时，这些类之间的关系被称为**依赖关系**。在依赖关系中，依赖类的任何改变对其所依赖的类没有任何影响。但是如果它所依赖的类发生变化，依赖类将会受到影响。

这种关系用虚线表示，末端有一个箭头。例如，让我们想象一下我们手机上有一个主题。如果我们改变主题，手机的图标会改变，所以图标对主题有依赖。这种关系在下面的图中显示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/73fabc73-d7d4-44ae-9f17-4af0a2b5a0b4.png)

# 类图的一个例子

让我们来看一个项目的类图的例子。在这里，我们有一些成绩管理软件，被学校的老师和学生使用。这个软件允许老师更新特定学生在不同学科的成绩。它也允许学生查看他们的成绩。对于这个软件，我们有以下的类：

+   `Person`:

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/7f2d8fd2-4b2a-450e-ae7b-4d32f334715c.png)

人员类图

+   老师：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/f38bc1d5-dbe2-471f-b2f3-a82ee2b8f65b.png)

老师类图

+   `Student`:

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/4488335c-873e-4021-b3a9-064096d3331f.png)

学生类图

+   `Subject`:

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/479eb717-fadd-421e-b87c-8efd0e87dbd3.png)

学科类图

在这里，我们使用 Visual Studio 生成我们的类图，所以箭头可能不匹配前面部分给出的箭头。如果你使用其他绘图软件绘制你的类图，或者你手绘，那么请使用前面部分指定的箭头。

让我们来看下面的完整类图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/ec3d0186-abb9-4525-ab2e-8d22d3571048.png)

在这里，我们可以看到我们有一个`Person`类，有两个属性，`FirstName`和`LastName`。`Student`和`Teacher`类继承了`Person`类，所以我们可以看到箭头是空心的。`Student`类有两个属性，`email`和`studentId`。它还有一个名为`GetExamGrade`的方法（string subject），它接受学科的名称并返回`char`类型的成绩。我们可以看到另一个类`Subject`与`Student`有合成关系。`Student`有一个学科列表，而`Subject`类有三个属性，`grade`，`name`和`subjectId`。`Teacher`类有一个`email`，`phoneNumber`和`teacherId`，它们分别是`string`，`string`和`int`类型。`Teacher`类与`Student`类有一个关联关系，因为老师有一组学生在他们下面。`Teacher`类还有一个名为`GiveExamGrade`的方法，它接受三个参数，`studentId`，`subject`和`grade`。这个方法将设置学生学科的成绩。

仅仅通过查看类图，我们就可以清楚地了解系统。我们知道学科与学生的关系，以及学生与老师的关系。我们还知道一个学科对象不能没有学生对象存在，因为它们有合成关系。这就是类图的美妙之处。

# 用例图

**用例图**是在软件开发中非常常用的行为图。这个图的主要目的是说明软件的功能使用。它包含了系统的用例，并且可以用来提供功能的高层视图，甚至是软件的非常具体的低级模块。通常对于一个系统，会有多个用例图，专注于系统的不同层次。用例图不应该用来显示系统的实现细节；它们被开发出来只是为了显示系统的功能需求。用例图对于业务人员来传达他们从系统中需要什么非常有用。

用例图的四个主要部分如下列表所示：

+   角色

+   用例

+   通信链接

+   系统边界

# 角色

用例图中的角色不一定是一个人，而是系统的用户。它可以是一个人，另一个系统，甚至是系统的另一个模块。角色的可视表示如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/0e846aec-8451-4299-a724-68d343e6b723.png)

角色负责提供输入。它向系统提供指令，系统会相应地工作。角色所做的每一个动作都有一个目的。用例图向我们展示了一个角色可以做什么，以及角色的期望是什么。

# 用例

用例图的视觉部分或表示被称为**用例**。这代表了系统的功能。角色将执行一个用例来实现一个目标。用例由一个带有功能名称的椭圆表示。例如，在餐厅应用程序中，*下订单*可能是一个用例。我们可以表示如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/23f866bf-55e6-476f-b4f4-63a353931cd9.png)

# 通信链接

**通信链接**是从角色到用例的简单线条。这个链接用于显示角色与特定用例的关系。角色无法访问所有用例，因此在显示哪些用例可以被哪个角色访问时，通信链接非常重要。让我们看一个通信链接的例子，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/37f21476-f699-4702-bc50-b4c79ff2f693.png)

# 系统边界

**系统边界**主要用于显示系统的范围。能够确定哪些用例属于我们的系统，哪些不属于是很重要的。在用例图中，我们只关注我们系统中的用例。在大型系统中，如果这些模块足够独立，可以独立运行，那么系统的每个模块有时会被视为一个边界。这通常用一个包含用例的矩形框来表示。角色不是系统的一部分，因此角色将在系统边界之外，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/2849c139-5649-4c82-85ca-af90ca198e15.png)

# 用例图的一个例子

让我们现在想象一下，我们有一个餐厅系统，顾客可以点餐。厨师准备食物，经理跟踪销售情况，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/60d6aaf7-dcfb-47d0-b532-0e16b2895a3c.png)

从上图可以看出，我们有三个角色（顾客、厨师和经理）。我们还有不同的用例——查看菜单、点餐、烹饪食物、上菜、支付和销售报告，这些用例与一个或多个角色相连。**顾客**参与了查看菜单、点餐和支付用例。厨师必须访问点餐以了解订单情况。厨师还参与了烹饪食物和上菜用例。与厨师和顾客不同，经理能够查看餐厅的销售报告。

通过查看这个用例图，我们能够确定系统的功能。它不会给出任何实现细节，但我们可以很容易地看到系统的概述。

# 序列图

序列图是行为图中的一种交互图。顾名思义，它显示了系统活动的顺序。通过查看序列图，您可以确定在特定时间段内发生了哪些活动，以及接下来发生了哪些活动。它使我们能够理解系统的流程。它表示的活动可能是用户与系统之间的交互，两个系统之间的交互，或者系统与子系统之间的交互。

序列图的水平轴显示时间从左到右流逝，而垂直轴显示活动的流程。不同的活动以顺序的方式放置在图中。序列图不一定显示时间流逝的持续时间，而是显示从一个活动到另一个活动的步骤。

在接下来的部分中，我们将看一下序列图中使用的符号。

# 一个参与者

序列图中的参与者与用例图中的参与者非常相似。它可以是用户、另一个系统，甚至是用户组。参与者不是系统的一部分，而是在外部执行命令。不同的操作是在接收用户命令时执行的。参与者用一个棒状图表示，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/0c3a3caf-1da0-424c-a660-ccc90aaaf83f.png)

# 一个生命线

序列图中的生命线是系统的一个实体或元素。每个生命线都有自己的逻辑和任务要完成。通常，一个系统有多个生命线，并且命令是从一个生命线传递到另一个生命线的。

一个生命线由一个从底部发出的带有垂直线的框表示，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/8de10e9a-0fe9-4c81-9cb4-cb91fa71807d.png)

# 一个激活

激活是生命线上的一个小矩形框。这个激活框代表了一个活动处于活动状态的时刻。框的顶部代表活动的开始，框的底部代表活动的结束。

让我们看看在图中是什么样子的：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/106cb923-d43a-4443-b318-47964cdeb963.png)

# 一个呼叫消息

一个呼叫消息表示生命线之间的交互。它从左到右流动，并且以一条箭头表示在线的末端，如下图所示。一个消息呼叫代表了一些信息或触发下一个生命线的触发器：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/8b2892f6-8979-431c-a7d8-e21a6ab4ea85.png)

# 一个返回消息

序列图中的正常消息流是从左到右的，因为这代表了动作命令；然而，有时消息会返回给调用者。一个返回消息从右到左流动，并且以一个带箭头头的虚线表示，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/d2e819bf-6312-4869-937c-197f934da53f.png)

# 一个自消息

有时，消息是从一个生命线传递到它自己，比如内部通信。它将以与消息呼叫类似的方式表示，但是它不是指向另一个活动或另一个生命线，而是返回到相同生命线的相同活动，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/650a7243-f3f6-4234-9079-8478e204619b.png)

# 一个递归消息

当发送一个自消息用于递归目的时，它被称为递归消息。在同一时间线上为此目的绘制另一个小活动，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/08ca0a1f-f656-4487-9a85-fe267efadec5.png)

# 一个创建消息

这种类型的消息不是普通的消息，比如一个呼叫消息。当一个生命线由另一个生命线创建时，会使用一个创建消息，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/a01993e4-ef74-4d0f-95b2-1a0b6048300f.png)

# 一个销毁消息

当从一个活动发送一个销毁消息到一个生命线时，意味着接下来的生命线不会被执行，流程将停止，如下图所示。它被称为销毁消息，因为它销毁了活动流程：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/b2684c59-cf70-4fa6-a275-e4187b4cd873.png)

# 一个持续消息

我们使用一个持续消息来显示当一个活动将消息传递给下一个活动时有一个时间持续。它类似于一个呼叫消息，但是是向下倾斜的，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/63b79c11-31e7-40da-8cc0-bfa999315e34.png)

# 一个注释

备注用于包含与元素或操作相关的任何必要备注。它没有特定的规则。可以将其放置在适合清楚表示事件的任何位置。任何类型的信息都可以写在备注中。备注表示如下：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/26eabc06-08ee-442a-809e-1de6752d45d9.png)

# 序列图示例

学习任何东西的最佳方法是通过查看其示例。让我们来看一个简单餐厅系统的序列图示例：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-oop-cs/img/ab1d8615-8507-4288-a0ec-873e7b6bdc13.png)

在这里，我们可以看到客户首先从 UI 请求菜单。UI 将请求传递给控制器，然后控制器将请求传递给经理。经理获取菜单并回应控制器。控制器回应 UI，UI 在显示器上显示菜单。

客户选择商品后，订单逐步传递给经理。经理调用另一个方法来准备食物，并向客户发送响应，通知他们订单已收到。食物准备好后，将其送到客户那里。客户收到食物后，支付账单并领取付款收据。

通过查看序列图，我们可以看到流程中涉及的不同活动。系统是如何一步一步地工作的非常清楚。这种类型的图表在展示系统流程方面非常有用，非常受欢迎。

# 摘要

在本章中，您学习了如何使用 UML 图表对软件进行建模和设计的基础知识。这对每个软件开发人员来说都非常重要，因为我们需要能够与企业进行沟通，反之亦然。您还会发现，当与其他开发人员或软件架构师讨论系统时，这些图表也很有用。在本章中，我们没有涵盖所有可用于建模和设计软件的不同图表，因为这超出了本书的范围。在本章中，我们涵盖了类图、用例图和序列图。我们看到了每个图表的一个示例，并了解了如何绘制它们。

在下一章中，我们将学习如何使用 Visual Studio。我们将看到一些技巧和窍门，这些将帮助您在使用 Visual Studio 时提高生产力。
