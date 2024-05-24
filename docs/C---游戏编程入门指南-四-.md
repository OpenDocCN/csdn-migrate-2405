# C++ 游戏编程入门指南（四）

> 原文：[`annas-archive.org/md5/8b22c2649bdec9fa4ee716ae82ae0bb1`](https://annas-archive.org/md5/8b22c2649bdec9fa4ee716ae82ae0bb1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：指针，标准模板库和纹理管理

在这一章中，我们将学到很多，也会在游戏中完成很多工作。我们将首先学习关于**指针**的基本 C++主题。指针是保存内存地址的变量。通常，指针将保存另一个变量的内存地址。这听起来有点像引用，但我们将看到它们更加强大。我们还将使用指针来处理一个不断扩大的僵尸群。

我们还将学习**标准模板库**（STL），这是一组允许我们快速轻松地实现常见数据管理技术的类集合。

一旦我们理解了 STL 的基础知识，我们就能够利用这些新知识来管理游戏中的所有纹理，因为如果我们有 1000 个僵尸，我们实际上不希望为每一个加载一份僵尸图形到 GPU 中。

我们还将深入研究面向对象编程，并使用静态函数，这是一个类的函数，可以在没有类实例的情况下调用。同时，我们将看到如何设计一个类，以确保只能存在一个实例。当我们需要保证代码的不同部分将使用相同的数据时，这是理想的。

在这一章中，我们将学习以下主题：

+   学习关于指针

+   学习关于 STL

+   使用静态函数和**单例**类实现`Texture Holder`类

+   实现一个指向一群僵尸的指针

+   编辑一些现有的代码，使用`TextureHolder`类为玩家和背景

# 指针

在学习 C++编程时，指针可能会引起挫折。但实际上，这个概念很简单。

### 注意

**指针**是一个保存内存地址的变量。

就是这样！没有什么需要担心的。对初学者可能引起挫折的是语法，我们用来处理指针的代码。考虑到这一点，我们将逐步介绍使用指针的代码的每个部分。然后你可以开始不断地掌握它们。

### 提示

在这一部分，我们实际上会学到比这个项目需要的更多关于指针。在下一个项目中，我们将更多地使用指针。尽管如此，我们只是浅尝辄止。强烈建议进一步学习，我们将在最后一章更多地谈论这个问题。

我很少建议记忆事实、数字或语法是学习的最佳方式。然而，记忆与指针相关的相当简短但至关重要的语法可能是值得的。这样它就会深深地扎根在我们的大脑中，我们永远不会忘记它。然后我们可以讨论为什么我们需要指针，并研究它们与引用的关系。指针的类比可能会有所帮助。

### 提示

如果一个变量就像一座房子，它的内容就是它所持有的值，那么指针就是房子的地址。

我们在上一章中学到，当我们将值传递给函数，或者从函数返回值时，实际上是在制作一个完全与之前相同的新房子。我们正在复制传递给函数或从函数返回的值。

此时，指针可能开始听起来有点像引用。那是因为它们有点像引用。然而，指针更加灵活、强大，并且有它们自己特殊和独特的用途。这些特殊和独特的用途需要特殊和独特的语法。

## 指针语法

与指针相关的主要运算符有两个。第一个是**取地址**运算符：

```cpp
'&' 

```

第二个是**解引用**运算符：

```cpp
'*' 

```

现在我们将看一下我们如何使用这些运算符与指针。

你会注意到的第一件事是地址运算符与引用运算符相同。为了增加一个渴望成为 C++游戏程序员的人的困境，这两个运算符在不同的上下文中做不同的事情。从一开始就知道这一点是很有价值的。如果你盯着一些涉及指针的代码看，感觉自己要发疯，知道这一点：

### 提示

你是完全理智的！你只需要看看上下文的细节。

现在你知道，如果有什么东西不清楚和立即明显，那不是你的错。指针不是清晰和立即明显的，但仔细观察上下文会揭示发生了什么。

有了这个知识，你需要比以前的语法更加关注指针，以及这两个运算符是什么（地址运算符和解引用），我们现在可以开始看一些真正的指针代码了。

### 提示

确保在继续之前已经记住了这两个运算符。

## 声明指针

要声明一个新的指针，我们使用解引用运算符以及指针将要保存的变量的类型。看一下代码，我们将进一步讨论它：

```cpp
// Declare a pointer to hold the address of a variable of type int 

int* pHealth; 

```

这段代码声明了一个名为`pHealth`的新指针，可以保存`int`类型变量的地址。请注意，我说的是可以保存`int`类型的变量。与其他变量一样，指针也需要初始化一个值才能正确使用它。与其他变量一样，名称`pHealth`是任意的。

通常习惯上，将指针的名称前缀为`p`。这样在处理指针时更容易记住，并且可以将它们与常规变量区分开来。

解引用运算符周围使用的空格是可选的（因为 C++在语法上很少关心空格），但建议使用，因为它有助于可读性。看一下以下三行代码，它们做的事情完全相同。

我们刚刚在前面的例子中看到的格式，带有解引用运算符紧挨着类型：

```cpp
int* pHealth; 

```

解引用运算符两侧的空格是可选的。

```cpp
int * pHealth; 

```

解引用运算符紧挨着指针的名称：

```cpp
int *pHealth; 

```

了解这些可能性是值得的，这样当你阅读代码时，也许在网上，你会明白它们都是一样的。在本书中，我们将始终使用与类型紧挨着的解引用运算符的第一个选项。

就像常规变量只能成功地包含适当类型的数据一样，指针也应该只保存适当类型的变量的地址。

指向`int`类型的指针不应该保存 String、Zombie、Player、Sprite、float 或任何其他类型的地址。

## 初始化指针

接下来我们可以看到如何将变量的地址存入指针中。看一下以下代码：

```cpp
// A regular int variable called health 
int health = 5; 

// Declare a pointer to hold the address of a variable of type int 
int* pHealth; 

// Initialize pHealth to hold the address of health, 
// using the "address of" operator 
pHealth = &health; 

```

在前面的代码中，我们声明了一个名为`health`的`int`变量，并将其初始化为`5`。尽管我们以前从未讨论过，但这个变量必须在计算机内存中的某个地方。它必须有一个内存地址。

我们可以使用地址运算符访问这个地址。仔细看前面代码的最后一行。我们用`health`的地址初始化了`pHealth`，就像这样：

```cpp
  pHealth = &health; 

```

我们的`pHealth`现在保存了常规`int`变量`health`的地址。在 C++术语中，我们说`pHealth`指向 health。

我们可以通过将`pHealth`传递给一个函数来使用它，这样函数就可以处理`health`，就像我们用引用一样。如果我们只是这样做，指针就没有存在的理由了。

## 重新初始化指针

指针，不像引用，可以重新初始化以指向不同的地址。看一下以下代码：

```cpp
// A regular int variable called health 
int health = 5; 
int score = 0; 

// Declare a pointer to hold the address of a variable of type int 
int* pHealth; 

// Initialize pHealth to hold the address of health 
pHealth = &health; 

// Re-initialize pHealth to hold the address of score 
pHealth = &score; 

```

现在`pHealth`指向`int`变量`score`。

当然，我们的指针名称`pHealth`现在有点模糊，可能应该被称为`pIntPointer`。在这里要理解的关键是我们可以进行这种重新赋值。

到目前为止，我们实际上还没有使用指针来做任何其他事情，而只是简单地指向（保存内存地址）。 让我们看看如何访问指针指向的地址存储的值。 这将使它们真正有用。

## 解引用指针

因此，我们知道指针保存内存中的地址。 如果我们在游戏中输出这个地址，也许在我们的 HUD 中，声明并初始化后，它可能看起来像这样：`9876`。

它只是一个值。 一个代表内存中地址的值。 在不同的操作系统和硬件类型上，这些值的范围会有所不同。 在本书的上下文中，我们从不需要直接操作地址。 我们只关心指向的地址存储的值是什么。

变量使用的实际地址是在游戏执行时（在运行时）确定的，因此，在编写游戏时，无法知道变量的地址以及指针中存储的值。

我们通过使用解引用运算符`*`访问指针指向的地址存储的值。 以下代码直接操作了一些变量，并使用了指针。 试着跟着走，然后我们会解释一下。

### 提示

警告！ 接下来的代码毫无意义（有点刻意）。 它只是演示使用指针。

```cpp
// Some regular int variables 
int score = 0; 
int hiScore = 10; 

// Declare 2 pointers to hold the addresses of ints 
int* pIntPointer1; 
int* pIntPointer2; 

// Initialize pIntPointer1 to hold the address of score 
pIntPointer1 = &score; 

// Initialize pIntPointer2 to hold the address of hiScore 
pIntPointer2 = &hiScore; 

// Add 10 to score directly 
score += 10; 
// Score now equals 10 

// Add 10 to score using pIntPointer1 
*pIntPointer1 += 10; 
// score now equals 20- A new high score 

// Assign the new hi score to hiScore using only pointers 
*pIntPointer2 = *pIntPointer1; 
// hiScore and score both equal 20 

```

在前面的代码中，我们声明了两个 int 变量，`score`和`hiScore`。 然后我们分别用零和十初始化它们。 接下来，我们声明了两个指向`int`的指针。 它们是`pIntPointer1`和`pIntPointer2`。 我们在声明它们的同时初始化它们，以保存（指向）变量`score`和`hiScore`的地址。

接下来，我们以通常的方式给`score`加上十分，`score += 10`。 然后我们看到，通过在指针上使用解引用运算符，我们可以访问指向的地址存储的值。 以下代码实际上改变了由`pIntPointer1`指向的变量存储的值：

```cpp
// Add 10 to score using pIntPointer1 
*pIntPointer1 += 10; 
// score now equals 20, A new high score 

```

前面代码的最后一部分解引用了两个指针，将`pIntPointer1`指向的值分配为`pIntPointer2`指向的值：

```cpp
// Assign the new hi-score to hiScore with only pointers 
*pIntPointer2 = *pIntPointer1; 
// hiScore and score both equal 20 

```

`score`和`hiScore`现在都等于`20`。

## 指针是多才多艺且强大的

我们可以用指针做更多的事情。 以下是一些有用的事情。

### 动态分配的内存

到目前为止，我们所见过的所有指针都指向作用域仅限于它们创建的函数的内存地址。 因此，如果我们声明并初始化一个指向局部变量的指针，当函数返回时，指针、局部变量和内存地址都会消失。 它超出了作用域。

到目前为止，我们一直在使用预先决定的固定内存量。 此外，我们一直在使用的内存由操作系统控制，变量在我们调用和返回函数时会丢失和创建。 我们需要的是一种使用始终在作用域内的内存的方法，直到我们完成为止。 我们希望拥有可以自己调用并负责的内存。

当我们声明变量（包括指针）时，它们位于称为**堆栈**的内存区域中。 还有另一个内存区域，尽管由操作系统分配/控制，但可以在运行时分配。 这另一个内存区域称为**自由存储**，有时也称为**堆**。

### 提示

堆上的内存没有特定函数的作用域。 从函数返回不会删除堆上的内存。

这给了我们很大的力量。 通过访问计算机运行游戏的资源所限制的内存，我们可以规划具有大量对象的游戏。 在我们的情况下，我们想要一个庞大的僵尸群。 然而，正如蜘蛛侠的叔叔会毫不犹豫地提醒我们的那样，*伴随着巨大的力量而来的是巨大的责任*。

让我们看看如何使用指针来利用自由存储器上的内存，以及在完成后如何将该内存释放回操作系统。

要创建一个指向堆上值的指针，首先我们需要一个指针：

```cpp
int* pToInt = nullptr; 

```

在上一行代码中，我们声明了一个指针，就像我们以前看到的那样，但是由于我们没有将其初始化为指向一个变量，而是将其初始化为`nullptr`。我们这样做是因为这是一个好习惯。考虑解引用一个指针（更改它指向的地址的值），当你甚至不知道它指向什么时。这将是编程等同于去射击场，蒙住某人的眼睛，让他转个圈，然后告诉他射击。通过将指针指向空（`nullptr`），我们不会对其造成任何伤害。

当我们准备在自由存储器上请求内存时，我们使用`new`关键字，如下面的代码行所示：

```cpp
pToInt = new int; 

```

指针`pToInt`现在保存了在自由存储器上的内存地址，该内存大小刚好可以容纳一个`int`值。

### 提示

任何分配的内存在程序结束时都会被返回。然而，重要的是要意识到，除非我们释放它，否则这段内存永远不会被释放（在我们的游戏执行中）。如果我们继续从自由存储器中获取内存而不归还，最终它将耗尽并且游戏会崩溃。

我们不太可能因为偶尔从自由存储器中获取`int`大小的内存块而耗尽内存。但是，如果我们的程序有一个频繁执行请求内存的函数或循环，最终游戏将变慢然后崩溃。此外，如果我们在自由存储器上分配了大量对象并且没有正确管理它们，那么这种情况可能会很快发生。

下面的代码行，将之前由`pToInt`指向的自由存储器上的内存返回（删除）：

```cpp
delete pToInt; 

```

现在，之前由`pToInt`指向的内存不再属于我们，我们必须采取预防措施。尽管内存已经返回给操作系统，但`pToInt`仍然保存着这段内存的地址，这段内存不再属于我们。

下面的代码行确保`pToInt`不能用于尝试操作或访问这段内存：

```cpp
pToInt = nullptr; 

```

### 提示

如果指针指向的地址无效，则称为**野指针**或**悬空指针**。如果您尝试对悬空指针进行解引用，如果幸运的话，游戏会崩溃，并且会收到内存访问违规错误。如果不幸的话，您将创建一个非常难以找到的错误。此外，如果我们使用自由存储器上的内存超出函数生命周期，我们必须确保保留指向它的指针，否则我们将泄漏内存。

现在我们可以声明指针并将它们指向自由存储器上新分配的内存。我们可以通过对它们进行解引用来操作和访问它们指向的内存。当我们完成后，我们可以将内存返回到自由存储器，并且我们知道如何避免悬空指针。

让我们看看指针的一些更多优势。

### 将指针传递给函数

首先，我们需要编写一个具有指针在签名中的函数，如下面的代码：

```cpp
void myFunction(int *pInt) 
{ 
   // dereference and increment the value stored  
   // at the address pointed to by the pointer 
   *pInt ++ 
   return; 
} 

```

前面的函数只是对指针进行解引用，并将存储在指定地址的值加一。

现在我们可以使用该函数，并显式地传递一个变量的地址或另一个指向变量的指针：

```cpp
int someInt = 10; 
int* pToInt = &someInt; 

myFunction(&someInt); 
// someInt now equals 11 

myFunction(pToInt); 
// someInt now equals 12 

```

现在，如前面的代码所示，在函数内部，我们实际上正在操作来自调用代码的变量，并且可以使用变量的地址或指向该变量的指针来这样做。

### 声明并使用指向对象的指针

指针不仅适用于常规变量。我们还可以声明指向用户定义类型（如我们的类）的指针。这是我们声明指向类型为`Player`的对象的指针的方法：

```cpp
Player player; 
Player* pPlayer = &Player; 

```

我们甚至可以直接从指针访问`Player`对象的成员函数，就像下面的代码一样：

```cpp
// Call a member function of the player class 
pPlayer->moveLeft() 

```

在这个项目中，我们不需要使用指向对象的指针，我们将在下一个项目中更加仔细地探讨它们。

## 指针和数组

数组和指针有一些共同之处。数组名是一个内存地址。更具体地说，数组的名称是数组中第一个元素的内存地址。换句话说，数组名指向数组的第一个元素。理解这一点的最好方法是继续阅读，看下一个例子。

我们可以创建一个指向数组保存的类型的指针，然后使用指针以与我们使用数组完全相同的方式使用相同的语法：

```cpp
// Declare an array of ints 
int arrayOfInts[100]; 
//  Declare a pointer to int and initialize it with the address of the first element of the array, arrayOfInts 
int* pToIntArray = arrayOfInts; 

// Use pToIntArray just as you would arrayOfInts 
arrayOfInts[0] = 999; 
// First element of arrayOfInts now equals 999 

pToIntArray[0] = 0; 
// First element of arrayOfInts now equals 0 

```

这也意味着一个具有接受指针原型的函数也接受指针指向的类型的数组。当我们建立我们不断增加的僵尸群时，我们将利用这一事实。

### 提示

关于指针和引用之间的关系，编译器在实现我们的引用时实际上使用指针。这意味着引用只是一个方便的工具（在幕后使用指针）。你可以把引用看作是一种自动变速箱，适合在城里开车，而指针是一种手动变速箱，更复杂，但正确使用时能够获得更好的结果/性能/灵活性。

## 指针总结

指针有时有点棘手。事实上，我们对指针的讨论只是对这个主题的一个介绍。要想熟练掌握它们，唯一的方法就是尽可能多地使用它们。在完成这个项目时，你需要理解关于指针的以下内容：

+   指针是存储内存地址的变量。

+   我们可以将指针传递给函数，直接从调用函数的范围内调用函数中操作值。数组是第一个元素的内存地址。我们可以将这个地址作为指针传递，因为这正是它的作用。

+   我们可以使用指针指向自由存储器上的内存。这意味着我们可以在游戏运行时动态分配大量内存。

### 提示

为了进一步使指针的问题变得神秘，C++最近进行了升级。现在有更多的方法来使用指针。我们将在最后一章学习一些关于智能指针的知识。

还有一个主题要讨论，然后我们可以再次开始编写僵尸竞技场项目。

# 标准模板库

STL 是一组数据容器和操作我们放入这些容器中的数据的方法。更具体地说，它是一种存储和操作不同类型的 C++变量和类的方法。

我们可以将不同的容器视为定制和更高级的数组。STL 是 C++的一部分。它不是一个可选的需要设置的东西，比如 SFML。

STL 是 C++的一部分，因为它的容器和操作它们的代码对许多应用程序需要使用的许多类型的代码至关重要。

简而言之，STL 实现了我们和几乎每个 C++程序员几乎肯定需要的代码，至少在某个时候可能会经常需要。

如果我们要编写自己的代码来包含和管理我们的数据，那么我们不太可能像编写 STL 的人那样高效地编写它。

因此，通过使用 STL，我们保证使用最佳编写的代码来管理我们的数据。甚至 SFML 也使用 STL。例如，在幕后，`VertexArray`类使用 STL。

我们所需要做的就是从可用的容器中选择正确的类型。通过 STL 可用的容器类型包括以下内容：

+   **向量**：就像一个带有助推器的数组。动态调整大小，排序和搜索。这可能是最有用的容器。

+   **列表**：允许对数据进行排序的容器。

+   **Map**：一种允许用户将数据存储为键/值对的关联容器。这是一种数据是查找另一种数据的关键的地方。地图也可以增长和缩小，以及进行搜索。

+   **Set**：一个容器，保证每个元素都是唯一的。

### 注意

有关 STL 容器类型和解释的完整列表，请访问以下链接：[`www.tutorialspoint.com/cplusplus/cpp_stl_tutorial.htm`](http://www.tutorialspoint.com/cplusplus/cpp_stl_tutorial.htm)

在僵尸竞技场游戏中，我们将使用地图。

### 提示

如果您想一窥 STL 为我们节省的复杂性，那么请看一下这个教程，该教程实现了列表将要做的事情。请注意，该教程仅实现了列表的最简单的基本功能：[`www.sanfoundry.com/cpp-program-implement-single-linked-list/`](http://www.sanfoundry.com/cpp-program-implement-single-linked-list/)。

我们可以很容易地看到，如果我们探索 STL，我们将节省大量时间，并且最终会得到一个更好的游戏。让我们更仔细地看看如何使用 Map，然后我们将看到它在僵尸竞技场游戏中对我们有多有用。

## 什么是地图

**Map**是一个动态可调整大小的容器。我们可以轻松地添加和删除元素。与 STL 中的其他容器相比，地图的特殊之处在于我们访问其中的数据的方式。

地图中的数据是成对存储的。考虑这样一种情况，您登录到一个帐户，可能使用用户名和密码。地图非常适合查找用户名，然后检查相关密码的值。

地图也可以用于诸如帐户名称和数字，或者公司名称和股价等事物。

请注意，当我们使用 STL 中的 Map 时，我们决定形成键值对的值的类型。这些值可以是数据类型，如 string 和 int，例如帐户号码，用户名和密码等字符串，或者用户定义的类型，如对象。

接下来是一些真实的代码，让我们熟悉地图。

## 声明地图

这是我们如何声明一个 Map 的方式：

```cpp
map<string, int> accounts; 

```

前一行代码声明了一个名为`accounts`的新`map`，它具有 String 对象的键，每个键将引用一个 int 值。

现在我们可以存储字符串到数据类型（如 int）的键值对，接下来我们将看到如何做到这一点。

## 向地图中添加数据

让我们继续向帐户添加键值对：

```cpp
accounts["John"] = 1234567; 

```

现在有一个可以使用 John 作为键访问的地图条目。以下代码向帐户`map`添加了另外两个条目：

```cpp
accounts["Onkar"] = 7654321; 
accounts["Wilson"] = 8866772; 

```

我们的地图中有三个条目。让我们看看如何访问帐户号码。

## 在地图中查找数据

我们访问数据的方式与添加数据的方式完全相同，即使用键。例如，我们可以将键`Onkar`存储的值赋给一个新的 int`accountNumber`，就像这样的代码：

```cpp
int accountNumber = accounts["Onkar"]; 

```

int 变量`accountNumber`现在存储值`7654321`。我们可以对存储在地图中的值做任何我们可以对该类型的值做的事情。

## 从地图中删除数据

从我们的地图中取值也很简单。下一行代码删除了键`John`及其关联的值：

```cpp
accounts.erase("John"); 

```

让我们看看我们可以用 Map 做些什么。

## 检查地图的大小

我们可能想知道我们的地图中有多少键值对。下一行代码就是这样做的：

```cpp
int size = accounts.size(); 

```

现在，int 变量 size 保存的值是 2。这是因为 accounts 保存了`Onkar`和 Wilson 的值，我们删除了 John。

## 检查地图中的键

地图最相关的特性是使用键查找值的能力。我们可以这样测试特定键的存在与否：

```cpp
if(accounts.find("John") != accounts.end()) 
{ 
   // This code won't run because John was erased 
} 

if(accounts.find("Onkar") != accounts.end()) 
{ 
   // This code will run because Onkar is in the map 
} 

```

在前面的代码中，“！= accounts.end”用于确定键是否存在或不存在。如果搜索的键在地图中不存在，那么`accounts.end`将成为`if`语句的结果。

## 循环/迭代地图的键值对

我们已经看到了如何使用`for`循环来循环/迭代数组的所有值。如果我们想对 Map 做类似的事情怎么办？

以下代码显示了我们如何循环遍历 accounts Map 的每个键值对，并为每个帐户号码加一：

```cpp
for (map<string,int>::iterator it = accounts.begin(); it ! = 
  accounts.end();  ++ it) 
{ 
    it->second +=1; 
} 

```

for 循环的条件可能是前面代码中最有趣的部分。条件的第一部分是最长的部分。如果我们把`map<string,int>::iterator it = accounts.begin()`代码分解开来，它会更容易理解。

`map<string,int>::iterator`代码是一种类型。我们声明了一个适用于具有`string`和`int`键值对的`map`的`iterator`。迭代器的名称是`it`。我们将从`accounts.begin()`返回的值赋给`it`。迭代器`it`现在保存了`map`中的第一个键值对。

`for`循环的条件的其余部分工作如下。代码`it != accounts.end()`表示循环将继续直到达到`map`的末尾，`it++`只是在循环中每次通过时步进到下一个键值对。

在`for`循环内，`it->second`访问键值对的第二个元素，`+=1`将值加一。请注意，我们可以使用`it->first`访问键（它是键值对的第一部分）。

## auto 关键字

在`for`循环的条件中的代码相当冗长，特别是`map<string,int>::iterator`类型。C++提供了一种简洁的方法来减少冗长，即使用`auto`关键字。使用`auto`关键字，我们可以改进前面的代码如下：

```cpp
for (auto it = accounts.begin(); it != accounts.end();  ++ it) 
{ 
    it->second +=1; 
} 

```

auto 关键字指示编译器自动为我们推断类型。这将在我们编写的下一个类中特别有用。

## STL 摘要

与本书中涵盖的几乎每个 C++概念一样，STL 是一个庞大的主题。已经有整整一本书专门讨论 STL。然而，到目前为止，我们已经了解到足够的知识来构建一个使用 STL Map 来存储 SFML `Texture`对象的类。然后我们可以通过使用文件名作为键的键值对来检索/加载纹理。

为什么我们要增加这种额外的复杂性，而不是像到目前为止一样继续使用`Texture`类，随着我们的进行，这将变得明显。

# TextureHolder 类

成千上万的僵尸代表了一个新的挑战。不仅加载、存储和操作三种不同僵尸纹理的成千上万个副本会占用大量内存，还会占用大量处理能力。我们将创建一个新类型的类来解决这个问题，并允许我们只存储每种纹理的一个副本。

我们还将以这样的方式编写类，使得它只能有一个实例。这种类型的类被称为**单例**。

单例是一种设计模式，一种已被证明有效的代码结构方式。

此外，我们还将编写类，以便可以直接通过类名在我们的游戏代码中的任何地方使用它，而无需访问实例。

## 编写 TextureHolder 头文件

创建新的头文件。在**解决方案资源管理器**中右键单击**头文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，选择（通过左键单击）**头文件（** `.h` **）**，然后在**名称**字段中输入`TextureHolder.h`。

将以下代码添加到`TextureHolder.h`文件中，然后我们可以讨论它：

```cpp
#pragma once 
#ifndef TEXTURE_HOLDER_H 
#define TEXTURE_HOLDER_H 

#include <SFML/Graphics.hpp> 
#include <map> 

using namespace sf; 
using namespace std; 

class TextureHolder 
{ 
private: 
   // A map container from the STL, 
   // that holds related pairs of String and Texture 
   std::map<std::string, Texture> m_Textures; 

   // A pointer of the same type as the class itself 
   // the one and only instance 
   static TextureHolder* m_s_Instance; 

public: 
   TextureHolder(); 
   static Texture& GetTexture(string const& filename); 

}; 

#endif 

```

在前面的代码中，注意我们为 STL 中的`map`包含了一个包含指令。我们声明了一个包含 String 和 SFML `Texture`键值对的`map`。这个`map`被称为`m_Textures`。

在前面的代码中，接下来是这行：

```cpp
static TextureHolder* m_s_Instance; 

```

前一行代码非常有趣。我们声明了一个指向`TextureHolder`类型对象的静态指针，称为`m_s_Instance`。这意味着`TextureHolder`类有一个与自身相同类型的对象。不仅如此，因为它是静态的，所以可以通过类本身使用，而无需类的实例。当我们编写相关的`.cpp`文件时，我们将看到如何使用它。

在类的`public`部分，我们有构造函数`TextureHolder`的原型。构造函数不带参数，并且像通常一样没有返回类型。这与默认构造函数相同。我们将使用定义来覆盖默认构造函数，使我们的单例工作如我们所希望的那样。

我们还有另一个名为`GetTexture`的函数。让我们再次看一下签名，并分析到底发生了什么：

```cpp
static Texture& GetTexture(string const& filename); 

```

首先，注意函数返回一个`Texture`的引用。这意味着`GetTexture`将返回一个引用，这是有效的，因为它避免了对可能是相当大的图形进行复制。还要注意函数声明为`static`。这意味着该函数可以在没有类实例的情况下使用。该函数以`String`作为常量引用作为参数。这样做的效果是双重的。首先，操作是有效的，其次，因为引用是常量的，所以它是不可改变的。

## 编写 TextureHolder 函数定义

现在我们可以创建一个新的`.cpp`文件，其中包含函数定义。这将使我们能够看到我们新类型的函数和变量背后的原因。在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加 | 新项目...**。在**添加新项**窗口中，通过左键单击突出显示**C++文件**（**`.cpp`**），然后在**名称**字段中键入`TextureHolder.cpp`。最后，单击**添加**按钮。我们现在准备编写类的代码。

添加以下代码，然后我们可以讨论它：

```cpp
#include "stdafx.h" 
#include "TextureHolder.h" 

// Include the "assert feature" 
#include <assert.h> 

TextureHolder* TextureHolder::m_s_Instance = nullptr; 

TextureHolder::TextureHolder() 
{ 
   assert(m_s_Instance == nullptr); 
   m_s_Instance = this; 
} 

```

在前面的代码中，我们将指向`TextureHolder`类型的指针初始化为`nullptr`。在构造函数中，代码`assert(m_s_Instance == nullptr)`确保`m_s_Instance`等于`nullptr`。如果不是，则游戏将退出执行。然后代码`m_s_Instance = this`将指针分配给此实例。现在考虑一下这段代码发生在哪里。代码在构造函数中。构造函数是我们从类中创建对象实例的方式。因此，实际上我们现在有一个指向`TextureHolder`的指针，指向自身的唯一实例。

将最后一部分代码添加到`TextureHolder.cpp`文件中。接下来的注释比代码更多。在添加代码时，请检查代码并阅读注释，然后我们可以一起讨论：

```cpp
sf::Texture& TextureHolder::GetTexture(std::string const& filename) 
{ 
   // Get a reference to m_Textures using m_S_Instance 
   auto& m = m_s_Instance->m_Textures; 
   // auto is the equivalent of map<string, Texture> 

   // Create an iterator to hold a key-value-pair (kvp) 
   // and search for the required kvp 
   // using the passed in filename 
   auto keyValuePair = m.find(filename); 
   // auto is equivelant of map<string, Texture>::iterator 

   // Did we find a match? 
   if (keyValuePair != m.end()) 
   { 
      // Yes 
      // Return the texture, 
      // the second part of the kvp, the texture 
      return keyValuePair->second; 
   } 
   else 
   { 
      // Filename not found 
      // Create a new key value pair using the filename 
      auto& texture = m[filename]; 
      // Load the texture from file in the usual way 
      texture.loadFromFile(filename); 

      // Return the texture to the calling code 
      return texture; 
   } 
} 

```

您可能会注意到前面代码中的第一件事是`auto`关键字。`auto`关键字在前一节中有解释。

### 提示

如果您想知道`auto`替换的实际类型是什么，请看一下前面代码中每次使用`auto`后面的注释。

在代码的开头，我们获取了对`m_textures`的引用。然后我们尝试获取一个迭代器，该迭代器表示传入的文件名（`filename`）所代表的键值对。如果我们找到匹配的键，我们返回`return keyValuePair->second`的纹理。否则，我们将纹理添加到`map`中，然后将其返回给调用代码。

诚然，`TextureHolder`类引入了许多新概念（单例、`static`函数、常量引用、`this`和`auto`关键字）和语法。再加上我们刚刚学习了指针和 STL，这一部分的代码可能有点令人生畏。

## TextureHolder 到底实现了什么？

重点是现在我们有了这个类，我们可以在代码中随意使用纹理，而不必担心内存不足或者在特定函数或类中访问特定纹理。我们很快就会看到如何使用`TextureHolder`。

# 构建一群僵尸

现在我们有了`TextureHolder`类，以确保我们的僵尸纹理易于获取，并且只加载到 GPU 一次，我们可以着手创建一整群僵尸。

我们将把僵尸存储在一个数组中，由于构建和生成一群僵尸的过程涉及相当多的代码行，因此将其抽象为一个单独的函数是一个很好的选择。很快我们将编写`CreateHorde`函数，但首先，当然，我们需要一个`Zombie`类。

## 编写 Zombie.h 文件

构建代表僵尸的类的第一步是在头文件中编写成员变量和函数原型。

在**解决方案资源管理器**中右键单击**头文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，突出显示（单击左键）**头文件（.h）**，然后在**名称**字段中键入`Zombie.h`。

将以下代码添加到`Zombie.h`文件中：

```cpp
#pragma once 
#include <SFML/Graphics.hpp> 

using namespace sf; 

class Zombie 
{ 
private: 
   // How fast is each zombie type? 
   const float BLOATER_SPEED = 40; 
   const float CHASER_SPEED = 80; 
   const float CRAWLER_SPEED = 20; 

   // How tough is each zombie type 
   const float BLOATER_HEALTH = 5; 
   const float CHASER_HEALTH = 1; 
   const float CRAWLER_HEALTH = 3; 

   // Make each zombie vary its speed slightly 
   const int MAX_VARRIANCE = 30; 
   const int OFFSET = 101 - MAX_VARRIANCE; 

   // Where is this zombie? 
   Vector2f m_Position; 

   // A sprite for the zombie 
   Sprite m_Sprite; 

   // How fast can this one run/crawl? 
   float m_Speed; 

   // How much health has it got? 
   float m_Health; 

   // Is it still alive? 
   bool m_Alive; 

   // Public prototypes go here 
}; 

```

先前的代码声明了`Zombie`类的所有私有成员变量。在先前的代码顶部，我们有三个常量变量来保存每种类型僵尸的速度。一个非常缓慢的**爬行者**，一个稍快的**膨胀者**，以及一个相当快的**追逐者**。我们可以尝试调整这三个常量的值，以帮助平衡游戏的难度级别。值得一提的是，这三个值仅用作每种僵尸类型速度的起始值。正如我们将在本章后面看到的，我们将从这些值中以一小百分比变化每个僵尸的速度。这样可以防止相同类型的僵尸在追逐玩家时聚集在一起。

接下来的三个常量确定了每种僵尸类型的生命值。请注意，膨胀者是最坚韧的，其次是爬行者。为了平衡，追逐者僵尸将是最容易被杀死的。

接下来我们有两个更多的常量`MAX_VARIANCE`和`OFFSET;`，这些将帮助我们确定每个僵尸的个体速度。当我们编写`Zombie.cpp`文件时，我们将看到具体如何做到这一点。

在这些常量之后，我们声明了一堆变量，这些变量应该看起来很熟悉，因为我们在`Player`类中有非常相似的变量。`m_Position`、`m_Sprite`、`m_Speed`和`m_Health`变量分别代表了僵尸对象的位置、精灵、速度和生命值。

最后，在先前的代码中，我们声明了一个布尔值`m_Alive`，当僵尸活着并追捕时为`true`，但当其生命值降到零时为`false`，它只是我们漂亮背景上的一滩血迹。

现在来完成`Zombie.h`文件。添加下面突出显示的函数原型，然后我们将讨论它们：

```cpp
   // Is it still alive? 
   bool m_Alive; 

   // Public prototypes go here
   public:
   // Handle when a bullet hits a zombie
   bool hit();

   // Find out if the zombie is alive
   bool isAlive();

   // Spawn a new zombie
   void spawn(float startX, float startY, int type, int seed);

   // Return a rectangle that is the position in the world
   FloatRect getPosition();

   // Get a copy of the sprite to draw
   Sprite getSprite();

   // Update the zombie each frame
   void update(float elapsedTime, Vector2f playerLocation); 

}; 

```

在先前的代码中，有一个`hit`函数，我们可以在僵尸被子弹击中时调用它。该函数可以采取必要的步骤，比如从僵尸身上减少生命值（减少`m_Health`的值）或者将其杀死（将`m_Alive`设置为 false）。

`isAlive`函数返回一个布尔值，让调用代码知道僵尸是活着还是死了。我们不希望对走过血迹时发生碰撞检测或从玩家身上减少生命值。

`spawn`函数接受一个起始位置、一个类型（爬行者、膨胀者或追逐者，用一个整数表示），以及一个种子，用于一些我们将在下一节中看到的随机数生成。

就像在`Player`类中一样，`Zombie`类有`getPosition`和`getSprite`函数，用于获取代表僵尸所占空间的矩形和可以在每一帧绘制的精灵。

上一个代码中的最后一个原型是`update`方法。我们可能已经猜到它会接收自上一帧以来的经过的时间，但也要注意它接收了一个名为`playerLocation`的`Vector2f`。这个向量确实是玩家中心的确切坐标。我们很快就会看到我们如何使用这个向量来追逐玩家。

## 编写 Zombie.cpp 文件

接下来我们将编写 Zombie 类的实际功能，即函数定义。

创建一个新的`.cpp`文件，其中包含函数定义。在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加 | 新项目...**。在**添加新项目**窗口中，通过左键单击**C++文件**（**`.cpp`**），然后在**名称**字段中键入`Zombie.cpp`。最后，单击**添加**按钮。我们现在准备好编写类了。

现在将以下代码添加到`Zombie.cpp`文件中：

```cpp
#include "stdafx.h" 
#include "zombie.h" 
#include "TextureHolder.h" 
#include <cstdlib> 
#include <ctime> 

using namespace std; 

```

首先添加必要的包含指令，然后添加`using namespace std`这一行。您可能还记得我们在一些情况下在对象声明前面加上了`std::`。这个`using`指令意味着我们在这个文件中的代码不需要这样做。

现在添加以下代码，这是`spawn`函数的定义。添加后，请仔细研究代码，然后我们将逐步讲解：

```cpp
void Zombie::spawn(float startX, float startY, int type, int seed) 
{ 

   switch (type) 
   { 
   case 0: 
      // Bloater 
      m_Sprite = Sprite(TextureHolder::GetTexture( 
         "graphics/bloater.png")); 

      m_Speed = 40; 
      m_Health = 5; 
      break; 

   case 1: 
      // Chaser 
      m_Sprite = Sprite(TextureHolder::GetTexture( 
         "graphics/chaser.png")); 

      m_Speed = 70; 
      m_Health = 1; 
      break; 

   case 2: 
      // Crawler 
      m_Sprite = Sprite(TextureHolder::GetTexture( 
         "graphics/crawler.png")); 

      m_Speed = 20; 
      m_Health = 3; 
      break; 
   } 

   // Modify the speed to make the zombie unique 
   // Every zombie is unique. Create a speed modifier 
   srand((int)time(0) * seed); 

   // Somewhere between 80 an 100 
   float modifier = (rand() % MAX_VARRIANCE) + OFFSET; 

   // Express this as a fraction of 1 
   modifier /= 100; // Now equals between .7 and 1 
   m_Speed *= modifier; 

   // Initialize its location 
   m_Position.x = startX; 
   m_Position.y = startY; 

   // Set its origin to its center 
   m_Sprite.setOrigin(25, 25); 

   // Set its position 
   m_Sprite.setPosition(m_Position); 
} 

```

函数的第一件事是基于传入的`int`类型进行`switch`。在`switch`块内，为每种僵尸类型都有一个 case。根据类型和相应的纹理，速度和生命值被初始化为相关的成员变量。

有趣的是，我们使用静态的`TextureHolder::GetTexture`函数来分配纹理。这意味着无论我们生成多少僵尸，GPU 的内存中最多只会有三种纹理。

前面代码的最后三行（不包括注释）分别执行以下操作：

+   用作参数传入的`seed`变量来初始化随机数生成器。

+   使用`rand`函数和`MAX_VARIANCE`和`OFFSET`常量声明和初始化`modifier`浮点变量。结果是一个介于零和一之间的分数，可以用来使每个僵尸的速度都是独特的。我们之所以要这样做，是因为我们不希望僵尸们太过拥挤。

+   现在我们可以将`m_Speed`乘以`modifier`，这样我们就得到了一个速度在这种特定类型的僵尸速度常量的`MAX_VARRIANCE`百分比内的僵尸。

解决了速度之后，我们将`startX`和`startY`中传入的位置分别赋给`m_Position.x`和`m_Position.y`。

前面列表中的最后两行代码设置了精灵的原点为中心，并使用`m_Position`向量来设置精灵的位置。

现在将以下代码添加到`Zombie.cpp`文件中，用于`hit`函数：

```cpp
bool Zombie::hit() 
{ 
   m_Health--; 

   if (m_Health < 0) 
   { 
      // dead 
      m_Alive = false; 
      m_Sprite.setTexture(TextureHolder::GetTexture( 
         "graphics/blood.png")); 

      return true;  
   } 

   // injured but not dead yet 
   return false; 
} 

```

`hit`函数非常简单。将`m_Health`减一，然后检查`m_Health`是否小于零。

如果小于零，将`m_Alive`设置为 false，将僵尸的纹理替换为血迹，并返回 true 给调用代码，这样它就知道僵尸现在已经死了。

如果僵尸幸存下来，返回 false。

添加下面的三个 getter 函数，它们只是将一个值返回给调用代码：

```cpp
bool Zombie::isAlive() 
{ 
   return m_Alive; 
} 

FloatRect Zombie::getPosition() 
{ 
   return m_Sprite.getGlobalBounds(); 
} 

Sprite Zombie::getSprite() 
{ 
   return m_Sprite; 
} 

```

前面的三个函数相当容易理解，也许除了`getPosition`函数使用`m_Sprite.getLocalBounds`函数来获取`FloatRect`之外，这个例外。这个函数返回给调用代码。

最后，为`Zombie`类添加`update`函数的代码；仔细查看代码，然后我们将逐步讲解：

```cpp
void Zombie::update(float elapsedTime,  
   Vector2f playerLocation) 
{ 
   float playerX = playerLocation.x; 
   float playerY = playerLocation.y; 

   // Update the zombie position variables 
   if (playerX > m_Position.x) 
   { 
      m_Position.x = m_Position.x +  
         m_Speed * elapsedTime; 
   } 

   if (playerY > m_Position.y) 
   { 
      m_Position.y = m_Position.y +  
         m_Speed * elapsedTime; 
   } 
   if (playerX < m_Position.x) 
   { 
      m_Position.x = m_Position.x -  
         m_Speed * elapsedTime; 
   } 

   if (playerY < m_Position.y) 
   { 
      m_Position.y = m_Position.y -  
         m_Speed * elapsedTime; 
   } 

   // Move the sprite 
   m_Sprite.setPosition(m_Position); 

   // Face the sprite in the correct direction 
   float angle = (atan2(playerY - m_Position.y, 
      playerX - m_Position.x) 
      * 180) / 3.141; 

   m_Sprite.setRotation(angle); 

} 

```

首先将`playerLocation.x`和`playerLocation.y`复制到本地变量`playerX`和`playerY`中。

接下来有四个`if`语句。它们测试僵尸是否在当前玩家位置的左侧、右侧、上方或下方。这四个`if`语句在评估为`true`时，使用通常的公式`speed * time`来适当地调整僵尸的`m_Position.x`和`m_Position.y`值。更具体地说，代码是`m_Speed * elapsedTime`。

在四个`if`语句之后，`m_Sprite`被移动到它的新位置。

然后我们使用与之前用于玩家和鼠标指针的相同计算；不过这次是用于僵尸和玩家。这个计算找到了面向玩家的僵尸所需的角度。

最后，我们调用`m_Sprite.setRotation`来实际旋转僵尸精灵。请记住，这个函数将在游戏的每一帧中为每个（活着的）僵尸调用。

## 使用 Zombie 类创建一个僵尸群

现在我们有了一个类来创建一个活着的、攻击的和可杀死的僵尸，我们想要生成一整群它们。

为了实现这一点，我们将编写一个单独的函数，并使用指针，以便我们可以引用在`main`中声明但在不同范围内配置的我们的僵尸群。

在 Visual Studio 中打开`ZombieArena.h`文件，并添加下面显示的突出显示的代码行：

```cpp
#pragma once 
#include "Zombie.h" 

using namespace sf; 

int createBackground(VertexArray& rVA, IntRect arena); 
Zombie* createHorde(int numZombies, IntRect arena);

```

现在我们有了一个原型，我们可以编写函数定义了。

创建一个新的`.cpp`文件，其中包含函数定义。在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加 | 新建项...**。在**添加新项**窗口中，选择（通过左键单击）**C++文件**（`.cpp`），然后在**名称**字段中键入`CreateHorde.cpp`。最后，单击**添加**按钮。

将下面显示的代码添加到`CreateHorde.cpp`文件中并学习它。之后，我们将把它分解成块并讨论它：

```cpp
#include "stdafx.h" 
#include "ZombieArena.h" 
#include "Zombie.h" 

Zombie* createHorde(int numZombies, IntRect arena)  
{ 
   Zombie* zombies = new Zombie[numZombies]; 

   int maxY = arena.height - 20; 
   int minY = arena.top + 20; 
   int maxX = arena.width - 20; 
   int minX = arena.left + 20; 

   for (int i = 0; i < numZombies; i++) 
   { 

      // Which side should the zombie spawn 
      srand((int)time(0) * i); 
      int side = (rand() % 4); 
      float x, y; 

      switch (side) 
      { 
      case 0: 
         // left 
         x = minX; 
         y = (rand() % maxY) + minY; 
         break; 

      case 1: 
         // right 
         x = maxX; 
         y = (rand() % maxY) + minY; 
         break; 

      case 2: 
         // top 
         x = (rand() % maxX) + minX; 
         y = minY; 
         break; 

      case 3: 
         // bottom 
         x = (rand() % maxX) + minX; 
         y = maxY; 
         break; 
      } 

      // Bloater, crawler or runner 
      srand((int)time(0) * i * 2); 
      int type = (rand() % 3); 

      // Spawn the new zombie into the array 
      zombies[i].spawn(x, y, type, i); 

   } 
   return zombies; 
} 

```

让我们再次逐步查看所有以前的代码。

首先我们添加了现在熟悉的包含指令：

```cpp
#include "stdafx.h" 
#include "ZombieArena.h" 
#include "Zombie.h" 

```

接下来是函数签名。请注意，函数必须返回一个指向`Zombie`对象的指针。我们将创建一个`Zombie`对象的数组。一旦我们创建了这个僵尸群，我们将返回这个数组。当我们返回数组时，实际上是返回数组的第一个元素的地址。这与本章前面学到的内容相同，也就是指针。函数签名还显示我们有两个参数。第一个参数`numZombies`将是当前僵尸群所需的僵尸数量，第二个参数`arena`是一个`IntRect`，用于保存当前竞技场的大小，以便创建这个僵尸群。

在函数签名之后，我们声明了一个名为`zombies`的指向`Zombie`类型的指针，并用数组的第一个元素的内存地址进行初始化，这个数组是我们在堆上动态分配的。

```cpp
Zombie* createHorde(int numZombies, IntRect arena)  
{ 
   Zombie* zombies = new Zombie[numZombies]; 

```

接下来的代码简单地将竞技场的边界复制到`maxY`、`minY`、`maxX`和`minX`中。我们从右边和底部减去 20 像素，同时在顶部和左边加上 20 像素。我们使用这四个局部变量来帮助定位每个僵尸。我们进行了 20 像素的调整，以防止僵尸出现在墙上。

```cpp
int maxY = arena.height - 20; 
int minY = arena.top + 20; 
int maxX = arena.width - 20; 
int minX = arena.left + 20; 

```

现在我们进入一个`for`循环，该循环将遍历从零到`numZombies`的每个`Zombie`对象在僵尸数组中的元素：

```cpp
for (int i = 0; i < numZombies; i++) 

```

在`for`循环内，代码的第一件事是初始化随机数生成器，然后生成一个介于零和三之间的随机数。这个数字存储在`side`变量中。我们将使用`side`变量来决定僵尸是在竞技场的左侧、顶部、右侧还是底部生成。我们还声明了两个`int`变量`x`和`y`。这两个变量将临时保存当前僵尸的实际水平和垂直坐标。

```cpp
// Which side should the zombie spawn 
srand((int)time(0) * i); 
int side = (rand() % 4); 
float x, y; 

```

在`for`循环中，我们有一个`switch`块，包含四个`case`语句。注意`case`语句分别为 0、1、2 和 3，而 switch 语句中的参数是 side。在每个 case 块内，我们使用一个预定值（minX、maxX、minY 或 maxY）和一个随机生成的值来初始化 x 和 y。仔细观察每个预定值和随机值的组合，你会发现它们适合将当前僵尸随机放置在竞技场的左侧、顶部、右侧或底部。这样做的效果是，每个僵尸可以在竞技场的外边缘随机生成：

```cpp
switch (side) 
{ 
   case 0: 
      // left 
      x = minX; 
      y = (rand() % maxY) + minY; 
      break; 

   case 1: 
      // right 
      x = maxX; 
      y = (rand() % maxY) + minY; 
      break; 

   case 2: 
      // top 
      x = (rand() % maxX) + minX; 
      y = minY; 
      break; 

   case 3: 
      // bottom 
      x = (rand() % maxX) + minX; 
      y = maxY; 
      break;       
} 

```

在`for`循环内部，我们再次初始化随机数生成器，并生成一个介于 0 和 2 之间的随机数。我们将这个数字存储在 type 变量中。type 变量将决定当前僵尸是 Chaser、Bloater 还是 Crawler。

确定类型后，我们在`zombies`数组中的当前`Zombie`对象上调用`spawn`函数。作为提醒，传入`spawn`函数的参数确定了僵尸的起始位置和僵尸的类型。看似任意的`i`被传入，因为它被用作一个唯一的种子，可以在适当的范围内随机变化僵尸的速度。这样可以防止我们的僵尸**聚集**在一起，而不是形成一群：

```cpp
// Bloater, crawler or runner 
srand((int)time(0) * i * 2); 
int type = (rand() % 3); 

// Spawn the new zombie into the array 
zombies[i].spawn(x, y, type, i); 

```

`for`循环对`numZombies`中包含的每个僵尸重复一次，然后返回数组。再次提醒，数组只是它自身的第一个元素的地址。数组是在堆上动态分配的，因此在函数返回后它将持续存在：

```cpp
return zombies; 

```

现在我们可以让僵尸活过来。

## 让僵尸群复活

我们有一个`Zombie`类和一个函数来随机生成一群僵尸。我们有`TextureHolder`单例作为一种简洁的方式来保存仅三个纹理，可以用于数十甚至数千个僵尸。现在我们可以在`main`中将僵尸群添加到我们的游戏引擎中。

添加以下突出显示的代码以包含`TextureHolder`类。然后，在`main`内部，我们初始化了唯一的`TextureHolder`实例，可以在游戏的任何地方使用：

```cpp
#include "stdafx.h" 
#include <SFML/Graphics.hpp> 
#include "ZombieArena.h" 
#include "Player.h" 
#include "TextureHolder.h" 

using namespace sf; 

int main() 
{ 
 // Here is the instance of TextureHolder
   TextureHolder holder; 

   // The game will always be in one of four states 
   enum class State { PAUSED, LEVELING_UP, GAME_OVER, PLAYING }; 
   // Start with the GAME_OVER state 
   State state = State::GAME_OVER; 

```

接下来几行突出显示的代码声明了一些控制变量，用于波开始时僵尸的数量、仍需杀死的僵尸数量，当然还有一个名为`zombies`的`Zombie`指针，我们将其初始化为`nullptr`。

添加突出显示的代码：

```cpp
// Create the background 
VertexArray background; 
// Load the texture for our background vertex array 
Texture textureBackground; 
textureBackground.loadFromFile("graphics/background_sheet.png"); 

// Prepare for a horde of zombies
int numZombies;
int numZombiesAlive;
Zombie* zombies = nullptr; 

// The main game loop 
while (window.isOpen()) 

```

接下来，在`LEVELING_UP`部分嵌套的`PLAYING`部分中，我们添加以下代码：

+   将`numZombies`初始化为`10`。随着项目的进展，这将最终变得动态，并基于当前波数。

+   删除任何已分配的内存，否则每次调用`createHorde`都会占用越来越多的内存，而不释放先前僵尸群的内存

+   然后调用`createHorde`并将返回的内存地址分配给`zombies`

+   将`zombiesAlive`初始化为`numZombies`，因为在这一点上我们还没有杀死任何僵尸

添加我们刚刚讨论过的突出显示的代码：

```cpp
if (state == State::PLAYING) 
{ 
   // Prepare thelevel 
   // We will modify the next two lines later 
   arena.width = 500; 
   arena.height = 500; 
   arena.left = 0; 
   arena.top = 0; 

   // Pass the vertex array by reference  
   // to the createBackground function 
   int tileSize = createBackground(background, arena); 

   // Spawn the player in the middle of the arena 
   player.spawn(arena, resolution, tileSize); 

 // Create a horde of zombies
   numZombies = 10;

   // Delete the previously allocated memory (if it exists)
   delete[] zombies;
   zombies = createHorde(numZombies, arena);
   numZombiesAlive = numZombies; 

   // Reset the clock so there isn't a frame jump 
   clock.restart(); 
} 

```

现在将以下突出显示的代码添加到`ZombieArena.cpp`文件中：

```cpp
/* 
 **************** 
 UPDATE THE FRAME 
 **************** 
 */ 
if (state == State::PLAYING) 
{ 
   // Update the delta time 
   Time dt = clock.restart(); 
   // Update the total game time 
   gameTimeTotal += dt; 
   // Make a decimal fraction of 1 from the delta time 
   float dtAsSeconds = dt.asSeconds(); 

   // Where is the mouse pointer 
   mouseScreenPosition = Mouse::getPosition(); 

   // Convert mouse position to world coordinates of mainView 
   mouseWorldPosition = window.mapPixelToCoords( 
      Mouse::getPosition(), mainView); 

   // Update the player 
   player.update(dtAsSeconds, Mouse::getPosition()); 

   // Make a note of the players new position 
   Vector2f playerPosition(player.getCenter()); 

   // Make the view center around the player           
   mainView.setCenter(player.getCenter()); 

 // Loop through each Zombie and update them
   for (int i = 0; i < numZombies; i++)
   {
     if (zombies[i].isAlive())
     {
        zombies[i].update(dt.asSeconds(), playerPosition);
     }
   } 

}// End updating the scene 

```

新代码所做的一切就是循环遍历僵尸数组，检查当前僵尸是否还活着，如果是的话，就用必要的参数调用它的`update`函数。

添加以下代码来绘制所有的僵尸：

```cpp
/* 
 ************** 
 Draw the scene 
 ************** 
 */ 

if (state == State::PLAYING) 
{ 
   window.clear(); 

   // set the mainView to be displayed in the window 
   // And draw everything related to it 
   window.setView(mainView); 

   // Draw the background 
   window.draw(background, &textureBackground); 

 // Draw the zombies
   for (int i = 0; i < numZombies; i++)
   {
     window.draw(zombies[i].getSprite());
   } 

   // Draw the player 
   window.draw(player.getSprite()); 
} 

```

先前的代码循环遍历所有的僵尸，并调用`getSprite`函数以允许`draw`方法发挥作用。我们不检查僵尸是否还活着，因为即使僵尸已经死亡，我们也希望绘制血迹。

在主函数的末尾，我们确保删除了我们的指针，尽管从技术上讲这并非必要，因为游戏即将退出，操作系统将在`return 0`语句之后回收所有使用的内存：

```cpp
   }// End of main game loop 

 // Delete the previously allocated memory (if it exists)
   delete[] zombies; 

   return 0; 
} 

```

您可以运行游戏，看到僵尸在竞技场的边缘生成。它们会立即以各自的速度直奔玩家而去。为了好玩，我增加了竞技场的大小，并将僵尸数量增加到 1000。

![将僵尸群带回生命（重新活过来）](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_08_001.jpg)

这将以失败告终！

请注意，由于我们在第六章中编写的代码，您还可以使用**Enter**键暂停和恢复僵尸群的袭击：*面向对象编程，类和 SFML 视图*。

# 使用`TextureHolder`类加载所有纹理

既然我们有了`TextureHolder`类，我们可能会一致地使用它来加载所有的纹理。让我们对加载背景精灵表和玩家纹理的现有代码进行一些非常小的修改。

## 更改背景获取纹理的方式

在`ZombieArena.cpp`文件中，找到这段代码：

```cpp
// Load the texture for our background vertex array 
Texture textureBackground;
textureBackground.loadFromFile("graphics/background_sheet.png");

```

删除先前突出显示的代码，并用以下突出显示的代码替换，该代码使用我们的新`TextureHolder`类：

```cpp
// Load the texture for our background vertex array 
Texture textureBackground = TextureHolder::GetTexture(
  "graphics/background_sheet.png");

```

## 更改 Player 获取纹理的方式

在`Player.cpp`文件中，在构造函数内，找到这段代码：

```cpp
#include "stdafx.h" 
#include "player.h" 

Player::Player() 
{ 
   m_Speed = START_SPEED; 
   m_Health = START_HEALTH; 
   m_MaxHealth = START_HEALTH; 

   // Associate a texture with the sprite 
   // !!Watch this space!! 
 m_Texture.loadFromFile("graphics/player.png");
   m_Sprite.setTexture(m_Texture); 

   // Set the origin of the sprite to the center,  
   // for smooth rotation 
   m_Sprite.setOrigin(25, 25); 
} 

```

删除先前突出显示的代码，并用使用我们的新`TextureHolder`类的以下代码替换。此外，添加包含指令以将`TextureHolder`头文件添加到文件中。新代码如下所示，突出显示在上下文中：

```cpp
#include "stdafx.h" 
#include "player.h" 
#include "TextureHolder.h" 

Player::Player() 
{ 
   m_Speed = START_SPEED; 
   m_Health = START_HEALTH; 
   m_MaxHealth = START_HEALTH; 

   // Associate a texture with the sprite 
   // !!Watch this space!! 
 m_Sprite = Sprite(TextureHolder::GetTexture(
      "graphics/player.png")); 

   // Set the origin of the sprite to the center,  
   // for smooth rotation 
   m_Sprite.setOrigin(25, 25); 
} 

```

从现在开始，我们将使用`TextureHolder`类加载所有纹理。

# 常见问题

以下是您可能会想到的一些问题：

Q）指针和引用有什么区别？

A）指针就像带有助推器的引用。指针可以更改指向不同变量（内存地址），以及指向自由存储器上动态分配的内存。

Q）数组和指针有什么关系？

A）数组实际上是指向它们第一个元素的常量指针。

Q）您能提醒我一下`new`关键字和内存泄漏吗？

A）当我们使用`new`关键字在自由存储器上使用内存时，即使创建它的函数已经返回并且所有局部变量都消失了，它仍然存在。当我们使用自由存储器上的内存时，我们必须释放它。因此，如果我们使用自由存储器上的内存，我们希望它在函数的生命周期之外持续存在，我们必须确保保留指向它的指针，否则我们将泄漏内存。这就像把所有的东西放在我们的房子里然后忘记我们住在哪里一样！当我们从`createHorde`返回僵尸数组时，就像是把接力棒（内存地址）从`createHorde`传递给`main`。这就像是说好的，这是你的一群僵尸 - 现在它们是你的责任了。我们不希望我们的 RAM 中有任何泄漏的僵尸，所以我们必须记得在指向动态分配内存的指针上调用`delete`。

# 总结

您可能已经注意到，这些僵尸似乎并不那么危险。它们只是漂浮在玩家身边，而不留下任何伤痕。目前这是件好事，因为玩家没有办法自卫。

在下一章中，我们将制作另外两个类。一个用于弹药和生命值的拾取，另一个用于玩家可以射击的子弹。在完成这些之后，我们将学习如何检测碰撞，以便子弹和僵尸造成一些伤害，并且玩家可以收集拾取物品。


# 第九章：碰撞检测、拾取物品和子弹

到目前为止，我们已经实现了游戏的主要视觉方面。我们有一个可控的角色在一个充满追逐他的僵尸的竞技场中奔跑。问题是它们彼此之间没有互动。僵尸可以毫无阻碍地穿过玩家。我们需要检测僵尸和玩家之间的碰撞。

如果僵尸能够伤害并最终杀死玩家，那么给玩家一些子弹是公平的。然后我们需要确保子弹能够击中并杀死僵尸。

同时，如果我们正在为子弹、僵尸和玩家编写碰撞检测代码，那么现在是添加用于健康和弹药拾取的类的好时机。

以下是我们将要做的事情以及我们将涵盖的主题顺序：

+   射击子弹

+   添加准星并隐藏鼠标指针

+   生成拾取物品

+   检测碰撞

# 编写子弹类

我们将使用 SFML 的`RectangleShape`类来直观表示子弹。我们将编写一个`Bullet`类，其中包含一个`RectangleShape`成员以及其他成员数据和函数。我们将分几步向游戏中添加子弹：

1.  首先，我们将编写`Bullet.h`文件。这将显示成员数据的所有细节和函数的原型。

1.  接下来，我们将编写`Bullet.cpp`文件，其中当然将包含`Bullet`类所有函数的定义。当我们逐步进行时，我将解释`Bullet`类型的对象将如何工作和被控制。

1.  最后，在`main`函数中，我们将声明一个完整的子弹数组。我们还将实现射击的控制方案，管理玩家剩余的弹药，并进行重新加载。

让我们从第一步开始。

## 编写子弹头文件

要创建新的头文件，**右键单击** **解决方案资源管理器**中的**头文件**，然后选择**添加 | 新项目...**。在**添加新项目**窗口中，通过左键单击**头文件（**`.h`**）**，然后在**名称**字段中键入`Bullet.h`。

在`Bullet.h`文件中，添加以下私有成员变量以及`Bullet`类声明。然后我们可以运行并解释它们的用途：

```cpp
#pragma once 
#include <SFML/Graphics.hpp> 

using namespace sf; 

class Bullet 
{ 
private: 
   // Where is the bullet? 
   Vector2f m_Position; 

   // What each bullet looks like 
   RectangleShape m_BulletShape; 

   // Is this bullet currently whizzing through the air 
   bool m_InFlight = false; 

   // How fast does a bullet travel? 
   float m_BulletSpeed = 1000; 

   // What fraction of 1 pixel does the bullet travel,  
   // Horizontally and vertically each frame? 
   // These values will be derived from m_BulletSpeed 
   float m_BulletDistanceX; 
   float m_BulletDistanceY; 

   // Some boundaries so the bullet doesn't fly forever 
   float m_MaxX; 
   float m_MinX; 
   float m_MaxY; 
   float m_MinY; 

// Public function prototypes go here 

```

在前面的代码中，第一个成员是一个名为`m_Position`的`Vector2f`，它将保存子弹在游戏世界中的位置。

接下来，我们声明了一个名为`m_BulletShape`的`RectangleShape`，因为我们为每颗子弹使用了一个简单的非纹理图形，有点像我们在 Timber!!!中为时间条所做的那样。

代码然后声明了一个`Boolean m_InFlight`，它将跟踪子弹当前是否在空中飞行。这将使我们能够决定是否需要在每帧调用其`update`函数，以及我们是否需要运行碰撞检测检查。

`float`变量`m_BulletSpeed`将（你可能猜到了）保存子弹的像素速度。它被初始化为`1000`的值，这有点随意，但效果很好。

接下来我们有另外两个`float`变量，`m_BulletDistanceX`和`m_BulletDistanceY`。由于移动子弹的计算比移动僵尸或玩家的计算稍微复杂一些，我们将受益于这两个变量，我们将对它们进行计算。它们将用于决定每帧子弹位置的水平和垂直变化。

最后，对于前面的代码，我们有另外四个`float`变量（`m_MaxX`、`m_MinX`、`m_MaxY`和`m_MinY`），它们将稍后初始化以保存子弹的水平和垂直位置的最大和最小值。

很可能有些变量的需求并不立即显而易见，但当我们在`Bullet.cpp`文件中看到它们各自发挥作用时，它们将变得更清晰。

现在将所有公共函数原型添加到`Bullet.h`文件中：

```cpp
// Public function prototypes go here 
public:
   // The constructor
   Bullet();

   // Stop the bullet
   void stop();

   // Returns the value of m_InFlight
   bool isInFlight();

   // Launch a new bullet
   void shoot(float startX, float startY,
     float xTarget, float yTarget);

   // Tell the calling code where the bullet is in the world
   FloatRect getPosition();

   // Return the actual shape (for drawing)
   RectangleShape getShape();

   // Update the bullet each frame
   void update(float elapsedTime);

```

让我们依次审查每个函数，然后我们可以继续编写它们的定义。

首先是`Bullet`函数，当然是构造函数。在这个函数中，我们将为每个`Bullet`实例设置好准备行动。

`stop`函数将在子弹已经在行动但需要停止时被调用。

`isInFlight`函数返回一个布尔值，用于测试子弹当前是否在飞行中。

`shoot`函数的用途可以从其名称中得知，但它的工作方式值得讨论。现在，只需注意它有四个`float`参数将被传入。这四个值代表子弹的起始（玩家所在位置）水平和垂直位置，以及垂直和水平目标位置（准星所在位置）。

`getPosition`函数返回一个`FloatRect`，表示子弹的位置。这个函数将用于检测与僵尸的碰撞。您可能还记得来自第八章：*指针、标准模板库和纹理管理*中，僵尸也有一个`getPosition`函数。

接下来我们有`getShape`函数，它返回一个`RectangleShape`类型的对象。正如我们讨论过的，每个子弹在视觉上都由一个`RectangleShape`对象表示。因此，`getShape`函数将被用来获取`RectangleShape`当前状态的副本，以便绘制它。

最后，也希望如预期的那样，有`update`函数，它有一个`float`参数，表示自上次调用`update`以来经过的一秒钟的时间。`update`方法将在每一帧改变子弹的位置。

让我们来看看并编写函数定义。

## 编写子弹源文件

现在我们可以创建一个新的`.cpp`文件，其中包含函数定义。在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加 | 新项目...**。在**添加新项目**窗口中，通过左键单击**C++文件**（`.cpp`）来突出显示，然后在**名称**字段中键入`Bullet.cpp`。最后，单击**添加**按钮。我们现在准备好编写类了。

添加以下代码，这是包含指令和构造函数。我们知道这是构造函数，因为函数的名称与类名相同：

```cpp
#include "stdafx.h" 
#include "bullet.h" 

// The constructor 
Bullet::Bullet() 
{ 
   m_BulletShape.setSize(sf::Vector2f(2, 2)); 
}
```

`Bullet`构造函数唯一需要做的事情就是设置`m_BulletShape`的大小，这是`RectangleShape`对象。代码将大小设置为两像素乘以两像素。

接下来是更实质性的`shoot`函数。将以下代码添加到`Bullet.cpp`文件中，研究它，然后我们可以讨论它：

```cpp
void Bullet::shoot(float startX, float startY, 
   float targetX, float targetY) 
{ 
   // Keep track of the bullet 
   m_InFlight = true; 
   m_Position.x = startX; 
   m_Position.y = startY; 

   // Calculate the gradient of the flight path 
   float gradient = (startX - targetX) / (startY - targetY); 

   // Any gradient less than 1 needs to be negative 
   if (gradient < 0) 
   { 
      gradient *= -1; 
   } 

   // Calculate the ratio between x and y 
   float ratioXY = m_BulletSpeed / (1 + gradient); 

   // Set the "speed" horizontally and vertically 
   m_BulletDistanceY = ratioXY; 
   m_BulletDistanceX = ratioXY * gradient; 

   // Point the bullet in the right direction 
   if (targetX < startX) 
   { 
      m_BulletDistanceX *= -1; 
   } 

   if (targetY < startY) 
   { 
      m_BulletDistanceY *= -1; 
   } 

   // Set a max range of 1000 pixels 
   float range = 1000; 
   m_MinX = startX - range; 
   m_MaxX = startX + range; 
   m_MinY = startY - range; 
   m_MaxY = startY + range; 

   // Position the bullet ready to be drawn 
   m_BulletShape.setPosition(m_Position); 

```

为了揭开`shoot`函数的神秘面纱，我们将把它分解并讨论我们刚刚添加的代码块。

首先让我们回顾一下签名。`shoot`函数接收子弹的起始和目标水平和垂直位置。调用代码将根据玩家精灵的位置和准星的位置提供这些值。这里是它的签名：

```cpp
void Bullet::shoot(float startX, float startY, float targetX, float targetY)
```

在`shoot`函数内部，我们将`m_InFlight`设置为`true`，并使用参数`startX`和`startY`定位子弹。这里是那段代码：

```cpp
// Keep track of the bullet 
m_InFlight = true; 
m_Position.x = startX; 
m_Position.y = startY;
```

现在我们使用一些简单的三角学来确定子弹的行进斜率。子弹的水平和垂直进展必须根据在子弹起始和目标之间绘制的线的斜率而变化。变化的速率不能相同，否则非常陡峭的射击将在水平位置到达之前到达垂直位置，对于较浅的射击则相反。

以下代码首先根据一条直线的方程推导出斜率。然后它检查斜率是否小于零，如果是，则乘以`-1`。这是因为传入的起始和目标坐标可以是负数或正数，我们总是希望每帧的进度量是正数。乘以`-1`只是将负数变成它的正数等价物，因为负数乘以负数得正数。实际的行进方向将在`update`函数中处理，通过在这个函数中得到的正值进行加减。

接下来，我们通过将我们的子弹速度（`m_BulletSpeed`）除以斜率加一来计算水平到垂直距离的比率。这将允许我们根据子弹所指向的目标，每帧正确地改变子弹的水平和垂直位置。

最后，在代码的这一部分，我们为`m_BulletDistanceY`和`m_BulletDistanceX`赋值：

```cpp
// Calculate the gradient of the flight path 
float gradient = (startX - targetX) / (startY - targetY); 

// Any gradient less than zero needs to be negative 
if (gradient < 0) 
{ 
   gradient *= -1; 
} 

// Calculate the ratio between x and y 
float ratioXY = m_BulletSpeed / (1 + gradient); 

// Set the "speed" horizontally and vertically 
m_BulletDistanceY = ratioXY; 
m_BulletDistanceX = ratioXY * gradient;
```

以下代码要简单得多。我们只是设置了子弹可以到达的最大水平和垂直位置。我们不希望子弹一直飞下去。我们将在`update`函数中看到这一点，我们会测试子弹是否已经超过了它的最大或最小位置：

```cpp
// Set a max range of 1000 pixels in any direction 
float range = 1000; 
m_MinX = startX - range; 
m_MaxX = startX + range; 
m_MinY = startY - range; 
m_MaxY = startY + range;
```

以下代码将代表子弹的**RectangleShape**移动到其起始位置。我们像以前经常做的那样使用`setPosition`函数：

```cpp
// Position the bullet ready to be drawn 
m_BulletShape.setPosition(m_Position);
```

接下来我们有四个简单直接的函数。添加`stop`，`isInFlight`，`getPosition`和`getShape`函数：

```cpp
void Bullet::stop() 
{ 
   m_InFlight = false; 
} 

bool Bullet::isInFlight() 
{ 
   return m_InFlight; 
} 

FloatRect Bullet::getPosition() 
{ 
   return m_BulletShape.getGlobalBounds(); 
} 

RectangleShape Bullet::getShape() 
{ 
   return m_BulletShape; 

```

`stop`函数只是将`m_InFlight`变量设置为`false`。`isInFlight`函数返回当前这个变量的值。所以我们可以看到`shoot`让子弹飞出去，`stop`让它停下来，`isInFlight`让我们知道当前的状态是什么。

`getPosition`函数返回一个`FloatRect`，我们将看到如何使用每个游戏对象的`FloatRect`来检测碰撞，很快就会看到。

最后，对于之前的代码，`getShape`返回一个`RectangleShape`，所以我们可以在每一帧中绘制子弹。

在我们开始使用`Bullet`对象之前，我们需要实现的最后一个函数是`update`。添加以下代码，研究一下，然后我们可以讨论一下：

```cpp
void Bullet::update(float elapsedTime) 
{ 
   // Update the bullet position variables 
   m_Position.x += m_BulletDistanceX * elapsedTime; 
   m_Position.y += m_BulletDistanceY * elapsedTime; 

   // Move the bullet 
   m_BulletShape.setPosition(m_Position); 

   // Has the bullet gone out of range? 
   if (m_Position.x < m_MinX || m_Position.x > m_MaxX || 
      m_Position.y < m_MinY || m_Position.y > m_MaxY) 
   { 
      m_InFlight = false; 
   } 
}
```

在`update`函数中，我们使用`m_BulletDistanceX`和`m_BulletDistanceY`乘以自上一帧以来的时间来移动子弹。记住，这两个变量的值是在`shoot`函数中计算的，并且表示移动子弹所需的斜率（彼此的比率）。然后我们使用`setPosition`函数来实际移动`RectangleShape`。

在`update`中我们做的最后一件事是测试子弹是否已经超过了它的最大射程。稍微复杂的`if`语句检查`m_Position.x`和`m_Position.y`与在`shoot`函数中计算的最大和最小值。这些最大和最小值存储在`m_MinX`，`m_MaxX`，`m_MinY`和`m_MaxY`中。如果测试为真，则`m_InFlight`设置为`false`。

`Bullet`类已经完成。现在我们可以看看如何在`main`函数中射击一些子弹。

# 让子弹飞

我们将通过以下六个步骤使子弹可用：

1.  为`Bullet`类添加必要的包含指令。

1.  添加一些控制变量和一个数组来保存一些`Bullet`实例。

1.  处理玩家按下*R*键重新装填。

1.  处理玩家按下鼠标左键发射子弹。

1.  在每一帧中更新所有正在飞行的子弹。

1.  在每一帧中绘制正在飞行中的子弹。

## 包含 Bullet 类

添加包含指令以使 Bullet 类可用：

```cpp
#include "stdafx.h" 
#include <SFML/Graphics.hpp> 
#include "ZombieArena.h" 
#include "Player.h" 
#include "TextureHolder.h" 
#include "Bullet.h" using namespace sf;
```

让我们继续下一步。

## 控制变量和子弹数组

这里有一些变量来跟踪子弹、弹夹大小、备用/剩余子弹、弹夹中的子弹、当前射速（每秒开始为一颗），以及上一颗子弹被射击的时间。

添加突出显示的代码，我们可以继续看到本节中所有这些变量的实际运行情况：

```cpp
// Prepare for a horde of zombies 
int numZombies; 
int numZombiesAlive; 
Zombie* zombies = NULL; 

// 100 bullets should do
Bullet bullets[100];
int currentBullet = 0;
int bulletsSpare = 24;
int bulletsInClip = 6;
int clipSize = 6;
float fireRate = 1;
// When was the fire button last pressed?
Time lastPressed; 

// The main game loop 
while (window.isOpen())
```

接下来，让我们处理玩家按下***R***键时会发生什么，这个键用于重新装弹。

## 重新装弹

现在我们处理与射击子弹相关的玩家输入。首先，我们将处理按下***R***键重新装弹。我们使用 SFML 事件来实现。

添加下面突出显示的代码块。为了确保代码放在正确的位置，提供了大量上下文来展示。研究代码，然后我们可以讨论它：

```cpp
// Handle events 
Event event; 
while (window.pollEvent(event)) 
{ 
   if (event.type == Event::KeyPressed) 
   { 
      // Pause a game while playing 
      if (event.key.code == Keyboard::Return && 
         state == State::PLAYING) 
      { 
         state = State::PAUSED; 
      } 

      // Restart while paused 
      else if (event.key.code == Keyboard::Return && 
         state == State::PAUSED) 
      { 
         state = State::PLAYING; 
         // Reset the clock so there isn't a frame jump 
         clock.restart(); 
      } 

      // Start a new game while in GAME_OVER state 
      else if (event.key.code == Keyboard::Return && 
         state == State::GAME_OVER) 
      { 
         state = State::LEVELING_UP; 
      } 

      if (state == State::PLAYING) 
      { 
 // Reloading
        if (event.key.code == Keyboard::R)
        {
           if (bulletsSpare >= clipSize)
           {
             // Plenty of bullets. Reload.
             bulletsInClip = clipSize;
             bulletsSpare -= clipSize;
           }
           else if (bulletsSpare > 0)
           {
             // Only few bullets left
             bulletsInClip = bulletsSpare;
             bulletsSpare = 0;
           }
           else
           {
             // More here soon?!
           }
       } 
      } 

   } 
}// End event polling
```

先前的代码嵌套在游戏循环的事件处理部分（`while(window.pollEvent)`）中，只有在游戏实际进行时执行的代码块内（`if(state == State::Playing)`）。很明显，我们不希望在游戏结束或暂停时玩家重新装弹，通过描述的新代码实现了这一点。

在新代码本身中，我们首先测试是否按下了**R**键，使用`if (event.key.code == Keyboard::R)`。一旦检测到按下**R**键，剩下的代码就会执行。以下是`if`、`else if`和`else`块的结构：

```cpp
if(bulletsSpare >= clipSize) 
   ... 
else if(bulletsSpare > 0) 
   ... 
else 
   ...
```

先前的结构允许我们处理三种可能的情况。

+   玩家按下了`R`，并且他们有比弹夹能装下的更多的备用子弹。在这种情况下，弹夹被重新填充，备用子弹的数量减少。

+   玩家有一些备用子弹，但不足以完全填满弹夹。在这种情况下，弹夹将填满玩家拥有的尽可能多的备用子弹，并且备用子弹的数量被设置为零。

+   玩家按下了 R，但他们没有备用子弹。对于这种情况，我们实际上不需要改变变量。但是当我们在第十一章中实现声音时，我们会在这里播放声音效果，所以我们留下了空的`else`块。

最后，让我们实际射击一颗子弹。

## 射击子弹

接下来，我们可以处理按下鼠标左键来实际射击子弹。添加下面突出显示的代码并仔细研究它：

```cpp
   if (Keyboard::isKeyPressed(Keyboard::D)) 
   { 
      player.moveRight(); 
   } 
   else 
   { 
      player.stopRight(); 
   } 

 // Fire a bullet
   if (Mouse::isButtonPressed(sf::Mouse::Left))
   {
     if (gameTimeTotal.asMilliseconds()
        - lastPressed.asMilliseconds()
        > 1000 / fireRate && bulletsInClip > 0)
     {

        // Pass the center of the player
        // and the center of the crosshair
        // to the shoot function
        bullets[currentBullet].shoot(
           player.getCenter().x, player.getCenter().y,
           mouseWorldPosition.x, mouseWorldPosition.y);

        currentBullet++;
        if (currentBullet > 99)
        {
           currentBullet = 0;
        }
        lastPressed = gameTimeTotal;
        bulletsInClip--;
     }
   }// End fire a bullet
}// End WASD while playing

```

所有先前的代码都包裹在一个`if`语句中，只有当按下鼠标左键时执行，`if (Mouse::isButtonPressed(sf::Mouse::Left))`。请注意，即使玩家只是按住按钮，代码也会重复执行。我们现在要讨论的代码控制射速。

在先前的代码中，我们检查游戏中经过的总时间（`gameTimeTotal`）减去玩家上次射击子弹的时间（`lastPressed`）是否大于`1000`除以当前射速，以及玩家弹夹中至少有一颗子弹。我们使用`1000`是因为这是一秒钟内的毫秒数。

如果这个测试成功，那么实际射击子弹的代码就会执行。射击子弹很容易，因为我们在`Bullet`类中已经做了所有的工作。我们只需在`bullets`数组中的当前子弹上调用`shoot`。我们传入玩家和准星的当前水平和垂直位置。子弹将由`Bullet`类的`shoot`函数中的代码进行配置和发射。

我们所要做的就是跟踪子弹数组。首先我们增加`currentBullet`变量。然后我们检查是否用语句`if (currentBullet > 99)`发射了最后一颗子弹（`99`）。如果是最后一颗子弹，我们将`currentBullet`设置为零。如果不是最后一颗子弹，那么下一颗子弹就准备好了，只要射速允许并且玩家按下鼠标左键。

最后，对于之前的代码，我们将子弹发射的时间存储在`lastPressed`中，并减少`bulletsInClip`。

现在我们可以每帧更新每一颗子弹。

## 每帧更新子弹

添加高亮代码来循环遍历子弹数组，检查子弹是否在飞行，如果是，调用它的更新函数：

```cpp
   // Loop through each Zombie and update them 
   for (int i = 0; i < numZombies; i++) 
   { 
      if (zombies[i].isAlive()) 
      { 
         zombies[i].update(dt.asSeconds(), playerPosition); 
      } 
   } 

 // Update any bullets that are in-flight
   for (int i = 0; i < 100; i++)
   {
     if (bullets[i].isInFlight())
     {
        bullets[i].update(dtAsSeconds);
     }
   } }// End updating the scene
```

最后，我们可以绘制所有的子弹。

## 每帧绘制子弹

添加高亮代码来循环遍历`bullets`数组，检查子弹是否在飞行中，如果是，就绘制它：

```cpp
/* 
 ************** 
 Draw the scene 
 ************** 
 */ 

if (state == State::PLAYING) 
{ 
   window.clear(); 

   // set the mainView to be displayed in the window 
   // And draw everything related to it 
   window.setView(mainView); 

   // Draw the background 
   window.draw(background, &textureBackground); 

   // Draw the zombies 
   for (int i = 0; i < numZombies; i++) 
   { 
      window.draw(zombies[i].getSprite()); 
   } 

 for (int i = 0; i < 100; i++)
   {
     if (bullets[i].isInFlight())
     {
        window.draw(bullets[i].getShape());
     }
   } 

   // Draw the player 
   window.draw(player.getSprite()); 
}
```

运行游戏来尝试子弹。注意你可以连续射击六次，然后需要按***R***重新装填。明显缺少的是弹夹中子弹数量和备用子弹数量的一些视觉指示。另一个问题是玩家很快就会用尽子弹，特别是因为子弹根本没有停止力。它们直接穿过僵尸。再加上玩家期望以鼠标指针而不是精确的准星瞄准，我们明显还有工作要做。

在下一章中，我们将通过 HUD 给出视觉反馈。接下来我们将用一个准星替换鼠标光标，然后在此之后生成一些拾取物品来补充子弹和生命值。最后，在本章中，我们将处理碰撞检测，使子弹和僵尸造成伤害，并使玩家能够真正获得拾取物品。

# 给玩家一个准星

添加一个准星很容易，只需要一个新的概念。添加高亮代码，然后我们可以运行它：

```cpp
// 100 bullets should do 
Bullet bullets[100]; 
int currentBullet = 0; 
int bulletsSpare = 24; 
int bulletsInClip = 6; 
int clipSize = 6; 
float fireRate = 1; 
// When was the fire button last pressed? 
Time lastPressed; 

// Hide the mouse pointer and replace it with crosshair
window.setMouseCursorVisible(true);
Sprite spriteCrosshair;
Texture textureCrosshair =
    TextureHolder::GetTexture("graphics/crosshair.png");

spriteCrosshair.setTexture(textureCrosshair);
spriteCrosshair.setOrigin(25, 25); 
// The main game loop 
while (window.isOpen())
```

首先我们在`window`对象上调用`setMouseCursorVisible`函数。然后我们加载一个`Texture`，声明一个`Sprite`，并以通常的方式初始化它。此外，我们将精灵的原点设置为它的中心，以使子弹飞向中心更加方便和简单，正如你所期望的那样。

现在我们需要每帧更新准星的世界坐标。添加高亮代码行，它使用`mouseWorldPosition`向量来设置每帧的准星位置：

```cpp
/* 
 **************** 
 UPDATE THE FRAME 
 **************** 
 */ 
if (state == State::PLAYING) 
{ 
   // Update the delta time 
   Time dt = clock.restart(); 
   // Update the total game time 
   gameTimeTotal += dt; 
   // Make a decimal fraction of 1 from the delta time 
   float dtAsSeconds = dt.asSeconds(); 

   // Where is the mouse pointer 
   mouseScreenPosition = Mouse::getPosition(); 

   // Convert mouse position to world coordinates of mainView 
   mouseWorldPosition = window.mapPixelToCoords( 
      Mouse::getPosition(), mainView); 

 // Set the crosshair to the mouse world location
   spriteCrosshair.setPosition(mouseWorldPosition); 

   // Update the player 
   player.update(dtAsSeconds, Mouse::getPosition());
```

接下来，正如你可能期望的那样，我们可以为每一帧绘制准星。在指定位置添加高亮代码行。这行代码不需要解释，但它在所有其他游戏对象之后的位置很重要，这样它就会被绘制在最上面：

```cpp
/* 
 ************** 
 Draw the scene 
 ************** 
 */ 

if (state == State::PLAYING) 
{ 
   window.clear(); 

   // set the mainView to be displayed in the window 
   // And draw everything related to it 
   window.setView(mainView); 

   // Draw the background 
   window.draw(background, &textureBackground); 

   // Draw the zombies 
   for (int i = 0; i < numZombies; i++) 
   { 
      window.draw(zombies[i].getSprite()); 
   } 

   for (int i = 0; i < 100; i++) 
   { 
      if (bullets[i].isInFlight()) 
      { 
         window.draw(bullets[i].getShape()); 
      } 
   } 

   // Draw the player 
   window.draw(player.getSprite()); 

 //Draw the crosshair
   window.draw(spriteCrosshair);
}

```

现在你可以运行游戏，看到酷炫的准星，而不是鼠标光标：

![给玩家一个准星](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_09_001.jpg)

注意子弹是如何整齐地穿过准星中心的。射击机制的工作方式类似于允许玩家选择从腰部射击或瞄准射击。如果玩家保持准星靠近中心，他可以快速射击和转身，但必须仔细判断远处僵尸的位置。

或者，玩家可以直接将准星悬停在远处僵尸的头部，进行精确射击；然而，如果僵尸从另一个方向袭击，那么他就需要更远地移动准星。

对游戏的一个有趣改进是为每一枪增加一点小的随机不准确性。这种不准确性可能会在波之间的升级中得到缓解。

# 编写一个用于拾取的类

我们将编写一个`Pickup`类，其中有一个`Sprite`成员以及其他成员数据和函数。我们将在几个步骤中向我们的游戏中添加拾取物品：

1.  首先，我们将编写`Pickup.h`文件。这将揭示所有成员数据的细节和函数的原型。

1.  接下来，我们将编写`Pickup.cpp`文件，其中当然将包含`Pickup`类的所有函数的定义。当我们逐步进行时，我将解释`Pickup`类型的对象将如何工作和被控制。

1.  最后，我们将在`main`函数中使用`Pickup`类来生成、更新和绘制它们。

让我们从第 1 步开始。

## 编写拾取物头文件

要创建新的头文件，**在** **解决方案资源管理器** 中**右键单击** **头文件**，然后选择**添加 | 新建项...**。在**添加新项**窗口中，通过左键单击**头文件（** `.h` **）**，然后在**名称**字段中键入`Pickup.h`。

在`Pickup.h`文件中添加并学习以下代码，然后我们可以逐步进行：

```cpp
#pragma once 
#include <SFML/Graphics.hpp> 

using namespace sf; 

class Pickup 
{ 
private: 
   //Start value for health pickups 
   const int HEALTH_START_VALUE = 50; 
   const int AMMO_START_VALUE = 12; 
   const int START_WAIT_TIME = 10; 
   const int START_SECONDS_TO_LIVE = 5; 

   // The sprite that represents this pickup 
   Sprite m_Sprite; 

   // The arena it exists in 
   IntRect m_Arena; 

   // How much is this pickup worth? 
   int m_Value; 

   // What type of pickup is this?  
   // 1 = health, 2 = ammo 
   int m_Type; 

   // Handle spawning and disappearing 
   bool m_Spawned; 
   float m_SecondsSinceSpawn; 
   float m_SecondsSinceDeSpawn; 
   float m_SecondsToLive; 
   float m_SecondsToWait;   

   // Public prototypes go here 
};
```

之前的代码声明了`Pickup`类的所有私有变量。虽然这些变量的名称应该很直观，但为什么需要这么多变量可能并不明显。让我们从顶部开始逐个讲解：

+   `const int HEALTH_START_VALUE = 50`：这个常量变量用于设置所有生命值拾取物的起始值。这个值将用于初始化`m_Value`变量，在游戏过程中需要对其进行操作。

+   `const int AMMO_START_VALUE = 12`：这个常量变量用于设置所有弹药拾取物的起始值。这个值将用于初始化`m_Value`变量，在游戏过程中需要对其进行操作。

+   `const int START_WAIT_TIME = 10`：这个变量是拾取物在消失后重新生成前要等多久。它将用于初始化`m_SecondsToWait`变量，在游戏过程中可以对其进行操作。

+   `const int START_SECONDS_TO_LIVE = 5`：这个变量确定拾取物在生成和消失之间持续多长时间。和前面三个常量一样，它有一个与之关联的非常量，可以在游戏过程中进行操作。它用于初始化`m_SecondsToLive`。

+   `Sprite m_Sprite`：这是用来直观表示对象的精灵。

+   `IntRect m_Arena`：这将保存当前竞技场的大小，以帮助拾取物在合理的位置生成。

+   `int m_Value`：这个拾取物值多少生命值或弹药？当玩家升级生命值或弹药拾取物的值时会使用这个值。

+   `int m_Type`：这将是生命值或弹药的零或一。我们本可以使用一个枚举类，但对于只有两个选项来说，这似乎有点杀鸡用牛刀。

+   `bool m_Spawned`：拾取物当前是否生成？

+   `float m_SecondsSinceSpawn`：拾取物生成后多长时间了？

+   `float m_SecondsSinceDeSpawn`：拾取物消失后多长时间了？

+   `float m_SecondsToLive`：这个拾取物在生成后应该存活多久？

+   `float m_SecondsToWait`：这个拾取物在消失后应该等多久才重新出现？

### 提示

请注意，这个类的大部分复杂性是由于变量生成时间及其可升级的特性。如果拾取物在收集后只是重新生成并具有固定值，那么这将是一个非常简单的类。我们需要我们的拾取物可以升级，所以玩家被迫制定策略来通过僵尸的波次。

然后，在`Pickup.h`文件中添加以下公共函数原型。确保熟悉新代码，以便我们可以逐步进行：

```cpp
// Public prototypes go here 
public:
   Pickup::Pickup(int type);

   // Prepare a new pickup
   void setArena(IntRect arena);
   void spawn();

   // Check the position of a pickup
   FloatRect getPosition();

   // Get the sprite for drawing
   Sprite getSprite();

   // Let the pickup update itself each frame
   void update(float elapsedTime);

   // Is this pickup currently spawned?
   bool isSpawned();

   // Get the goodness from the pickup
   int gotIt();

   // Upgrade the value of each pickup
   void upgrade();
};

```

让我们简要讨论每个函数定义：

+   第一个函数是构造函数，以类的名称命名。注意它只接受一个`int`参数。这将用于初始化它将是什么类型的拾取物（生命值还是弹药）。

+   `setArena`函数接收一个`IntRect`。这个函数将在每个波次开始时为每个`Pickup`实例调用。然后`Pickup`对象将知道它们可以生成的区域。

+   `spawn`函数当然会处理生成拾取物。

+   `getPosition`函数，就像在`Player`、`Zombie`和`Bullet`类中一样，将返回一个代表游戏世界中对象当前位置的`FloatRect`。

+   `getSprite`函数返回一个`Sprite`对象，使得拾取物可以在每一帧中被绘制。

+   `update`函数接收上一帧所用的时间。它使用这个值来更新它的私有变量，并决定何时生成和取消生成。

+   `isSpawned`函数返回一个布尔值，让调用代码知道拾取物当前是否已生成。

+   `gotIt`函数在检测到与玩家的碰撞时将被调用。然后`Pickup`类代码可以准备在适当的时间重新生成。请注意，它返回一个`int`，以便调用代码知道拾取物的价值是健康还是弹药。

+   `upgrade`函数将在玩家选择在游戏的升级阶段升级拾取物的属性时被调用。

现在我们已经浏览了成员变量和函数原型，应该很容易跟着我们编写函数定义。

## 编写 Pickup 类函数定义

现在我们可以创建一个新的`.cpp`文件，其中包含函数定义。在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加 | 新项目...**。在**添加新项目**窗口中，通过左键单击**C++文件（**`.cpp` **）**突出显示，然后在**名称**字段中键入`Pickup.cpp`。最后，单击**添加**按钮。我们现在准备好编写类的代码了。

将此处显示的代码添加到`Pickup.cpp`文件中。确保审查代码，以便我们可以讨论它：

```cpp
#include "stdafx.h" 
#include "Pickup.h" 
#include "TextureHolder.h" 

Pickup::Pickup(int type) 
{ 
   // Store the type of this pickup 
   m_Type = type; 

   // Associate the texture with the sprite 
   if (m_Type == 1) 
   { 
      m_Sprite = Sprite(TextureHolder::GetTexture( 
         "graphics/health_pickup.png")); 

      // How much is pickup worth 
      m_Value = HEALTH_START_VALUE; 

   } 
   else 
   { 
      m_Sprite = Sprite(TextureHolder::GetTexture( 
         "graphics/ammo_pickup.png")); 

      // How much is pickup worth 
      m_Value = AMMO_START_VALUE; 
   } 

   m_Sprite.setOrigin(25, 25); 

   m_SecondsToLive = START_SECONDS_TO_LIVE; 
   m_SecondsToWait = START_WAIT_TIME; 
}
```

在之前的代码中，我们添加了熟悉的包含指令。然后我们添加了`Pickup`构造函数。我们知道这是构造函数，因为它与类名相同。

构造函数接收一个名为`type`的`int`，代码的第一件事就是将从`type`接收到的值赋给`m_Type`。之后，有一个`if…else`块，检查`m_Type`是否等于`1`。如果是，`m_Sprite`将与健康拾取纹理相关联，`m_Value`将设置为`HEALTH_START_VALUE`。

如果`m_Type`不等于`1`，`else`块将把弹药拾取纹理与`m_Sprite`相关联，并将`AMMO_START_VALUE`的值赋给`m_Value`。

在`if…else`块之后，代码使用`setOrigin`函数将`m_Sprite`的原点设置为中心，并将`START_SECONDS_TO_LIVE`和`START_WAIT_TIME`分别赋给`m_SecondsToLive`和`m_SecondsToWait`。

构造函数已成功准备了一个可以使用的`Pickup`对象。

接下来我们将添加`setArena`函数。在添加时检查代码：

```cpp
void Pickup::setArena(IntRect arena) 
{ 

   // Copy the details of the arena to the pickup's m_Arena 
   m_Arena.left = arena.left + 50; 
   m_Arena.width = arena.width - 50; 
   m_Arena.top = arena.top + 50; 
   m_Arena.height = arena.height - 50; 

   spawn(); 
}
```

我们刚刚编写的`setArena`函数只是简单地复制了传入的`arena`对象的值，但在左侧和顶部增加了五十，右侧和底部减少了五十。现在 Pickup 对象已经知道它可以生成的区域。`setArena`函数然后调用自己的`spawn`函数，为每一帧的绘制和更新做最后的准备。

接下来是`spawn`函数。在`setArena`函数之后添加以下代码：

```cpp
void Pickup::spawn() 
{ 
   // Spawn at a random location 
   srand((int)time(0) / m_Type); 
   int x = (rand() % m_Arena.width); 
   srand((int)time(0) * m_Type); 
   int y = (rand() % m_Arena.height); 

   m_SecondsSinceSpawn = 0; 
   m_Spawned = true; 

   m_Sprite.setPosition(x, y); 
}
```

`spawn`函数执行准备拾取物所需的一切。首先它为随机数生成器设置种子，并获取对象的水平和垂直位置的随机数。请注意，它使用`m_Arena.width`和`m_Arena.height`作为可能水平和垂直位置的范围。

`m_SecondsSinceSpawn`设置为零，因此在取消生成之前允许的时间长度被重置。`m_Spawned`变量设置为`true`，因此当我们从`main`中调用`isSpawned`时，我们将得到一个积极的响应。最后，`m_Sprite`通过`setPosition`移动到位置，准备绘制到屏幕上。

在以下代码块中，我们有三个简单的 getter 函数。`getPosition`函数返回`m_Sprite`当前位置的`FloatRect`，`getSprite`返回`m_Sprite`本身的副本，`isSpawned`根据对象当前是否生成返回`true`或`false`。

添加并检查我们刚刚讨论的代码：

```cpp
FloatRect Pickup::getPosition() 
{ 
   return m_Sprite.getGlobalBounds(); 
} 

Sprite Pickup::getSprite() 
{ 
   return m_Sprite; 
} 

bool Pickup::isSpawned() 
{ 
   return m_Spawned; 
} 

```

接下来我们将编写`gotIt`函数。当玩家触摸/碰撞（获得）拾取物时，将从`main`中调用此函数。在`isSpawned`函数之后添加`gotIt`函数：

```cpp

int Pickup::gotIt() 
{ 
   m_Spawned = false; 
   m_SecondsSinceDeSpawn = 0; 
   return m_Value; 
}
```

`gotIt`函数将`m_Spawned`设置为`false`，所以我们知道此刻不要绘制和检查碰撞。`m_SecondsSinceDespawn`设置为零，因此再次开始生成的倒计时从头开始，`m_Value`返回给调用代码，以便调用代码可以处理添加额外的弹药或生命值。

接下来是`update`函数，它将我们迄今为止看到的许多变量和函数联系在一起。添加并熟悉`update`函数，然后我们可以讨论它：

```cpp
void Pickup::update(float elapsedTime) 
{ 
   if (m_Spawned) 
   { 
      m_SecondsSinceSpawn += elapsedTime; 
   } 
   else 
   { 
      m_SecondsSinceDeSpawn += elapsedTime; 
   } 

   // Do we need to hide a pickup? 
   if (m_SecondsSinceSpawn > m_SecondsToLive && m_Spawned) 
   { 
      // Remove the pickup and put it somewhere else 
      m_Spawned = false; 
      m_SecondsSinceDeSpawn = 0; 
   } 

   // Do we need to spawn a pickup 
   if (m_SecondsSinceDeSpawn > m_SecondsToWait && !m_Spawned) 
   { 
      // spawn the pickup and reset the timer 
      spawn(); 
   } 

}
```

`update`函数分为四个块，每帧考虑执行一次：

+   如果`m_Spawned`为 true，则执行`if`块——`if (m_Spawned)`。这段代码将本帧的时间添加到`m_SecondsSinceSpawned`，以跟踪拾取物已经生成的时间。

+   相应的`else`块，如果`m_Spawned`为`false`，则执行。此块将本帧所花费的时间添加到`m_SecondsSinceDeSpawn`，以跟踪拾取物自上次取消生成（隐藏）以来等待的时间。

+   另一个`if`块，当生成的拾取物已经存在的时间超过应该存在的时间时执行——`if (m_SecondsSinceSpawn > m_SecondsToLive && m_Spawned)`。这个块将`m_Spawned`设置为`false`，并将`m_SecondsSinceDeSpawn`重置为零。现在块 2 将执行，直到再次生成的时间到来。

+   最后一个`if`块，当自上次取消生成以来等待的时间超过必要的等待时间，并且拾取物当前未生成时执行——`if (m_SecondsSinceDeSpawn > m_SecondsToWait && !m_Spawned)`。当执行此块时，是时候再次生成了，并调用生成函数。

这四个测试和代码控制着拾取物的隐藏和显示。

最后，添加`upgrade`函数的定义：

```cpp
void Pickup::upgrade() 
{ 
   if (m_Type == 1) 
   { 
      m_Value += (HEALTH_START_VALUE * .5); 
   } 
   else 
   { 
      m_Value += (AMMO_START_VALUE * .5); 
   } 

   // Make them more frequent and last longer 
   m_SecondsToLive += (START_SECONDS_TO_LIVE / 10); 
   m_SecondsToWait -= (START_WAIT_TIME / 10); 
}
```

`upgrade`函数测试拾取物的类型，无论是生命值还是弹药，然后将`m_Value`的初始值的 50%添加到其中。在`if…else`块之后的两行增加了拾取物生成的时间和玩家等待生成之间的时间。

当玩家在`LEVELING_UP`状态下选择升级拾取物时，将调用此函数。我们的`Pickup`类已经准备就绪。

# 使用 Pickup 类

经过所有那些辛苦工作实现`Pickup`类之后，我们现在可以继续在游戏引擎中编写代码，真正将一些拾取物放入游戏中。

我们首先在`ZombieArena.cpp`文件中添加一个包含指令：

```cpp
#include "stdafx.h" 
#include <SFML/Graphics.hpp> 
#include "ZombieArena.h" 
#include "Player.h" 
#include "TextureHolder.h" 
#include "Bullet.h" 
#include "Pickup.h" using namespace sf;
```

在以下代码中，我们添加了两个`Pickup`实例，一个称为`healthPickup`，另一个称为`ammoPickup`。我们分别将值`1`和`2`传递给构造函数，以便它们被初始化为正确类型的拾取物。添加我们刚刚讨论过的突出显示的代码：

```cpp
// Hide the mouse pointer and replace it with crosshair 
window.setMouseCursorVisible(true); 
Sprite spriteCrosshair; 
Texture textureCrosshair = TextureHolder::GetTexture("graphics/crosshair.png"); 
spriteCrosshair.setTexture(textureCrosshair); 
spriteCrosshair.setOrigin(25, 25); 

// Create a couple of pickups
Pickup healthPickup(1);
Pickup ammoPickup(2); 

// The main game loop 
while (window.isOpen())
```

在键盘处理的`LEVELING_UP`状态中，添加在嵌套的`PLAYING`代码块中显示的突出行：

```cpp
if (state == State::PLAYING) 
{ 
   // Prepare thelevel 
   // We will modify the next two lines later 
   arena.width = 500; 
   arena.height = 500; 
   arena.left = 0; 
   arena.top = 0; 

   // Pass the vertex array by reference  
   // to the createBackground function 
   int tileSize = createBackground(background, arena); 

   // Spawn the player in the middle of the arena 
   player.spawn(arena, resolution, tileSize); 

 // Configure the pickups
   healthPickup.setArena(arena);
   ammoPickup.setArena(arena); 

   // Create a horde of zombies 
   numZombies = 10; 

   // Delete the previously allocated memory (if it exists) 
   delete[] zombies; 
   zombies = createHorde(numZombies, arena); 
   numZombiesAlive = numZombies; 

   // Reset the clock so there isn't a frame jump 
   clock.restart(); 
}
```

先前的代码简单地将`arena`传递给每个拾取物的`setArena`函数。拾取物现在知道它们可以生成的位置。这段代码对于每个新波次都会执行，因此随着竞技场的大小增长，`Pickup`对象将得到更新。

以下代码简单地为每个`Pickup`对象在每一帧调用`update`函数：

```cpp
// Loop through each Zombie and update them 
   for (int i = 0; i < numZombies; i++) 
   { 
      if (zombies[i].isAlive()) 
      { 
         zombies[i].update(dt.asSeconds(), playerPosition); 
      } 
   } 

   // Update any bullets that are in-flight 
   for (int i = 0; i < 100; i++) 
   { 
      if (bullets[i].isInFlight()) 
      { 
         bullets[i].update(dtAsSeconds); 
      } 
   } 

 // Update the pickups
   healthPickup.update(dtAsSeconds);
   ammoPickup.update(dtAsSeconds); }// End updating the scene
```

游戏循环的绘制部分中的以下代码检查拾取物当前是否生成，如果是，则绘制它。添加我们刚讨论过的突出显示的代码：

```cpp
   // Draw the player 
   window.draw(player.getSprite()); 

 // Draw the pickups, if currently spawned
   if (ammoPickup.isSpawned())
   {
     window.draw(ammoPickup.getSprite());
   }
   if (healthPickup.isSpawned())
   {
     window.draw(healthPickup.getSprite());
   } 

   //Draw the crosshair 
   window.draw(spriteCrosshair); 
}
```

现在您可以运行游戏并看到拾取物的生成和消失。但是，您目前无法实际拾取它们。

![使用 Pickup 类](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_09_002.jpg)

现在我们已经在游戏中有了所有的对象，是时候让它们相互作用（碰撞）了。

# 检测碰撞

我们只需要知道游戏中的某些对象何时接触到其他对象。然后我们可以以适当的方式对该事件做出响应。在我们的类中，我们已经添加了在对象碰撞时调用的函数。它们如下：

+   `Player`类有一个`hit`函数。当僵尸与玩家发生碰撞时，我们将调用它。

+   `Zombie`类有一个`hit`函数。当子弹与僵尸发生碰撞时，我们将调用它。

+   `Pickup`类有一个`gotIt`函数。当玩家与拾取物发生碰撞时，我们将调用它。

如果需要，回顾一下每个函数的工作原理。现在我们只需要检测碰撞并调用适当的函数。我们将使用**矩形相交**来检测碰撞。这种类型的碰撞检测非常简单（特别是使用 SFML）。我们可以想象绘制一个虚拟的矩形——我们可以称之为**碰撞框**或**边界矩形**——围绕我们想要测试碰撞的对象，然后测试它们是否相交。如果它们相交，我们就有了碰撞：

![检测碰撞](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_09_003.jpg)

从前面的图像中可以看出，这还远非完美。但在这种情况下已经足够了。要实现这种方法，我们只需要使用两个对象碰撞框的 x 和 y 坐标进行相交测试。

检测两个矩形相交的代码看起来可能是这样的。不要使用以下代码。这仅用于演示目的：

```cpp
if(objectA.getPosition().right > objectB.getPosition().left 
   && objectA.getPosition().left < objectB.getPosition().right ) 
{     
   // objectA is intersecting enemy on x axis     
   // But they could be at different heights     

   if(objectA.getPosition().top < objectB.getPosition().bottom          
      && objectA.getPosition().bottom > objectB.getPosition().top ) 
      {        
         // objectA is intersecting objectB on y axis as well  
         // Collision detected   
      }  
}
```

然而，我们不需要编写这段代码。我们将使用 SFML 的`intersects`函数，它适用于`FloatRect`对象。回想一下`Zombie`、`Player`、`Bullet`和`Pickup`类，它们都有一个`getPosition`函数，返回对象当前位置的`FloatRect`。我们将看到如何使用`getPosition`和`intersects`来进行所有的碰撞检测。

我们将分三个代码部分处理这个问题，它们将依次跟在游戏引擎更新部分的末尾。

我们需要每帧知道以下三个问题的答案：

+   是否有僵尸被击中？

+   玩家是否被僵尸触碰？

+   玩家是否触碰到了拾取物？

首先让我们添加几个变量`score`和`hiscore`。然后当杀死僵尸时我们可以改变它们。添加以下代码：

```cpp
// Create a couple of pickups 
Pickup healthPickup(1); 
Pickup ammoPickup(2); 

// About the game
int score = 0;
int hiScore = 0; 

// The main game loop 
while (window.isOpen())
```

现在让我们开始检测僵尸是否与子弹发生碰撞。

## 是否有僵尸被击中？

以下代码可能看起来很复杂，但当我们逐步进行时，我们会发现这实际上并不是我们以前没有见过的东西。在每帧更新拾取物后，添加以下代码。然后我们可以逐步进行：

```cpp
// Update the pickups 
healthPickup.update(dtAsSeconds); 
ammoPickup.update(dtAsSeconds); 

// Collision detection
// Have any zombies been shot?
for (int i = 0; i < 100; i++)
{
   for (int j = 0; j < numZombies; j++)
   {
     if (bullets[i].isInFlight() &&
         zombies[j].isAlive())
     {
        if (bullets[i].getPosition().intersects
           (zombies[j].getPosition()))
        {
           // Stop the bullet
           bullets[i].stop();
           // Register the hit and see if it was a kill
           if (zombies[j].hit())
           {
             // Not just a hit but a kill too
             score += 10;
             if (score >= hiScore)
             {
                hiScore = score;
             }
             numZombiesAlive--;
             // When all the zombies are dead (again)
             if (numZombiesAlive == 0)
             {
                state = State::LEVELING_UP;
             }
           }
        }
     }
   }
}// End zombie being shot

```

在接下来的部分中，我们将再次看到所有的僵尸和子弹碰撞检测代码。我们将一点一点地进行讨论。首先注意嵌套的`for`循环的结构（去掉代码后）如下：

```cpp
// Collision detection 
// Have any zombies been shot? 
for (int i = 0; i < 100; i++) 
{ 
   for (int j = 0; j < numZombies; j++) 
   { 
      ... 
      ... 
      ... 
   } 
}
```

该代码循环遍历每一颗子弹（从 0 到 99），对于每一个僵尸（从 0 到`numZombies`的前一个）。

在嵌套的`for`循环中，我们执行以下操作：

1.  使用以下代码检查当前子弹是否在飞行中，当前僵尸是否仍然活着：

```cpp
    if (bullets[i].isInFlight() && zombies[j].isAlive())
```

1.  假设僵尸还活着，子弹正在飞行，我们使用以下代码测试矩形相交：

```cpp
    if (bullets[i].getPosition().intersects (zombies[j].getPosition()))
```

如果当前子弹和僵尸发生了碰撞，那么我们会采取一些步骤。

1.  使用以下代码停止子弹：

```cpp
    // Stop the bullet
    bullets[i].stop();
```

1.  通过调用其`hit`函数向当前僵尸注册一次命中。请注意，`hit`函数返回一个`Boolean`，让调用代码知道僵尸是否已经死亡。这显示在以下代码行中：

```cpp
    // Register the hit and see if it was a kill 
    if (zombies[j].hit()) {
```

在此`if`块内，检测僵尸是否死亡而不仅仅是受伤时，我们执行以下操作：

+   将`score`增加十

+   如果分数超过（击败）`score`，则更改`hiScore`

+   将`numZombiesAlive`减少一个

+   检查是否所有僵尸都死了，`(numZombiesAlive == 0)`，如果是，则更改`state`为`LEVELING_UP`

这是我们刚讨论的`if(zombies[j].hit())`内的代码块：

```cpp
// Not just a hit but a kill too 
score += 10; 
if (score >= hiScore) 
{ 
   hiScore = score; 
} 

numZombiesAlive--; 

// When all the zombies are dead (again) 
if (numZombiesAlive == 0)  
{ 
   state = State::LEVELING_UP; 
}
```

这样就处理了僵尸和子弹。您可以运行游戏并看到血液。当然，在我们在下一章中实现 HUD 之前，您不会看到分数。

## 玩家是否被僵尸触碰？

这段代码比僵尸和子弹碰撞检测要简短和简单得多。在我们编写的先前代码之后添加以下突出显示的代码：

```cpp
}// End zombie being shot 

// Have any zombies touched the player
for (int i = 0; i < numZombies; i++)
{
  if (player.getPosition().intersects
    (zombies[i].getPosition()) && zombies[i].isAlive())
  {
    if (player.hit(gameTimeTotal))
    {
      // More here later
    }
    if (player.getHealth() <= 0)
    {
      state = State::GAME_OVER;
    }
  } }// End player touched
```

我们通过使用`for`循环遍历所有僵尸来检测僵尸是否与玩家发生碰撞。对于每个活着的僵尸，代码使用`intersects`函数来测试与玩家的碰撞。发生碰撞时，我们调用`player.hit`。然后我们通过调用`player.getHealth`来检查玩家是否死亡。如果玩家的健康值等于或小于零，则我们将`state`更改为`GAME_OVER`。

您可以运行游戏并检测碰撞。但是，由于尚未添加 HUD 或音效，因此不清楚是否发生了碰撞。此外，我们需要在玩家死亡并开始新游戏时做更多工作。因此，尽管游戏运行，但目前的结果并不特别令人满意。我们将在接下来的两章中改进这一点。

## 玩家是否触碰了物品？

玩家与两个物品之间的碰撞检测代码如下。在我们添加的先前代码之后添加以下突出显示的代码：

```cpp
   }// End player touched 

 // Has the player touched health pickup
   if (player.getPosition().intersects
     (healthPickup.getPosition()) && healthPickup.isSpawned())
   {
     player.increaseHealthLevel(healthPickup.gotIt());
   }

   // Has the player touched ammo pickup
   if (player.getPosition().intersects
     (ammoPickup.getPosition()) && ammoPickup.isSpawned())
   {
     bulletsSpare += ammoPickup.gotIt();
   }
}// End updating the scene

```

先前的代码使用两个简单的`if`语句来查看`healthPickup`或`ammoPickup`是否被玩家触碰。

如果已收集了健康物品，则`player.increaseHealthLevel`函数使用从`healthPickup.gotIt`函数返回的值来增加玩家的健康水平。

如果弹药捡起已被收集，那么`bulletsSpare`将增加`ammoPickup.gotIt`返回的值。

您可以运行游戏，杀死僵尸并收集物品！请注意，当您的健康值等于零时，游戏将进入`GAME_OVER`状态并暂停。要重新开始，您需要按*Enter*，然后输入*1*到*6*之间的数字。当我们实现 HUD、主屏幕和升级屏幕时，这些步骤对玩家来说将是直观和简单的。我们将在下一章中这样做。

# 常见问题

以下是您可能会问的一些问题：

Q）是否有更好的碰撞检测方法？

A）是的。有许多更多的碰撞检测方法，包括但不限于以下方法：

+   可以将对象分成多个更适合精灵形状的矩形。对于 C++来说，每帧检查成千上万个矩形是完全可管理的。特别是当您使用邻居检查等技术来减少每帧所需的测试数量时。

+   对于圆形对象，可以使用半径重叠方法。

+   对于不规则多边形，可以使用交叉数算法。

所有这些技术都可以在以下网站上进行调查：

+   **邻居检查**：[`gamecodeschool.com/essentials/collision-detection-neighbor-checking/`](http://gamecodeschool.com/essentials/collision-detection-neighbor-checking/)

+   **半径重叠方法**：[`gamecodeschool.com/essentials/collision-detection-radius-overlap/`](http://gamecodeschool.com/essentials/collision-detection-radius-overlap/)

+   **穿越数算法**：[`gamecodeschool.com/essentials/collision-detection-crossing-number/`](http://gamecodeschool.com/essentials/collision-detection-crossing-number/)

# 摘要

这是一个忙碌的章节，但我们取得了很多成就。我们不仅通过两个新的类为游戏添加了子弹和拾取物，而且还使所有的物体按照应有的方式进行交互，当它们相互碰撞时进行检测。

尽管取得了这些成就，我们仍需要做更多的工作来设置每个新游戏，并通过 HUD 向玩家提供反馈。在下一章中，我们将构建 HUD。
