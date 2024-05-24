# C++ 游戏开发的程序化内容生成（一）

> 原文：[`zh.annas-archive.org/md5/78a00fe20d9b720cedc79b3376ba4721`](https://zh.annas-archive.org/md5/78a00fe20d9b720cedc79b3376ba4721)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

电脑游戏是一个庞大的媒介，已经发展了三到四十年。游戏比以往任何时候都更大、更沉浸，玩家的期望也从未如此之高。虽然线性游戏，即具有固定故事和固定进度的游戏，仍然很常见，但越来越多的动态和开放式的游戏正在被开发。

计算机硬件和视频游戏技术的进步正在给“游戏世界”这个词带来更加直接的意义。游戏地图不断增加，变得更加灵活，这要归功于过程生成等技术的发展。由于内容是动态生成的，所以购买同一款游戏的两名玩家可能会有非常不同的体验。

在本书中，我们将介绍过程生成，学习生成内容以创建动态和不可预测的游戏系统和机制所需的技能。

本书提供了一个流氓式 C++游戏的游戏模板。当我们在第二章“项目设置和拆分”中编译和设置项目时，您会发现它目前只是一个空壳。然而，随着我们在书中的学习，您将通过真实的例子了解到程序生成内容背后的概念。然后我们将在空项目中实现这些例子。

# 本书涵盖的内容

第一章，“过程生成简介”，向我们介绍了过程生成的广阔主题。我一直觉得真正学会某事的关键部分是理解为什么要以这种方式完成。了解如何完成某事固然很重要，但了解其起源以及为什么会以这种方式完成则会创造出更完整的画面和更深刻的理解。在本章中，我们将回到过程生成的诞生以及它进入现代电脑游戏的历程。

第二章，“项目设置和拆分”，解释了如何在您选择的 IDE 中设置提供的流氓式游戏项目，并为 Visual Studio 和 Code::Blocks 提供了详细的说明。它是用 C++/SFML 编写的，我们将在整本书中进行扩展。我们还将介绍您可能遇到的常见问题，并首次运行该项目。

第三章，“使用 C++数据类型进行 RNG”，探讨了随机数生成（RNG），包括围绕它的问题以及我们如何在运行时使用它与 C++数据类型来实现随机结果。RNG 是过程生成的核心，是我们模拟计算机随机行为并通过算法实现动态结果的方式。

第四章，“过程填充游戏环境”，帮助我们通过在地图周围的随机位置生成物品和敌人来进一步开发我们的关卡。在过程生成的游戏中，生成环境是一个基本的部分，而在随机位置生成游戏对象是实现这一目标的重要一步。

第五章，“创建独特和随机的游戏对象”，探讨了我们如何创建独特和随机的游戏对象。在运行时，某些物品将被过程生成，这意味着可能会有大量的可能组合。我们将介绍在前几章中用于实现这一点的技能和技术。我们将把所有这些内容整合在一起，构建一个过程系统！

第六章，“程序生成艺术”，通过摆脱简单地随机设置成员变量，转而创建程序生成的艺术和图形，进一步提升了我们的程序生成工作。我们将为我们的敌人程序生成纹理，并修改关卡精灵，使我们的地牢每一层都具有独特的感觉。

第七章，“程序修改音频”，研究了艺术的近亲音频，使用类似的技术来为我们的声音创建差异。我们还将使用 SFML 的音频功能来创建专门的 3D 声音，为我们的关卡带来更多深度。

第八章，“程序行为和机制”，利用我们迄今为止学到的一切知识，创建复杂的程序行为和机制，如寻路和独特的关卡目标。我们将赋予我们的敌人智能，让他们穿越关卡并追逐玩家。我们还将创建独特的关卡目标，并为玩家执行带来独特的奖励。

第九章，“程序地牢生成”，完成了我们对游戏项目的工作。我们将实现也许是 roguelike 游戏最具代表性的特征：程序生成的关卡。在整本书中，我们一直在使用相同的固定关卡。所以，是时候开始程序生成它们了！我们还将在关卡之间创建一些差异，并实现我们在上一章中创建的目标生成器。

第十章，“基于组件的架构”，介绍了基于组件的设计，因为我们的模板项目的工作现在已经完成。程序生成的关键在于灵活性。因此，我们希望使用最灵活的架构进行工作。基于组件的架构可以实现这一点，对这种设计方法有很好的理解将有助于您未来的进步和构建更大的系统。

第十一章，“结语”，回顾了项目和我们在完成程序生成之旅时涉及的主题。对于我们使用的程序生成的每个领域，我们还将确定一些跳板，以便您希望深入探讨该主题。

# 您需要什么

在撰写本书的过程中，我使用了适用于 Windows 桌面的 Visual Studio Community 2015。这是一个很棒的 IDE，具有我们创建 Windows 的 C++游戏所需的所有工具。它可以免费从微软获得，因此我强烈建议您下载并在整本书的过程中使用它。

如果您以前从未使用过它，不要担心；我们将详细介绍项目设置，以便您熟悉我们将使用的 IDE 的各个部分。我还将提供 Code::Blocks 的设置说明。如果您选择不使用 IDE，您将需要访问 C++编译器，以便您可以运行我们在书中将要使用的项目。

# 这本书适合谁

这本书面向那些具有 C++游戏开发知识并希望将程序生成融入其游戏中的人。它将假定对编程基础有相当扎实的理解，如数据类型、返回类型、方法调用等。还假定对游戏开发背后的概念有一定了解，因为我们不会深入研究底层引擎。

提供了一个游戏模板，并且我们将在整本书的过程中使用 SFML 来扩展它。不需要有关 SFML 的先前经验。完成本书后，您将对程序生成的内容是什么，它在游戏中如何使用以及将应用于真实游戏的一系列实用技能有扎实的理解。

# 惯例

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例及其含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："我们调用了`std::srand()`并设置了一个新的种子，但每次运行程序时，我们都再次设置相同的种子"

代码块设置如下：

```cpp
Stirng myStringLiteral = "hello";
string myString = { 'h', 'e', 'l', 'l', 'o', '\0' };
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```cpp
// If the enemy is dead remove it.
if (enemy.IsDead())
{
    enemyIterator = m_enemies.erase(enemyIterator);

    // If we have an active goal decrement killGoal.
 if (m_activeGoal)
 {
 --m_killGoal;
 }
}
```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，比如菜单或对话框中的单词，会以这样的方式出现在文本中："在 Code::Blocks 中，将以下内容添加到项目的**构建选项**和**搜索目录**选项卡中"。

### 注意

警告或重要提示会以这样的方式出现在框中。

### 提示

提示和技巧会以这种方式出现。

## 额外练习

每章结束时，都有一些复习问题和进一步的练习可以完成。虽然这对书籍并不是至关重要，但建议您完成它们，以便您可以衡量对所涵盖主题的理解，并获得更多经验。


# 第一章：程序生成简介

当你在 PC 上加载一张图片、iPod 上的一首歌曲，或者 Kindle 上的一本书时，你是从存储中加载它。那张图片、歌曲和书已经作为一个整体存在，每当你想要访问它时，你就会获取整个之前创建的东西。在音乐或视频的情况下，你可以分块流式传输，但它仍然作为一个整体存在于存储中。让我们将这与从家具店购买现成的桌子进行比较。你得到整个桌子作为一个单一的东西，就是这样；你有了一张桌子。

现在，让我们想象一下，你不是买一个成品桌子，而是买了一个平装的桌子。你得到的不是一个预制的桌子，而是你需要建造一个桌子的所有零件，以及如何做的说明。当你回家后，你可以按照这些说明来建造桌子。如果你愿意，你甚至可以偏离说明，创造出与其他人不同的独特桌子。

让我们在游戏开发的背景下使用这个类比，将购买桌子替换为加载关卡。在第一种情况下，我们加载了整个关卡，因为它是预先构建好的。然而，在第二个例子中，我们得到了所有需要建造关卡的零件，并按照自己选择的顺序将它们组合在一起。

通过算法或程序创建某物的过程，而不是已经存在的东西，被称为**程序生成**。桌子是通过按照算法将其零件组合而成的。游戏关卡也是如此。这几乎可以扩展到任何东西。例如，音乐、图像、游戏和文本都可以通过程序生成。

在本章中，我们将涵盖以下主题：

+   程序生成与随机生成

+   在 C++中生成伪随机数

+   种子

+   程序生成的利与弊

+   罗格式游戏的简史

+   如何实现程序生成

# 程序生成与随机生成

在我们继续之前，我想先做一个区分。在这本书中，我们将大量讨论程序生成和随机生成。这些术语经常被互换使用，但它们并不是同一回事。因此，让我们花一点时间来定义它们。

## 程序生成

程序生成是使用算法创建内容的过程。这本身没有随机元素。如果用于生成内容的函数、表达式、算法和输入保持不变，那么你总是会得到相同的结果。这是因为计算机是确定性的，这是我们很快会讨论的内容。程序生成本身并不具有随机性。

## 随机生成

当我们给这些算法不同的输入或改变它们的表达时，就会引入随机性。这种变化是导致输出多样性的原因。当有人说某物是程序生成时，他们通常是指利用随机性进行程序生成。

# 引入随机性

计算机是**确定性**的机器。这意味着如果你给它们相同的输入，并执行相同的操作，每次都会得到相同的输出。就桌子的例子而言，每个人都得到相同的零件，遵循相同的说明，因此建造出相同的桌子。

再次以游戏的背景来说，如果每个人都得到相同的资产和算法来组合它们，我们都会得到相同的游戏和体验。有时，这是目标。然而，在我们的情况下，我们希望创建不可预测和动态的游戏系统。因此，我们需要在程序生成中引入一定的随机元素。

## 伪随机数生成

随机数生成只是随机选择一个数字的过程。对我们来说这很简单，但对计算机来说是一项更艰巨的任务。事实上，计算机要生成一个真正的随机数是不可能的，除非有特殊的硬件。你马上就会明白为什么会这样。

下一个最好的选择是伪随机数生成。单词*pseudo*的字面意思是*不真实*。因此，伪随机数生成可以被认为是假随机数生成。这些数字看起来是随机的，但实际上是复杂方程和算法的结果，事实上可以提前计算出来。

请记住，并非所有的伪随机数生成器都是一样的。对于诸如普通模拟和游戏之类的应用程序，可以使用相当线性的算法，并且非常适用。然而，伪随机数生成也用于诸如**密码学**之类的应用程序，将使用更复杂的算法，以便无法通过先前输出创建的模式来确定结果。

我们作为开发者使用的伪随机数生成器属于第一类，并且非常适用。幸运的是，C++提供了多种生成普通伪随机数的方法。在本书的过程中，我们将使用`std::rand()`和`std::srand()`，它们都是标准 C++函数，包含在`<cstdlib>`库中。

### 提示

学习如何阅读和从文档中提取信息是一项我认为经常被忽视的技能。有了众多优秀的论坛，很容易直接去谷歌寻找解决方案，但首先，一定要阅读文档。[`www.cplusplus.com`](http://www.cplusplus.com)是一个很好的 C++参考，SFML 在[`www.sfml-dev.org/documentation/`](http://www.sfml-dev.org/documentation/)上有完整的文档。

## 为什么计算机不能生成真正的随机数

我们现在知道计算机不能生成随机数，而是生成伪随机数。让我们看看为什么会这样。

这样做的原因与两台计算机在给定相同输入和操作的情况下会达到相同输出的原因相同；计算机是确定性的。计算机产生的一切都是算法或方程的结果。它们只不过是高度复杂的计算器。因此，你不能要求它们表现得不可预测。

真正的随机数可以生成，但你需要利用机器外部的系统。例如，在[`www.random.org/`](https://www.random.org/) **你可以**使用大气噪音生成真正的随机数。还有其他类似的系统，但除非你为安全目的生成随机数，否则普通伪随机数生成就足够了。

## 在 C++中生成随机数

让我们通过编写一个小程序来生成一些伪随机数来开始编码。为此，我们将使用`std::rand()`函数。它在`0`到`RAND_MAX`之间生成一个伪随机整数。`RAND_MAX`变量是在`<cstdlib>`中定义的常量。它的值将取决于你使用的库。在标准库实现中，它的值至少为 32767。

### 提示

如果你已经熟悉这个主题，可以直接跳到名为种子的子章节。

你可以从 Packt 网站[`www.packtpub.com/support`](http://www.packtpub.com/support)下载这个程序的代码。它将出现在`Examples`文件夹中，项目名称是`random_numbers`：

```cpp
// Random number generation
// This program will generate a random number each time we press enter.

#include <iostream>

using namespace std;

int main()
{
  while (true)
  {
    cout << "Press enter to generate a random number:";
    cin.get();

    // Generate a random integer.
    int randomInteger = rand();

    cout << randomInteger << endl << endl;
  }

  return 0;
}
```

### 提示

下载示例代码

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt Publishing 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

这是一个非常简单的控制台应用程序，每次按 Enter 键时都会调用`std::rand()`。这会返回伪随机数，并将其传递给`std::cout`以显示它。就是这么简单！

![在 C++中生成随机数](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_01_01.jpg)

## 在范围内生成随机数

先前的代码生成了介于`0`和`RAND_MAX`之间的数字。这很好，但通常我们希望更多地控制这一点，以便在特定范围内生成数字。为此，我们将使用**模运算符**。

### 提示

在 C++中，模运算符是%符号。这在不同的语言之间有所不同，但通常是*%*或*Mod*。

取模运算符返回两个数字之间的除法余数。因此，9 mod 2 是 1，因为 2 可以整除 9 四次，剩下 1。我们可以利用这个来创建伪随机数生成的范围。让我们生成一个介于 0 和 249 之间的数字。

为此，我们需要进行以下更改：

```cpp
// Generate a random integer.
//int randomInteger = rand();
int randomInteger = rand() % 250;

```

现在运行程序几次，您会看到所有的结果都限制在我们刚刚定义的范围内。所以现在我们可以生成一个介于 0 和 n 之间的数字，但是如果我们不希望我们的范围从 0 开始怎么办？为此，我们需要对生成数字的行进行一次更改：

```cpp
// Generate a random integer.
//int randomInteger = rand() % 250;
int randomInteger = rand() % 201 + 50;

```

记住，我们在模运算中使用的数字将生成一个介于 0 和 n-1 之间的数字，然后我们之后添加的数字将增加该数量的范围。因此，在这里，我们生成一个介于 0 和 200 之间的数字，然后增加 50 来获得一个介于 50 和 250 之间的数字。

### 提示

如果您对我们在这里所做的事情背后的数学不太了解，请前往 Khan Academy。这是一个学习的绝佳资源，有很多优秀的与数学相关的材料。

运行程序并注意生成的前五个数字。在我的情况下，它们是 91、226、153、219 和 124。现在再次运行。您会注意到发生了一些奇怪的事情；我们收到了完全相同的数字。

它们是以伪随机的方式生成的，对吧？也许这只是一个偶然。让我们再次运行它，看看我们得到了什么。你会再次得到相同的结果。要理解这里发生了什么，我们需要看一下**种子**。

# 种子

我们刚刚创建了一个生成伪随机数的程序，但每次运行它时，我们都会得到相同的结果。我们知道这些数字是复杂方程和算法的结果，那为什么它们是相同的呢？这是因为每次运行程序时，我们都从相同的种子开始。

## 定义种子

种子为算法提供了一个起点。因此，在前面的例子中，是的，我们正在使用复杂的算法来生成数字，但我们每次都从相同的点开始算法。无论算法有多复杂，如果您从相同的点开始，并执行相同的操作，您将得到相同的结果。

想象一下，我们有三个人，每个人都要走 5 步相同的路径。如果他们都从同一个方块开始，他们最终会到达同一个方块：

![定义种子](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_01_02.jpg)

现在，在下一个图表中，我们给这三个人不同的起始位置。即使他们做的动作与之前相同，并且在同一路径上，但由于他们从不同的位置开始，他们的结果是不同的：

![定义种子](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_01_03.jpg)

在这个类比中，路径是算法，起始方块是种子。通过改变种子，我们可以从相同的动作中获得不同的结果。

你很可能以前使用过种子，甚至都不知道。像 Minecraft 和乐高世界这样的游戏，在生成世界之前，会给你设置一个种子的选项。如果你的朋友生成了一个看起来很棒的世界，他们可以获取他们的种子并给你。当你自己输入那个种子时，你就像你的朋友一样从同一个位置启动算法，最终得到相同的世界。

## 使用种子

现在我们知道了种子是什么，让我们修复上一个例子，以便我们不再生成相同的数字。为此，我们将使用`std::srand()`函数。它类似于`std::rand()`，但它需要一个参数。这个参数用于设置算法的种子。我们将在进入 while 循环之前调用`std::srand()`。

### 提示

您只需要在应用程序运行时设置一次种子。一旦调用了`std::srand()`，所有后续对`std::rand()`的调用都将基于更新后的初始种子。

更新后的代码应该是这样的：

```cpp
// Random number generation
// This program will generate a random number each time we press enter.

#include <iostream>

using namespace std;

int main()
{
  // Here we will call srand() to set the seed for future rand() calls.
  srand(100);

  while (true)
  {
    cout << "Press enter to generate a random number:";
    cin.get();

    // Generate a random integer.
    int randomInteger = rand() % 201 + 50;

    cout << randomInteger << endl << endl;
  }

  return 0;
}
```

现在当我们运行这段代码时，我们得到了不同的结果！我得到了 214、60、239、71 和 233。如果你的数字和我的不完全匹配，不要担心；它们都是 CPU 和供应商特定的。那么如果我们再次运行程序会发生什么呢？我们改变了种子。所以我们应该再次得到不同的数字，对吗？

不完全正确。我们调用了`std::srand()`并设置了一个新的种子，但每次运行程序时，我们又设置了相同的种子。我们每次都从相同的位置启动算法，所以看到了相同的结果。我们真正想做的是在运行时随机生成一个种子，这样算法总是从一个新的位置开始。

## 在运行时生成随机种子

有许多方法可以实现这一点，您的用例将决定哪种方法适合。对于我们作为游戏开发者来说，通常一些相对琐碎的东西，比如当前系统时间，就足够了。

这意味着如果你在完全相同的时间运行程序，你会得到相同的结果，但这几乎永远不会成为我们的问题。C++为我们提供了一个很好的函数来获取当前时间，`time()`，它位于`<ctime>`中。

让我们最后一次更新程序，并将`time()`作为参数传递给`std::srand()`，以便在每次运行时生成唯一的数字：

```cpp
// Here we will call srand() to set the seed for future rand() calls.
//srand(100);
srand(time(nullptr));

```

现在，每次运行程序，我们都会得到唯一的数字！你可能已经注意到，如果连续多次运行程序，第一个数字总是与上次运行非常相似。这是因为在运行之间时间变化不大。这意味着起始点彼此接近，结果也反映了这一点。

## 控制随机性是生成随机数的关键

生成随机数的过程是创建过程生成游戏内容的重要组成部分。有许多生成随机数据的方法，比如噪声地图和其他外部系统，但在本书中，我们将坚持使用这些简单的 C++函数。

我们希望系统足够可预测，以便我们作为开发者控制它们，但它们也应该足够动态，以便为玩家创建变化。这种平衡很难实现，有时游戏会做错。在本章的后面，我们将看一些在将过程生成纳入游戏项目时需要注意的事项，以避免出现这种情况。

# 在游戏中使用过程生成

现在我们知道了过程生成是什么，以及它是我们添加的随机元素，让我们能够创建动态系统，让我们来看一些游戏中如何使用它的例子。它可以被利用的方式有无数种，以下只是一些主要的实现方式。

## 节省空间

俗话说，需要是发明之母。作为今天的开发者，我们被我们可以使用的硬件宠坏了。即使是今天最基本的机器也会有一个 500 GB 大小的硬盘作为标准。考虑到仅仅几十年前，那将是 MB 而不是 GB，这是相当奢侈的。

游戏分发在当时也是一个非常不同的游戏。今天，我们要么在物理光盘上购买游戏，蓝光光盘每层提供了惊人的 25 GB，要么从互联网上下载，那里根本没有大小限制。记住这一点，现在考虑一下大多数**任天堂娱乐系统**（**NES**）游戏的大小仅为 128 到 384 KB！这些存储限制意味着游戏开发人员必须将大量内容放入一个小空间，程序生成是一个很好的方法。

由于过去无法构建大型关卡并存储它们，游戏被设计为通过算法构建它们的关卡和资源。你会把所有需要的资源放在存储介质上，然后让软件在玩家端组装关卡。

希望现在早期的桌子类比更容易理解了。就像平装家具更容易运输，然后可以在家里组装一样。随着硬件的发展，这已经不再是一个问题，但对于早期有存储问题的开发者来说，这是一个很好的解决方案。

## 地图生成

在现代视频游戏中，程序生成最突出的用途之一是生成游戏地图和地形。它可以被广泛使用，从生成简单的 2D 地图到完整的 3D 世界和地形。

在程序生成 3D 地形时，诸如**Perlin 噪声**生成的噪声图被用来表示通过产生具有高低浓度区域的图像来代表随机分布。这些数据，浓度和强度的变化，可以以许多方式使用。在生成地形时，它通常用于确定任意位置的高度。

![地图生成](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_01_04.jpg)

复杂的 3D 地形的程序生成超出了本书的范围。然而，我们将在本书的后面生成 2D 地牢。

### 提示

如果你想探索 3D 地形生成，请阅读诸如“分形地形生成”、“高度图”和“噪声生成”之类的术语。这将让你走上正确的道路。

# 纹理创建

程序生成的另一个突出例子是纹理的创建。与地形生成类似，纹理的程序生成使用噪声来创建变化。然后可以用来创建不同的纹理。不同的图案和方程也被用来创建更受控制的噪声，形成可识别的图案。

像这样程序性地生成纹理意味着你可以在没有任何存储开销的情况下拥有无限数量的可能纹理。从有限的初始资源池中，可以生成无尽的组合，下面的图像就是一个例子：

![纹理创建](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_01_05.jpg)

Perlin 噪声只是许多常用于程序生成的算法之一。研究这些算法超出了本书的范围，但如果你想进一步探索程序生成的用途，这将是一个很好的起点。

## 动画

传统上，游戏动画是由动画师创建的，然后导出为一个动画文件，可以直接在游戏中使用。这个文件将存储模型的每个部分在动画期间经历的各种动作。然后在运行时应用到游戏角色上。玩家当前的状态将决定应该播放哪种动画。例如，当你按下*A*键跳跃时，玩家将变为跳跃状态，并触发跳跃动画。这个系统运行良好，但非常死板。每一步、跳跃和翻滚都是相同的。

然而，程序生成可以用来创建实时的、动态的动画。通过获取角色骨骼的当前位置，并计算施加在它上面的多个力，可以计算出一个新的位置。程序动画最突出的例子是布娃娃物理效果。

## 声音

尽管不如前面的例子常见，程序生成也被用来创建游戏音效。这通常是通过操纵现有的声音来实现的。例如，声音可以被空间化，意味着当用户听到时，它似乎是来自特定位置。

在某种程度上，可以合成短暂的、一次性的音效，但由于它所带来的好处与实施它所需的工作量相比很少，它很少被使用。加载预制的声音会更容易得多。

### 注意

Sfxr 是一个小程序，可以从头开始生成随机音效。它的源代码是可用的。因此，如果你对声音合成感兴趣，它将作为一个很好的起点。你可以在[`github.com/grimfang4/sfxr`](https://github.com/grimfang4/sfxr)找到这个项目。

# 程序生成的好处

我们已经看了一些程序生成在游戏中的关键用途。现在让我们来看看它的一些最重要的好处。

## 可以创建更大的游戏

如果你的游戏世界是手工建造的，由于种种原因，它将有大小限制。每个物体都需要手动放置，每个纹理/模型都需要手工制作，等等。所有这些都需要时间和金钱。即使是最大的手工制作游戏世界的大小，比如《巫师 3：狂猎》和《侠盗猎车手 V》中所见的那样，也远远不及程序生成的世界可以实现的规模。

如果一个游戏正确地利用程序生成，理论上，世界的大小是没有限制的。例如，《无人之境》是一个设定在一个无限的、程序生成的银河系中的科幻游戏。然而，当你开始制作真正巨大的地图时，硬件成为了一个限制因素。生成的区域需要保存到磁盘中以便重新访问，这很快就会累积起来。例如，要在《我的世界》中生成最大的世界，你将需要大约 409PB 的存储空间来存储关卡数据！

## 程序生成可以用来降低预算。

制作游戏是昂贵的。非常昂贵。事实上，大多数 AAA 游戏的制作成本高达数千万，甚至数亿美元。在这么高的预算下，任何节省金钱的选择都是受欢迎的。程序生成可以做到这一点。

假设我们正在制作一个需要 100 种砖块纹理的游戏。传统上，你需要让你的艺术家创建每一块砖。虽然它们会有最高质量，但这将耗费时间和金钱。另外，通过利用程序生成技术，你可以让一个艺术家创建一些资源，并使用它们来生成你需要使用的资源。

这只是一个例子，建模、设计等也是如此。以这种方式使用程序生成有利有弊，但这是一个有效的选择。

## 游戏玩法的多样性增加

如果你的游戏世界是手工制作的，那么玩家的体验将是固定的。每个人都会收集相同的物品，地形都是一样的，因此整体体验也将是一样的。程序生成游戏的显著特点是体验不同。游戏中有一种未知的感觉，每次玩都会有一些新的东西等着你去发现。

## 增加了可重复性

让我们从上一点继续。如果一个游戏是线性的，没有任何程序生成，那么在玩过一次游戏后挑战就消失了。你知道情节，你知道敌人会在哪里，除非它有一个惊人的故事或机制，否则你不会想再玩一次游戏。

然而，如果你的游戏利用程序生成，那么每次运行游戏时挑战都是新的。游戏总是在不断发展；环境总是新的。如果你看看那些具有最大重玩价值的游戏，它们往往是给玩家最大控制权的游戏。大多数这类游戏都会利用某种形式的程序生成来实现。

# 程序生成的缺点

和任何事物一样，事情都有两面性。程序生成为游戏带来了无数可能性和增强，但在实施时也需要考虑一些因素。

## 对硬件的负担更重

正如我们现在所知，程序生成是通过运行算法来创建内容。这些算法可能非常复杂，需要大量的计算能力。如果你开发的游戏大量使用程序生成，你需要确保普通消费者的 PC 或游戏机能够满足其需求。

例如，如果你选择在开放世界游戏中以程序方式生成树木，那么每当该区域需要生成时，CPU 和 GPU 的负担都会很大。性能较差的电脑可能无法胜任，因此游戏可能会出现卡顿。

## 世界可能会感到重复

另一个潜在的缺点是世界可能会感到重复。如果你允许游戏系统生成非常大的世界，但使用了少量和基本的算法，那么必然会生成很多重复的区域。模式和重复的区域会很容易被发现，这将大大降低游戏的质量。

## 你牺牲了质量控制

计算机可能比我们人类更快地进行数字计算，但有一件事我们绝对比计算机优秀，那就是创造力。无论程序算法有多么神奇，都无法取代人类的触感。经验丰富的设计师为项目带来的微小变化和细微差别都会因此而牺牲。

这也意味着你无法保证所有玩家都能获得相同的游戏质量。有些玩家可能会生成一个非常棒的地图，有利于游戏进行，而其他人可能生成一个明显阻碍游戏进行的地图。

## 你可能会生成一个无法玩的世界

在前一点的极端情况下，可能会生成一个完全无法玩的关卡。这种风险取决于你的程序内容生成得有多好，但这一点应该始终被考虑。

在生成 3D 地形地图时，你可能会意外生成一个对玩家来说太高无法攀爬的地形，或者封锁了需要进入的区域。2D 地图也是如此。在本书的后面，我们将随机生成地牢房间。例如，我们需要确保每个房间都有有效的入口和出口。

## 很难编写固定的游戏事件

继续前面的观点，程序生成是不确定的。如果你周围的整个世界都是纯粹通过程序和随机生成的，那么几乎不可能编写固定的游戏事件。

游戏事件是预先编写的事件，而程序生成的本质是创建未经脚本的世界。让这两者共同工作是一个艰巨的挑战。因此，游戏往往会同时使用程序生成和预先制作的游戏开发。通过这样，你可以得到固定的游戏事件和时刻，这些是驱动叙事所需要的，而在所有这些之间，你可以为玩家创造一个独特和开放的世界，让他们自由地探索和互动。

# Rogue-like 游戏的简要历史

由于我们将实现我们所学的内容在一个类似 Rogue 的游戏中，让我们花一点时间来看看它们的历史。了解你所做的事情的起源总是很好的！

Rogue 是一款地牢爬行游戏，最初由*Michael Toy*和*Glenn Wichman*开发，并于 1980 年首次发布。地牢的每个级别都是随机生成的，其中包括对象的位置。Rogue 定义了地牢爬行类型，并成为许多后续游戏的灵感来源。这就是为什么我们称这种类型的游戏为**roguelikes**，因为它们确实像 Rogue！

自从诞生以来，程序生成一直是 Roguelike 游戏的关键元素。这就是为什么我选择这种类型的游戏来介绍这个主题。我们将一起重新创建定义这种类型游戏的标志性特征，并以非常实际和动手的方式来处理程序生成。

# 我们将如何实现程序生成

在书的开头，我简要概述了每一章和我们将在其中涵盖的内容。现在我们已经了解了程序生成是什么，让我们具体看看一些我们将实施它的方式，因为我们努力创建我们自己的 Roguelike 游戏。这个列表并不详尽。

## 填充环境

当我们第一次加载游戏时，我们的对象将处于固定位置。我们将通过实现本章学到的关于随机数生成的知识来开始我们的努力，以在随机位置生成我们的对象。

在本章的最后，有一些可选的练习，包括在不同范围的集合中生成数字。如果你还不熟悉，我建议完成它们，因为我们将依靠它来实现这一点。

## 创建独特的游戏对象

程序生成的我个人最喜欢的一个方面是创建独特的对象和物品。知道游戏中有各种各样的物品是很棒的。知道这些物品甚至还不存在，而且可能性是无限的，更好！

我们将从简单地随机初始化对象的成员变量开始，然后逐步提供我们对象独特的精灵和属性。我们还将研究创建动态类，可以从单个基类创建高度独特的对象。

# 创建独特的艺术

使用程序生成从头开始生成纹理和材料是一个非常庞大的主题。有很多方法可以实现这一点。传统上，我们使用像 Perlin 噪声这样的基础函数，然后用图案和颜色进行扩展。我们不会深入探讨这个话题。相反，我们将使用**Simple and Fast Multimedia Library** (**SFML**)的内置图像处理功能，在运行时创建独特的纹理。

从简单的方法开始，我们将改变图像属性，如大小、颜色和比例，以创建现有资产的变化。然后，我们将使用渲染纹理来动态组合多个精灵组件，以创建我们敌人的独特资产。

# 音频操作

与图形一样，SFML 提供了许多函数，允许我们修改声音。因此，我们将使用这些来改变声音效果的音调和音量，以创建变化。然后，我们将使用高级函数来创建 3D 空间化声音，通过我们的音频为场景带来深度。

## 行为和机械

不仅是静态物品和资源可以通过程序生成，为了增加游戏玩法的多样性，我们将使用一些程序技术来创建动态的游戏机制。具体来说，我们将创建一个系统，为玩家生成一个随机目标，并在达成目标时提供一个随机奖励。

我们还将给我们的敌人一些基本的**人工智能**（**AI**），以**A 星**（**A***）寻路的形式，让它们能够在关卡中追逐玩家。

## 地牢生成

在书的最后，一旦我们熟练掌握了使用**随机数生成器**（**RNG**）和程序系统，以及我们的游戏项目，我们将实现 roguelike 的定义特征；随机生成的地牢。

我已经多次提到程序生成可以用来创建理论上无尽的游戏世界。因此，我们将实现一个系统，我们访问的每个房间都是随机生成的，并且我们将使用我们在后面章节学到的图形操作技术为每个楼层赋予独特的感觉。

# 基于组件的设计

程序生成就是关于创建动态系统、对象和数据。因此，我们希望拥有最灵活的游戏框架，以便很好地整合这一点。实现这一点的方法之一是组件化设计。因此，最后，我们将快速地看一下它，将我们的项目分解为更多基于组件的方法。

# 完整的游戏

这些是我们将要实现的主要系统变化。中间会有很多内容，但这些例子将涵盖我们将使用的主要机制和技能。当我们到达书的末尾时，你将拥有一个完全可用的 roguelike 游戏，其中包括一个无尽的随机生成地牢，随机生成的物品出现在随机位置，地牢层中的程序纹理，以及随机敌人，所有这些都是使用灵活的基于组件的架构实现的。

你不仅会学习实现程序生成在你自己的游戏中所需的技能，还会看到它们如何在彼此的背景下运作。孤立的练习很好，但没有什么比在一个真实的例子上工作更好。

# 练习

为了让你测试本章内容的知识，这里有一些练习供你做。它们对本书的其余部分并不是必需的，但做这些练习将帮助你评估所学内容的优势和劣势。

1.  使用`std::rand()`函数和取模运算符（%），更新`random_numbers.cpp`以生成落在以下范围内的数字：

+   0 到 1000

+   150 到 600

+   198 到 246

1.  想出一种在运行时生成随机种子的新方法。有很多方法可以做到这一点。所以要有创意！在我的解决方案中，前几个数字总是相似的。看看你是否能生成一个减轻这一点的随机种子。

1.  看看你的游戏收藏，找出哪些地方使用了程序生成。

1.  以下哪些是程序生成的例子？

+   加载一首歌

+   布娃娃物理

+   在运行时创建独特的对象

# 摘要

在本章中，我们了解到程序生成是通过使用算法来创建内容。这个概念可以应用于所有数字媒体，并且在游戏中用于创建动态系统和环境。程序生成带来了更大的游戏、多样性和动态性；但控制力较小，可能会影响性能，因为它对硬件要求较高。现代游戏中程序生成最流行的用途包括地形生成、纹理创建和程序动画。

在下一章中，我们将看一下本书提供的项目。当我们学习创建程序化系统时，我们将在一个真实的游戏项目中实现它们，最终目标是创建一个使用程序生成的游戏，这是一个大量利用程序生成的类型。我们将回顾游戏模板，我们将使用的 SFML 模块，并设置项目。然后，我们将在您的系统上编译它。

如果您熟悉 C++游戏开发并且以前使用过 SFML，您可能已经熟悉下一章中介绍的概念。如果是这种情况，请随意浏览本章，直接进入第三章*使用 C++数据类型的 RNG*的编程。


# 第二章：项目设置和分解

在我们自己实现过程生成之前，我们将快速浏览一下本书提供的游戏模板。未来，重点将放在我们创建的过程系统上，而不是底层模板和引擎。因此，在开始之前，熟悉模板和引擎将是有益的。

我们还将看一下**Simple Fast Multimedia Library**（**SFML**），这是我们将要使用的框架。

在本章中，我们将涵盖以下主题：

+   选择**集成开发环境**（**IDE**）

+   提供的游戏模板的分解

+   SFML 概述

+   多态

+   项目设置和第一次编译

+   对象管道

# 选择 IDE

在做任何事情之前，您需要一个可靠的 C++ IDE。您可能已经有自己喜欢使用的 IDE。如果您已经有一个，那很好。但如果没有，这是我喜欢的两个 IDE 的简要摘要。

## Microsoft Visual Studio

Microsoft Visual Studio 是微软的行业标准 IDE。它支持多种语言，并提供大量的测试和兼容性工具。它还与许多微软服务绑定在一起，使其成为 Windows PC 上开发的首选。使用 Microsoft Visual Studio 的优缺点如下：

**优点：**

+   它有许多免费版本可用

+   Microsoft Visual Studio 支持多种语言

+   它得到了微软的广泛支持

+   它具有高度可定制的环境，可通过可停靠窗口进行定制

+   它具有智能代码补全功能

+   它与许多微软功能集成

**缺点：**

+   其完整版本非常昂贵

+   其免费版本受限

+   仅适用于 Windows PC

### 提示

Microsoft Visual Studio 和其他许多微软技术可供学生免费使用。有关更多信息，请访问[`www.dreamspark.com/Student/`](https://www.dreamspark.com/Student/)。

## Code::Blocks

Code::Blocks IDE 是一个免费、开源、跨平台的 IDE，用于 C、C++和 Fortran 编程语言的开发。它建立在插件架构之上，意味着可以通过安装各种插件来高度定制，以创建最适合您需求的 IDE。

**优点：**

+   它是免费的

+   它适用于所有操作系统

+   通过安装插件，它可以高度定制

+   它支持多个容器

+   它具有智能代码补全功能

**缺点：**

+   与 Microsoft Visual Studio 提供的功能和工具相比，它具有较少的功能和工具

这两个 IDE 都具有我们在 C++中创建游戏所需的功能。因此，一切都取决于个人偏好。我建议使用 Visual Studio，并且这是我在整本书中将使用的 IDE。

## 其他 IDE

Visual Studio 和 Code::Blocks 只是众多可用的 IDE 中的两个例子。如果您不喜欢这两个，以下是一些备选的跨平台 IDE。它们都能够开发 C++代码：

+   NetBeans（Windows、Mac OS X 和 Linux）

+   Eclipse（Windows、Mac OS X 和 Linux）

+   Code Lite（Windows、Mac OS X 和 Linux）

## 构建系统

使用构建系统是使用 IDE 的替代方法。这些系统将构建过程与您使用的 IDE 或代码编辑器分离，使您对过程有更多控制。构建系统允许您自动化构建过程的各个方面。它可能是一些简单的事情，比如递增构建号，或者高级的事情，比如自动化单元测试。

有许多可用的构建系统，包括以下内容：

+   Make

+   CMake

+   MSBuild

+   Gradle

我们不会在书中涵盖这些系统的设置或使用。因此，请前往每个系统的相关网站查找文档和使用说明。

### 提示

有关构建系统及其提供的好处的更多信息，请访问[`www.cs.virginia.edu/~dww4s/articles/build_systems.html#make`](http://www.cs.virginia.edu/~dww4s/articles/build_systems.html#make)。

# 分解游戏模板

学习的最佳方式是通过实践。例子很好，但没有什么比真正投入并在一个真正的游戏中工作更好。提供的游戏模板将允许我们在一个真正的游戏中实现我们将要学习的系统，而不是它们成为一系列孤立的练习。

熟悉这个模板不仅会帮助使本书中的代码示例更清晰，还会使每章末尾的练习更容易。这也将使您能够在项目完成后使用所学知识来实现自己的系统。

## 下载模板

在开始之前，请下载游戏模板，以便在浏览一些关键点时可以使用源代码。模板可在 Packt Publishing 官方网站[`www.packtpub.com/support`](http://www.packtpub.com/support)上下载。

我们很快会设置它，但现在让我们快速查看一些其关键特性。

## 类图

项目下载包中包含了我们解决方案的完整类图像。如果您在任何时候对模板的结构有任何疑问，请参考该图表。

类图是查看软件完整结构的好方法。随着游戏变得越来越大，继承结构变得越来越复杂。如果您有可用的工具，定期查看类图并保持其结构是一个好主意。这将帮助您确定您的结构需要哪些工作，以及哪些不需要。

### 提示

在 Microsoft Visual Studio 中创建图表受限于专业版或更高版本。但是，有各种免费工具可用，例如 Doxygen [`www.stack.nl/~dimitri/doxygen/index.html`](http://www.stack.nl/~dimitri/doxygen/index.html)和 ArgoUML [`argouml.tigris.org/`](http://argouml.tigris.org/)，它们可以从源代码创建 UML 图表。

## 对象层次结构

模板中的所有对象都遵循一组继承层次结构。所有类的基础是`Object`类。这提供了一个`sprite`，一个`position`，一个`Update()`虚函数和一个`Draw()`虚函数。

所有类都从这个基类扩展，通过覆盖这些虚拟函数来实现它们自己的行为。在我们的`main`游戏类中，我们为主要基类创建容器，将所有物品和敌人分组到可以轻松迭代的单个集合中：

```cpp
std::vector<std::unique_ptr<Item>> m_items;
std::vector<std::unique_ptr<Enemy>> m_enemies;
```

基类指针的向量使我们能够利用多态性，并将从相同父类继承的所有类存储在单个数据结构中。如果您对多态性不熟悉，不要担心。在本章的末尾，我们将研究多态性和对象管道，以将对象添加到游戏中。

### 提示

我们在 C++11 中使用`std::unique_ptr`智能指针而不是原始指针。有关智能指针及其好处的更多信息，请访问[`msdn.microsoft.com/en-us/library/hh279674.aspx`](https://msdn.microsoft.com/en-us/library/hh279674.aspx)。

## 级别数据

提供的游戏模板是一个`roguelike`模板。鉴于此，级别被描述为一个网格。在这种情况下，表示网格的最佳方式是使用 2D 数组，并且为了存储我们需要的所有信息，我们将使用名为`Tile`的自定义数据类型，如下所示：

```cpp
/**
 * A struct that defines the data values our tiles need.
 */ 
struct Tile {
TILE type;         // The type of tile this is.

int columnIndex;   // The column index of the tile.

int rowIndex;      // The row index of the tile.

sf::Sprite sprite; // The tile sprite.

int H;             // Heuristic / movement cost to goal.

int G;             // Movement cost. (Total of entire path)

int F;             // Estimated cost for full path. (G + H)

Tile* parentNode;  // Node to reach this node.
};
```

这个`struct`允许我们拥有一个`Tile`类型的单个 2D 数组，可以存储每个瓦片需要的所有信息。在创建这种类型的游戏时，这种方法非常常见。该数组位于`Level`类中，在游戏开始时实例化。它封装了与级别相关的所有数据。

目前，级别数据存储在一个简单的文本文件中，在运行时通过对定义所有瓦片类型的枚举进行简单查找来解析。我们将在本章末尾的示例中进行这方面的工作。

以下屏幕截图显示了级别数据是如何保存的：

![级别数据](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_02_02.jpg)

## 碰撞

碰撞是基于您当前所站的瓦片的`ID`。每当玩家开始移动时，将计算成功移动后他们将处于的位置。然后使用这个位置来计算他们所在的网格“瓦片”。然后使用这个瓦片来确定应执行什么操作；操作可能涉及执行阻塞移动、拾取物品或受到伤害。

### 注意

这种类型的碰撞可能导致子弹穿过纸的问题，但鉴于游戏的速度，这在我们的情况下不是问题。如果您不知道这个问题是什么，请在网上查找；它可能在以后的项目中让您出乎意料！

## 输入

输入是通过自定义的静态`Input`类处理的。它的工作方式很像 SFML 提供的`Input`类，但它将多个可能的输入组合成一个调用。例如，当检查左键是否按下时，它将检查*A*键、左箭头键、左*D*-Pad 和模拟摇杆。如果使用标准的`Input`类来完成这个任务，您将不得不分别检查所有四个。提供的`Input`类简化了这一过程。

在`input.h`中定义了一个公共的键码枚举，并包含以下用于轮询输入的值：

```cpp
/**
 * An enum denoting all possible input keys.
 */
enum class KEY
{
  KEY_LEFT,
  KEY_RIGHT,
  KEY_UP,
  KEY_DOWN,
  KEY_ATTACK,
  KEY_ESC
};
```

要检查输入，我们只需静态调用`Inputs IsKeyPressed(KEY keycode)`，传递前面提到的有效键码之一。

# SFML 简单快速多媒体库

虽然您可能有 C++的经验，但可能没有 SFML 的先验经验。没关系，本书不假设任何先验经验，所以现在让我们简要地浏览一下它

## 定义 SFML

**SFML**，简称**Simple and Fast Multimedia Library**，是一个软件开发库，提供了对多个系统组件的简单访问。它是用 C++编写的，并分为以下简洁的模块：

+   系统

+   窗口

+   图形

+   音频

+   网络

使用这种架构，您可以轻松地选择如何使用 SFML，从简单的窗口管理器到使用 OpenGL，再到完整的多媒体库，能够制作完整的视频游戏和多媒体软件。

## 为什么我们会使用 SFML

SFML 既是免费的、开源的，又有一个充满活力的社区。在官方网站上有活跃的论坛和一系列优秀的教程，为那些希望学习的人提供了丰富的资源。使用 SFML 的另一个引人注目的原因是它是用 C++编写的，并且有许多其他语言的绑定，这意味着您几乎可以用任何您喜欢的语言编程。您可能会发现您希望使用的语言已经有了绑定！

SFML 最吸引人的特点是它是一个多平台库。使用 SFML 编写的应用程序可以在大多数常见操作系统上编译和运行，包括 Windows、Linux 和 Mac OS X，在撰写本书时，Android 和 iOS 版本即将上市。

### 提示

为了使您的应用程序跨各种平台兼容，请记住您还必须确保您的本地代码或其他使用的库（如果有的话）也是跨平台兼容的。

## 学习 SFML

在本书的过程中，我们将研究 SFML 的特点和功能，以实现我们的过程系统，但不会更多。我们不会深入研究这个库，因为那需要一整本书。幸运的是，Packt Publishing 出版了一些专门针对这个问题的好书：

+   SFML 游戏开发网址[`www.packtpub.com/game-development/sfml-game-development`](https://www.packtpub.com/game-development/sfml-game-development)

+   SFML 基础位于[`www.packtpub.com/game-development/sfml-essentials`](https://www.packtpub.com/game-development/sfml-essentials)

+   SFML 蓝图位于[`www.packtpub.com/game-development/sfml-blueprints`](https://www.packtpub.com/game-development/sfml-blueprints)

如果您想了解更多关于 SFML 的信息，那么这些书是一个很好的起点。官方 SFML 网站上也有一些很棒的教程和活跃的论坛。访问[`www.sfml-dev.org/learn.php`](http://www.sfml-dev.org/learn.php)获取更多信息。

## 替代方案

虽然 SFML 是跨平台游戏开发的一个很好的选择，但并不是唯一的选择。有许多出色的库可供选择，每个都有自己的方法和风格。因此，虽然我们将在这个项目中使用 SFML，但建议您为下一个项目四处寻找。您可能会遇到您新的最喜欢的库。

以下是一些建议供将来参考：

+   SDL2 位于[`www.libsdl.org/download-2.0.php`](https://www.libsdl.org/download-2.0.php)

+   Allegro 位于[`liballeg.org/`](http://liballeg.org/)

+   MonoGame 位于[`www.monogame.net/downloads/`](http://www.monogame.net/downloads/)

# 多态

在开始游戏模板之前，我们将看一下多态。这是面向对象编程的一个重要特性，我们将在许多我们将创建的过程系统中充分利用它。因此，重要的是您不仅要对它有一个扎实的理解，还要了解用于实现它的技术和潜在的陷阱。

### 提示

如果您已经对多态有很好的理解，可以跳过本节，或者访问[`msdn.microsoft.com/en-us/library/z165t2xk(v=vs.90)`](https://msdn.microsoft.com/en-us/library/z165t2xk(v=vs.90))以深入讨论该主题。

多态是通过独立实现的共同接口访问不同对象的能力。这是一个非常正式的定义。因此，让我们将其分解为用于实现它的各种技术和特性。值得注意的是，虽然多态是游戏行业的标准方法，但它仍然是编程的其他学派之一。

## 继承

继承可能是实现多态的关键组成部分。继承是通过继承其变量和函数来扩展现有类，然后添加自己的内容。

让我们看一个典型的游戏示例。假设我们有一个有三种不同武器的游戏：剑、魔杖和斧头。这些类将共享一些公共变量，如攻击力、耐久度和攻击速度。创建三个单独的类并将这些信息添加到每个类中将是一种浪费，因此我们将创建一个包含所有共享信息的父类。然后，子类将继承这些值并按照自己的方式使用它们。

继承创建了一个“是一个”关系。这意味着由于斧头是从武器继承而来，斧头就是一种武器。在父类中创建一个共同接口，并通过子类以独特的方式实现它的概念是实现多态的关键。

### 注意

通过接口，我指的是父类传递给子类的函数和变量集合。

下图以简单的类图形式说明了这种情况：

![继承](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_02_03.jpg)

在各个武器中突出显示的`Attack()`函数都是从**Weapon**类中定义的单个`Attack()`函数继承而来的。

### 提示

为了保持适当的封装和范围，重要的是给予我们的变量和函数正确的可见性修饰符。如果您对此不确定，或者需要一个快速提醒，可以访问[`msdn.microsoft.com/en-us/library/kktasw36.aspx`](https://msdn.microsoft.com/en-us/library/kktasw36.aspx)。

## 虚函数

继续使用通用武器示例，我们现在有一个父类，提供了许多函数和变量，所有子类都将继承。为了能够表示与父类不同的行为，我们需要能够重写父函数。这是通过使用虚函数实现的。

虚函数是可以被实现类重写的函数。为了实现这一点，父类必须将函数标记为虚函数。只需在函数声明前加上 virtual 关键字即可：

```cpp
Virtual void Attack();
```

在子类中，我们可以通过提供自己的定义来重写该函数，前提是两个函数的签名相同。这种重写是自动完成的，但是 C++11 引入了`override`关键字，用于明确指示函数将重写父类的函数。override 关键字是可选的，但被认为是良好的实践，并且建议使用。使用方法如下：

```cpp
Void Attack() override;
```

C++11 还引入了`final`关键字。该关键字用于指定不能在派生类中重写的虚函数。它也可以应用于不能被继承的类。您可以如下使用 final 关键字：

```cpp
Void Attack() final;
```

在这种情况下，`Attack()`函数无法被继承类重写。

## 纯虚函数

我们刚刚介绍的虚函数允许继承类*可选*地重写函数。重写是可选的，因为如果在子类中找不到默认实现，父类将提供默认实现。

然而，纯虚函数不提供默认实现。因此，它必须由继承类实现。此外，如果一个类包含纯虚函数，它就变成了抽象类。这意味着它无法被实例化，只有继承类可以，前提是它们为纯虚函数提供了实现。如果一个类从抽象类继承，并且没有为纯虚函数提供实现，那么该类也变成了抽象类。

声明纯虚函数的语法如下：

```cpp
Virtual void Attack() = 0;
```

在`Weapon`父类的例子中，它被`Sword`，`Axe`和`Wand`继承，将`Weapon`设为抽象类是有意义的。我们永远不会实例化`Weapon`对象；它的唯一目的是为其子类提供一个公共接口。由于每个子类都需要有一个`Attack()`函数，因此在`Weapon`中将`Attack()`函数设为纯虚函数是有意义的，因为我们知道每个子类都会实现它。

## 指针和对象切片

多态谜题的最后一部分是指针的使用。考虑以下两行代码：

```cpp
Weapon myWeapon = Sword();
Std::unique_ptr<Weapon> myWeapon = std::make_unique<Sword>();
```

在第一行中，我们没有使用指针；在第二行中，我们使用了指针。这似乎是一个小差别，但它产生了极其不同的结果。为了正确演示这一点，我们将看一个定义了多种武器的小程序。

### 提示

如果`Weapon`类包含一个纯虚函数，前面代码的第一行将无法编译，因为它是抽象的，无法实例化。

您可以从 Packt Publishing 网站下载此程序的代码。它将在`Examples`文件夹中，项目名称为`polymorphism_example`：

```cpp
#include <iostream>

// We're using namespace std here to avoid having to fully qualify everything with std::
using namespace std;

int main()
{

  // Here we define a base Weapon struct.
  // It provides a single data type, and a method to return it.
  struct Weapon
  {
    string itemType = "Generic Weapon";

    virtual string GetItemType()
    {
      return itemType;
    }
  };

  // Here we inherit from the generic Weapon struct to make a specific Sword struct.
  // We override the GetItemType() function to change the itemType variable before returning it.
  struct Sword : public Weapon
  {
    string GetItemType() override
    {
      itemType = "Sword";
      return itemType;
    }
  };

  Weapon myWeapon = Sword();

  // output the type of item that weapon is then wait.
  cout << myWeapon.GetItemType().c_str() << endl;
  std::cin.get();

  return 0;
}
```

在这段代码中，我们创建了一个基本结构`Weapon`。然后我们从中继承，创建了一个名为`Sword`的具体实现。基本`Weapon`结构定义了`GetItemType()`函数，而`Sword`重写它以更改并返回物品类型。这是一个很简单的继承和多态的例子，但有一些重要的事情我们需要知道，否则可能会让我们困惑。

目前，代码中`Weapon`对象是这样实例化的：

```cpp
Weapon myWeapon = Sword()
```

让我们运行代码，看看我们得到了什么：

![指针和对象切片](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_02_04.jpg)

尽管我们为`myWeapon`分配了一个`Sword`对象，但它是一个`Weapon`对象。这里发生了什么？问题在于`myWeapon`被赋予了一个固定类型的武器。当我们尝试为它分配一个`Sword`对象时，它被传递给`Weapon`的`copy`构造函数并被切割，只留下一个`Weapon`对象。因此，当我们调用`GetItemType()`函数时，我们调用的是`Weapon`中的函数。

### 提示

有关对象切割的更深入解释，请访问[`www.bogotobogo.com/cplusplus/slicing.php`](http://www.bogotobogo.com/cplusplus/slicing.php)。

有两种方法可以链接 SFML：**静态**和**动态**库。静态库是编译到可执行文件中的库。这意味着您的可执行文件会更大，但您不必担心在运行时获取库。动态库不会链接到可执行文件中，这会导致可执行文件更小，但会创建依赖关系。

```cpp
  // Create our weapon object.
  //Weapon myWeapon = Sword();
 std::unique_ptr<Weapon> myWeapon = std::make_unique<Sword>();

```

### 提示

像`unique_ptr`这样的智能指针需要`include <memory>`。所以不要忘记将其添加到文件的顶部。

既然我们现在把`myWeapon`改成了指针，我们还需要改变以下内容：

```cpp
// Output the type of item that weapon is then wait.
//cout << myWeapon.GetItemType().c_str() << endl;
cout << myWeapon->GetItemType().c_str() << endl;

```

在使用指针时，我们需要使用`->`运算符来访问它的变量和函数。现在，让我们重新运行代码，看看输出是什么：

![指针和对象切割](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_02_05.jpg)

下载 SFML

由于`myWeapon`现在是指向`Weapon`对象的指针，我们避免了对象切割。由于`Sword`是从`Weapon`派生出来的，指向内存中的`Sword`并不是问题。它们共享一个公共接口，因此我们实现了这种重写行为。回到最初的定义，多态性是通过独立实现的公共接口访问不同对象的能力。

# 接下来，您需要为您的编译器选择正确的软件包。如果您使用 Microsoft Visual Studio，您只需要选择与您版本匹配的年份，如果您使用 Code::Blocks，或者其他任何 IDE，选择您正在使用的**GNU 编译器集合（GCC）**的版本。

本书提供了一个专门为本书创建的`roguelike`游戏的模板。它被设计为接收我们将要涵盖的工作，并且在本书结束时，您将拥有一个完全功能的 roguelike 游戏，实现了您将学到的一切。现在我们已经复习了我们对多态性的理解，让我们开始设置模板。第一步是下载并链接 SFML。

### 提示

所提供的项目链接了 SMFL 32 位 Windows 库。这应该适合大多数系统。如果这与您的系统兼容，您可以跳过以下步骤。

## 下载 SFML

SFML 有许多不同的预编译软件包可用。例如，在撰写本书时的最新版本仅在 Windows 上就有 12 个软件包可用，因此重要的是您为您的系统下载正确的软件包。以下步骤将帮助您下载并设置 SFML：

1.  访问[`www.sfml-dev.org/download.php`](http://www.sfml-dev.org/download.php)查找 SFML 下载页面。除非您特别需要针对 64 位机器，否则选择 32 位库。32 位程序在 64 位机器上可以正常工作。

1.  这一次，我们按照预期调用了`Sword`结构中的重写函数，这归结为我们如何定义`myWeapon`。

1.  一旦确定了适合您系统的正确版本，请下载并提取`.zip`文件的内容到您想要保存 SFML 的位置。这个位置与您的项目无关；它们不需要共享一个目录。

### 提示

如果您希望或需要这样做，可以自己构建 SFML 以创建自定义软件包。有关如何执行此操作的说明，请访问[`github.com/SFML/SFML`](https://github.com/SFML/SFML)。

## 为了避免这种情况并充分利用多态性，我们需要使用指针。让我们对代码进行以下更改：

链接 SFML

### 提示

有关`static`和`dynamic`库之间的区别的更多信息，请访问[`www.learncpp.com/cpp-tutorial/a1-static-and-dynamic-libraries/`](http://www.learncpp.com/cpp-tutorial/a1-static-and-dynamic-libraries/)。

我们将进行动态链接，这意味着要运行游戏，您将需要`.dll`文件。

为此，首先从 SFML 源中将游戏需要的`DLL`文件复制到项目的可执行位置。将所有文件从`<sfml-install-path/bin>`复制到`<project-location/Debug>`。

接下来，我们必须告诉编译器 SFML 头文件在哪里，链接器输出库在哪里。头文件是`.hpp`文件，库是`.lib`文件。这一步根据您使用的 IDE 有所不同。

在 Microsoft Visual Studio 中，将以下内容添加到项目的属性中：

+   SFML 头文件的路径（`<sfml-install-path>/include`）到**C/C++** | **General** | **Additional Include Directories**

+   SFML 库的路径（`<sfml-install-path>/lib`）到**Linker** | **General** | **Additional Library Directories**

在 Code::Blocks 中，将以下内容添加到项目的**Build Options**和**Search Directories**选项卡：

+   SFML 头文件的路径（`<sfml-install-path>/include`）到`Compiler`搜索目录

+   SFML 库的路径（`<sfml-install-path>/lib`）到`Linker`搜索目录

### 提示

这些路径在`Debug`和`Release`配置中是相同的。因此，它们可以全局设置为项目。

最后一步是将我们的项目链接到正在使用的 SFML 库。SFML 由五个模块组成，但我们不会使用所有模块。我们使用`System`，`Windows`，`Graphics`和`Audio`。因此，我们只需要链接到这些库。与上一步不同，项目配置很重要。`Debug`和`Release`配置有单独的库。因此，您需要确保链接正确的库。

在`Debug`配置中，我们需要添加以下库：

+   `sfml-system-d.lib`

+   `sfml-window-d.lib`

+   `sfml-graphics-d.lib`

+   `sfml-audio-d.lib`

现在，对于**Release**配置做同样的事情。但是，从每个中删除`-d`。例如，在**Debug**配置中添加`sfml-system-d.lib`，在**Release**配置中添加`sfml-system.lib`。

要将它们添加到 Microsoft Visual Studio 中，必须通过导航到**Linker** | **Input** | **Additional Dependencies**将它们添加到项目的属性中。

要将它们添加到 Code::Blocks 中，必须在**Linker Settings**选项卡下的项目构建选项的**Link Libraries**列表中添加它们。

### 提示

如果您对此设置有任何疑问，请访问[`www.sfml-dev.org/learn.php`](http://www.sfml-dev.org/learn.php)获取完整的详细信息以及图片。

## 运行项目

现在 SFML 已链接到我们的项目，我们应该准备进行第一次构建。以下截图显示了我们目前空白的地牢游戏：

![运行项目](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_02_06.jpg)

目前，我们有一个可以运行的应用程序，在一个固定的房间中生成一个玩家。第一个任务涉及添加一个项目。

## 添加一个项目

我们创建的所有项目都需要继承自基类`Item`，因为所有游戏项目都存储在`std::unique_ptr<Item>`类型的单个向量中。通过这种数据结构，我们可以利用多态性，并将所有项目子类存储在一个结构中；通过这种方式，我们可以更新和绘制每个项目。

要添加到这个向量中，只需通过唯一指针实例化一个新项目。然后，使用`.push_back()`方法将其添加到向量中。由于我们使用的是唯一指针，因此必须使用`std::move()`来实现。

### 提示

如果您不清楚为什么我们在这里必须使用`std::move`，请在互联网上搜索唯一指针。

在`Game::PopulateLevel`函数中，让我们添加一个宝石项目，如下所示：

```cpp
// Create a gem object.
std::unique_ptr<Gem> gem = std::make_unique<Gem>();

// Set the gem position.
gem->SetPosition(sf::Vector2f(m_screenCenter.x + 50.f, m_screenCenter.y));

// Add the gem to our collection of all objects.
m_items.push_back(std::move(gem));

```

我们所要做的就是通过一个独特的指针创建一个新对象，给它一个位置，然后使用 `std::move` 函数将其添加到关卡中所有物品的列表中。简单！

## 更新和绘制

一旦物品被添加到所有对象的向量中，它将自动更新：

```cpp
// Update all items.
UpdateItems(playerPosition);
```

这个函数遍历所有的物品，检查它们是否被收集；如果不是，就更新它们。每个对象的 `Update()` 函数都有一个名为 `timeDelta` 的参数。这是一个包含自上次更新以来经过的时间的浮点数。它在主游戏循环中用于保持游戏逻辑固定在 60 fps。

### 提示

要了解更多关于主游戏循环的信息，请访问 [`gafferongames.com/game-physics/fix-your-timestep/`](http://gafferongames.com/game-physics/fix-your-timestep/)，这是一个关于这个主题的很棒的文章。

物品的绘制方式类似；它们的容器只是在 `Game::Draw` 函数中进行迭代。循环如下：

```cpp
// Have all objects draw themselves. 
for (const auto& item : m_items) 
{ 
    item->Draw(m_window, timeDelta); 
}
```

`m_window` 变量是一个指向渲染窗口的指针。因此，我们将它传递给每个对象，以便它可以用它来绘制自己。

现在，如果你运行游戏，你会看到房间里的宝石和金子，就像下面的截图所示：

![更新和绘制](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_02_07.jpg)

# 练习

为了帮助你测试本章内容的知识，这里有一些练习题供你练习。它们对于本书的其余部分并不是必要的，但是练习它们将有助于你评估所涵盖材料的优势和劣势。

1.  为你的游戏创建一个名称，并更改主窗口的文本以反映这一变化。

1.  考虑以下代码：

```cpp
class A
{
public:
    int x;
protected:
    int y;
private:
    int z;
};

class B : protected A
{

};
```

`B` 类中 `x`、`y` 和 `z` 的可见性是什么？

1.  在关卡中添加更多物品。

# 总结

在本章中，我们做了一些准备工作，以便开始编写游戏并创建程序系统。我们看了看将要使用的软件和库，以及我们将扩展的游戏模板。我们还快速学习了多态性和实现它的技术。

我们现在准备开始创建我们自己的程序系统。我们刚刚介绍的基础工作并不是非常令人兴奋，但对于理解我们将要涉及的工作至关重要。在下一章中，我们将利用我们在 C++ 数据类型中学到的关于随机数生成的知识来生成随机物品，并给我们的玩家随机属性。


# 第三章：使用 C++数据类型进行 RNG

在第一章中，*程序化生成简介*，我们了解到伪随机数生成是随机程序生成的核心。请记住，程序化系统本质上不是随机的，我们需要引入随机性。为了开始我们的旅程，我们将研究一系列不同的 C++数据类型，并使用随机数生成器（RNG）在运行时为它们赋予随机值。在随机但仍受控的方式下使用核心 C++数据类型的能力将成为我们未来所有系统的基础。

在本章中，我们将涵盖以下主题：

+   设置游戏种子

+   枚举器

+   随机设置布尔值

+   访问数组中的随机元素

+   生成随机字符串

+   随机数分布

# 设置游戏种子

在做任何事情之前，我们需要设置游戏种子。如果没有种子，我们每次运行游戏时都会得到相同的结果。正如我们所学的，这只需要我们调用`std::srand()`函数并传递一个随机参数作为种子。我们将使用当前系统时间作为我们的种子，对我们的目的来说已经足够随机了。

我们对`std::srand()`函数的调用是任意的，只要在对`std::rand()`函数的任何调用之前调用它即可。文件`main.cpp`包含了函数`main()`，这是应用程序的入口点。我们将在这里调用`std::srand()`函数。

我们更新后的`main()`函数现在应该是这样的：

```cpp
// Entry point of the application.
int main()
{
    // Set a random seed.
    std:: srand(static_cast<unsigned int>(time(nullptr)));

    // Create the main game object.
    Game game;

    // Create a Boolean that we can store out result it.
    bool result;

    // Initialize and run the game object.
    result = game.Initialize();

    if (result)
    {
        game.Run();
    }

    // Shutdown and release the game object.
    game.Shutdown();

    // Exit the application.
    return 0;
}
```

现在每次运行游戏时，我们都会设置一个随机种子，因此我们对`std::rand()`的调用会产生唯一的结果。

### 提示

如果您希望游戏在运行之间保持一致，可以使用硬编码的值作为种子。只是不要忘记改回来，否则以后会想为什么事情不随机！

# 随机设置布尔值

也许最简单的数据类型是谦卑的布尔值。只有两种状态，true 和 false，应该不难随机设置！当表示为整数时，这两种状态具有以下属性：

+   False = 0 或更低

+   True = 1 或更高

因此，要随机分配一个布尔值，我们只需要生成数字 0 或 1。 

## 生成 0 到 1 之间的数字

在第一章中，*程序化生成简介*，我们介绍了在特定范围内生成随机数。现在我们将把它用起来。使用`std::rand()`函数，我们将生成一个介于 0 和 1 之间的数字：

```cpp
std::rand() % 2;
```

### 提示

请记住，`std::rand()`生成一个介于`0`和`RAND_MAX`之间的数字。然后我们计算该结果除以 2 的余数。这样就只剩下了 0 和 1 的范围。

`bool`不一定要用`true`或`false`关键字设置。您可以将整数赋给`bool`，其状态将由整数的值决定，使用前面规定的规则。小于 1 的任何数字都是 false，大于 0 的任何数字都是 true。这意味着我们可以直接将结果传递给 bool：

```cpp
bool myBool = std::rand() % 2;
```

将这些放在一起，我们可以创建一个简单的控制台应用程序，每次用户按下*Enter*键时都会随机输出 true 或 false。

您可以从 Packt Publishing 网站下载此程序的代码。它将在`Examples`文件夹中，项目名称为`random_boolean`：

```cpp
#include <iostream>

using namespace std;

int main()
{
  // Loop forever.
  while (true)
{
    // Generate a number between 0 and 1.
    bool myBool = rand() % 2;
    if (myBool)
    {
        cout << "true";
    }
    else
    {
        cout << "false";
    }
    return 0;
}
```

这段代码的输出结果如下：

![生成 0 到 1 之间的数字](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_03_01.jpg)

每次我们按下*Enter*键，我们都会得到一个随机的布尔值。即使是这种简单的随机生成也可以让我们开始构建我们的程序化地牢游戏。让我们立即将其应用到房间创建时物品的生成上。

### 提示

请记住，在这个小例子应用程序中，我们没有随机设置种子。因此，每次运行程序时，该程序将生成相同的值序列。

## 选择物品是否生成

当前，当我们启动游戏时，宝石和黄金物品总是会生成。让我们使用这个随机布尔赋值来决定是否创建这两个物品。为了实现这一点，我们将封装它们的生成代码在一个`if`语句中，其参数将是我们随机布尔赋值的结果。

`Game::PopulateLevel`方法是我们生成物品的地方。我们将用以下代码替换当前的代码：

```cpp
// Populate the level with items.
void Game::PopulateLevel()
{
    // A Boolean variable used to determine if an object should be spawned.bool canSpawn;

    // Spawn gold.
    canSpawn = std::rand() % 2;
    if (canSpawn)
    {
       std::unique_ptr<Gold> gold = std::make_unique<Gold>();
       gold->SetPosition(sf::Vector2f(m_screenCenter.x - 50.f, m_screenCenter.y));
       m_items.push_back(std::move(gold));
    }

    // Spawn a gem.
    canSpawn = std::rand() % 2;
    if (canSpawn)
    {
       std::unique_ptr<Gem> gem = std::make_unique<Gem>();
       gem->SetPosition(sf::Vector2f(m_screenCenter.x + 50.f, m_screenCenter.y));
       m_items.push_back(std::move(gem));
    }
}
```

现在，每次我们运行游戏，宝石和黄金是否生成都是随机的。

![选择物品是否生成](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_03_02.jpg)

这是一个简单的改变，但是创建程序生成游戏的第一步。没有单一的算法或函数可以使游戏程序化。这是一系列小技巧的集合，比如这样的技巧可以使系统在运行时不可预测和确定。

# 随机数分配

让我们在随机数生成的基础上分配随机数字。我们首先生成 0 到 100 之间的`n`个数字。如果我们把它们加在一起，我们就得到一个随机总数，其中我们的每个单独的数字代表了一个百分比。然后我们可以取得我们目标数字的百分比来得到一个随机部分。以下代码演示了这一点，并会让它更清晰。

您可以从 Packt 网站下载此程序的代码。它将在`Examples`文件夹中，项目名称为`random_distribution`：

```cpp
#include <iostream>

using namespace std;

// Entry method of the application.
int main()
{
  // Create and initialize our variables.
  int upperLimit = 0;

  // Output instructions.
  cout << "Enter a number, and we'll split it into three random smaller numbers:" << endl;
  cin >> upperLimit;
  cout << endl;

  float number1Bias = rand() % 101;
  float number2Bias = rand() % 101;
  float number3Bias = rand() % 101;

  float total = number1Bias + number2Bias + number3Bias;

  // Output the numbers.
  cout << upperLimit * (number1Bias / total) << endl;
  cout << upperLimit * (number2Bias / total) << endl;
  cout << upperLimit * (number3Bias / total) << endl;

  // Pause so we can see output.
  cin.get();
  cin.get();

  // Exit function.
  return 0;
}
```

这种方法确保了数字的每个部分都是完全随机的。需要考虑一个轻微的舍入误差，但这对我们的应用程序不是问题。

![随机数分配](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_03_03.jpg)

让我们不浪费时间，将这项新技能应用到游戏中！

# 给玩家随机属性

这种随机分配数字的经典方式是给玩家随机属性。传统上，游戏中的角色会获得`n`个属性点，由玩家来分配。由于我们正在制作一个程序生成游戏，我们将随机分配它们，以创建程序生成的角色属性。

为此，我们需要将以前的代码与玩家属性变量的赋值连接起来。我们的玩家属性目前是固定的，并且是以下方式分配的：

```cpp
m_attack = 10;
m_defense = 10;
m_strength = 10;
m_dexterity = 10;
m_stamina = 10;
```

让我们用以下代码替换它来随机分配属性。我们还会给玩家添加一个变量，这样我们就可以改变玩家有多少`stat`点可以分配。

首先，将以下变量添加到玩家中，并不要忘记将其添加到我们的初始化列表中：

```cpp
int m_statPoints;
```

现在让我们使用这个来给我们的玩家随机属性：

```cpp
// Randomly distribute other stat.
m_statPoints = 50;

float attackBias = std::rand() % 101;
float defenseBias = std::rand() % 101;
float strengthBias = std::rand() % 101;
float dexterityBias = std::rand() % 101;
float staminaBias = std::rand() % 101;

float total = attackBias + defenseBias + strengthBias + dexterityBias + staminaBias;

m_attack += m_statPoints * (attackBias / total);
m_defense += m_statPoints * (defenseBias / total);
m_strength += m_statPoints * (strengthBias / total);
m_dexterity += m_statPoints * (dexterityBias / total);
m_stamina += m_statPoints * (staminaBias / total);
```

每次我们加载游戏时，我们的玩家的属性点都是随机分配的。这种随机分配一定数量的方法可以用在很多其他地方，比如在玩家之间分享战利品，或者在多个实体之间分配伤害。

![给玩家随机属性](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_03_04.jpg)

# 访问集合中的随机元素

当我们有类似对象的集合时，它们通常存储在数组和向量等结构中。通常在处理这些结构时，我们访问特定的元素，它们的统一性和顺序使它们有用。

要访问特定的元素，我们只需提供它在集合中的索引。因此，要访问数组的一个随机元素，我们只需提供一个随机索引，这只是生成一个随机数的简单情况。

让我们看一个例子。在下面的例子中，我们创建了一个字符串向量，其中我们填充了动物的名字。每次我们按回车键，我们通过生成一个 0 到向量大小之间的数字来访问向量的一个随机元素。

您可以从 Packt 网站下载此程序的代码。它将在`Examples`文件夹中，项目名称为`random_element`：

```cpp
#include <iostream>
#include <vector>

using namespace std;

// Entry method of the application.
int main()
{
  // Create and populate an array of animals.
  vector<string> animals = { "Dog", "Cat", "Bird", "Fox", "Lizard" };

  // Output the instructions.
  cout << "Press enter for the name of a random animal!" << endl;

  // Loop forever.
  while (true)
  {
    // Wait for user input.
    cin.get();

    // Generate a random index.
    int randomIndex;
    randomIndex = rand() % animals.size();

    // Output the name of the randomly selected animal.
    cout << animals[randomIndex].c_str();
  }

  // Exit function.
  return 0;
}
```

输出如下：

![访问集合中的随机元素](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_03_05.jpg)

访问集合的随机元素是创建程序系统的一个很好的工具。在游戏中的任何地方，只要有一个对象，您都可以创建一个备用的数组或向量，并在运行时随机选择一个。仅凭这一点，您就可以创建一个高度随机化的游戏，每次运行都是独一无二的。

# 生成随机物品

目前，当我们加载游戏时，设置物品会被生成。我们需要添加一些随机性，一个简单的`switch`语句就足够了。在可能的情况下，我们总是希望添加选项来创建随机和程序生成的内容。

要随机生成我们的物品，我们需要生成一个介于`0`和我们拥有的物品数量之间的随机数，然后在`switch`语句中使用它。如前所述，没有一种方法可以进行程序生成，因此还有其他方法可以实现这一点。

让我们添加数字生成和`switch`语句来选择要生成的物品。更新后的`Game::PopulateLevel`函数应该如下所示：

```cpp
// Populate the level with items.
void Game::PopulateLevel()
{
    // A Boolean variable used to determine if an object should be spawned.
    bool canSpawn;

    // Spawn an item.
    canSpawn = std::rand() % 2;
    if (canSpawn)
    {
        int itemIndex = std::rand() % 2;
        std::unique_ptr<Item> item;
        switch (itemIndex)
        {
            case 0:
                item = std::make_unique<Gold>();
            break;

            case 1:
                item = std::make_unique<Gem>();
            break;
        }
        item->SetPosition(sf::Vector2f(m_screenCenter.x, m_screenCenter.y));
        m_items.push_back(std::move(item));
    }
}
```

现在我们可以看到，当我们运行游戏时，如果可以生成一个物品，它将是金色物品或宝石。我们在游戏中有很多物品，在下一章中，我们将扩展此系统以包括它们所有，从一个函数中填充整个级别：

![生成随机物品](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_03_07.jpg)

# 生成随机字符

由于我们已经介绍了从固定词汇表生成随机字符串，让我们看看如何生成随机字符。`char`数据类型是一个单个的，一个字节的字符。

字符串实际上只是一个以空字符结尾的字符序列，所以下面的代码行产生了完全相同的结果：

```cpp
Stirng myStringLiteral = "hello";
string myString = { 'h', 'e', 'l', 'l', 'o', '\0' };
```

同样，以下代码在语义上是正确的：

```cpp
char myCharArray[6] = { 'h', 'e', 'l', 'l', 'o', '\0' };
string stringVersion = myCharArray;
```

由于`char`是一个字节，它具有 0 到 255 的可能整数表示。每个这些十进制值代表一个不同的字符。在 ASCII 表中可以找到查找表。例如，字符*a*的十进制值为`97`。我们可以在分配`char`时使用这些整数，如下所示：

```cpp
char myChar = 97;
```

### 提示

在 C++中，`char`的最大十进制值是 255。如果超过这个值，它将溢出并通过表格循环。例如，将 char 值设置为 353 将导致字符*a*。 ASCII 表可以在[`www.asciitable.com/`](http://www.asciitable.com/)找到。

因此，要生成一个随机字符，我们需要生成一个介于 0 和 255 之间的数字，这是我们现在非常熟悉的。

您可以从 Packt 网站下载此程序的代码。它将在`Examples`文件夹中，项目名称为`random_character`：

```cpp
#include <iostream>

using namespace std;

// Entry method of the application.
int main()
{
  // Loop forever.
  while (true)
  {
    // Output instructions.
    cout << "Press enter to generate a random character from the ASCII standard:" << endl;

    // Pause for user input.
    cin.get();

    // The ASCII characters range from 0 - 127 in decimal.
    int randInt = rand() % 128;

    // To turn that into a char, we can just assign the int.
    char randChar = randInt;

    // Output the random char.
    cout << "Random Char: " << randChar << "\n" << endl;
  }

  // Exit function.
  return 0;
}
```

通过这段代码，我们从整个 ASCII 表中生成一个随机字符。要在更具体的范围内生成字符，我们只需要限制我们生成的数字范围。

例如，查看 ASCII 表可以看到小写字母表从 97 开始，直到 122。让我们调整随机数生成器，只生成这个范围内的值：

```cpp
// The ASCII characters range from 0 - 127 in decimal.
//int randInt = rand() % 128;
int randInt = std::rand() % 128;
int randInt = std::rand() % 26 + 97;

```

现在我们可以看到输出只是小写字母表中的字母，如下面的屏幕截图所示：

![生成随机字符](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_03_08.jpg)

# 重复循环

生成随机数的另一个用途是循环执行一定次数的代码。例如，当我们生成物品时，我们对生成代码进行单独调用。如果我们只想每次生成一个物品，这是可以的，但是当我们想生成随机数量的物品时怎么办。

我们需要随机调用我们的代码，稍后我们将把它封装在自己的函数中，这可以通过`for`循环实现。在`for`循环中，我们指定循环迭代的次数，所以我们可以生成一个随机数来代替使用固定值。每次运行代码时，都会生成一个新的随机数，循环每次的大小都会不同。

您可以从[`www.packtpub.com/support`](http://www.packtpub.com/support)下载此程序的代码。它将在`Chapter 3`文件夹中，名为`random_loops.cpp`：

```cpp
// Include our dependencies.
#include <iostream>
#include <ctime>

// We include std so we don't have to fully qualify everything.
using namespace std;

void HelloWorld();

// Entry method of the application.
int main()
{
  // First we give the application a random seed.
  srand(time(nullptr));

  // Loop forever.
  while (true)
  {
    // Output the welcome message.
    cout << "Press enter to iterate a random number of times:" << endl;

    // Pause for user input.
    cin.get();

    // Generate a random number between 1 and 10.
    int iterations = rand() % 10 + 1;

    // Now loop that number of times.
    for (int i = 0; i < iterations; i++)
    {
      cout << "Iteration " << i << ": ";
      HelloWorld();
    }

    // Output ending message.
    cout << endl << "We made " << iterations << " call(s) to HelloWorld() that time!" << endl << endl;
  }

  // Exit function.
  return 0;
}

// Outputs the text Hello World!.
void HelloWorld()
{
  cout << "Hello World!" << endl;
}
```

输出显示在以下截图中：

![重复循环](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_03_09.jpg)

# 生成随机数量的物品

在我们的`Game::PopulateLevel`函数中生成物品，并且能够随机调用函数的次数，让我们更新代码，以便在游戏开始时生成随机数量的物品。

为了实现这一点，我们只需要像在上一个练习中一样创建相同的循环，并将我们的生成代码封装在其中。让我们用以下代码更新`Game::PopulateLevel`：

```cpp
// Populate the level with items.
void Game::PopulateLevel()
{
  // A Boolean variable used to determine if an object should be spawned.
  bool canSpawn;

 // Generate a random number between 1 and 10.
 int iterations = std::rand() % 10 + 1;

 // Now loop that number of times.
 for (int i = 0; i < iterations; i++)
 {
 // Spawn an item.
 canSpawn = std::rand() % 2;

    if (canSpawn)
    {
      int itemIndex = std::rand() % 2;
      std::unique_ptr<Item> item;

      switch (itemIndex)
      {
      case 0:
        item = std::make_unique<Gold>();
        break;

      case 1:
        item = std::make_unique<Gem>();
        break;
      }

      item->SetPosition(sf::Vector2f(m_screenCenter.x, m_screenCenter.y));
      m_items.push_back(std::move(item));
    }
  }
}
```

现在当我们运行代码时，会生成一堆物品。它们目前是在彼此之上生成的，但不用担心，我们将在下一章中解决这个问题！

![生成随机数量的物品](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_03_10.jpg)

# 练习

为了让您测试本章内容的知识，这里有一些练习题，您应该完成。它们对本书的其余部分并不是必不可少的，但通过完成它们，您可以评估自己在所涵盖材料上的优势和劣势。

1.  为随机字符串生成器添加更多选项。尝试创建一个使用两个随机单词的生成器。

1.  修改随机字符生成程序，以便生成大写字母 A-Z 和小写字母 a-z 的字符。

1.  玩家目前是在水平中的固定位置生成的。创建一组可能的生成坐标，并在运行时随机选择它们，以便生成位置有所变化。

# 总结

在本章中，我们已经了解了一系列 C++数据类型，并将 RNG 与它们的使用结合起来。以随机但受控的方式使用这些数据类型的能力是实现随机程序系统的关键。记住，程序生成只是根据计算结果创建内容。这并不是自然而然的随机，我们必须像本章中所做的那样引入随机性。我们对游戏所做的增加很小，但是是创建程序生成游戏的第一步。当我们运行游戏时，每次都会有一点不同。

在下一章中，我们将通过在地图周围的随机位置生成物品和敌人来进一步开发我们的水平。程序生成的环境是程序生成游戏中的一个重要部分，将游戏对象生成在随机位置是实现这一目标的重要一步。


# 第四章：程序化填充游戏环境

现在我们已经熟悉了使用核心 C++数据类型的**随机数生成器**（**RNG**），让我们看看如何创建一个高度随机化的环境。这将包括随机生成和定位物品、敌人等。在本章中，我们还将触及随机地图生成，然后在本书末尾直面挑战。

物体生成的方式在很大程度上取决于你的级别数据的基础设施。对于大多数 2D 游戏，你可以采取与本章演示的类似的方法，如果不是完全相同的方法。然而，3D 游戏需要更多的工作，因为有一个额外的维度需要处理，但原则仍然是有效的。

在本章中，我们将涵盖以下主题：

+   在程序化填充环境时的障碍

+   定义生成区域

+   随机选择游戏`tile`

+   在随机位置生成物品

+   程序化生成环境的变化

# 潜在障碍

随机生成游戏环境并不像看起来那么简单。不仅仅是在级别范围内生成一个随机数。虽然这在技术上可能有效，但那里没有控制，因此生成的环境将有许多缺陷。物体可能重叠，位于无法到达的地方，或者按照不好的顺序布置。为了生成有意义且可玩的级别，需要更多的控制。

## 保持在一个级别的范围内

我相信我们都玩过一个物品生成在我们触及不到的地方的游戏。当在地图周围随机生成物体时，物体生成在触及不到的地方是非常令人恼火的。因此，建立准确的边界以内可以生成物体是很重要的。

正如你所想象的，这项任务的复杂性将与你的环境的复杂性相匹配。对我们来说，我们的级别被描述为一个简单的 2D 数组。因此，计算边界是相当容易的。

## 避免物体重叠

即使你完美地定义了你的级别边界，你还没有成功。环境通常不是空的，大部分都充满了风景和其他游戏对象。在选择随机生成坐标时，重要的是要考虑这些对象，以免在其中生成对象，再次将物品推出玩家的触及范围之外。

同样，我们不必太担心这一点，因为我们将有简单的没有风景的级别。

## 创建有意义的级别

说来话长，级别必须是有意义的。即使我们避免生成玩家无法触及的物品，也不会互相重叠，但如果它们都生成在一个遥远的角落，那也不好。

我们需要在我们的 RNG 操作的范围内创建合适的参数，以便我们对结果保持适当的控制。这是程序化生成游戏的一个主要陷阱。一次又一次，你会看到一个级别并不合理，因为算法产生了一个奇怪的结果。

# 级别瓦片

在我们开始使用“级别”网格之前，我们需要知道它是如何设置的！我们的“级别”被描述为一个自定义类型`Tile`的 2D 数组，这是在`Level.h`中定义的一个`struct`：

```cpp
// A struct that defines the data values our tiles need.
struct Tile
{
TILE type;          // The type of tile this is.
int columnIndex;    // The column index of the tile.
int rowIndex;       // The row index of the tile.
sf::Sprite sprite;  // The tile sprite.
int H;              // Heuristic / movement cost to goal.
int G;              // Movement cost. (Total of entire path)
int F;              // Estimated cost for full path. (G + H)
Tile* parentNode;   // Node to reach this node.
};
```

现在不要担心最后四个值；当我们到达寻路部分时，我们会在稍后使用它们！现在，我们只需要知道每个`tile`结构存储其类型，在 2D 数组中的位置和其精灵。所有可能的`tile`类型都在`Util.h`中的枚举器中定义，如下所示：

```cpp
// All possible tiles.
enum class TILE {
  WALL_SINGLE,
  WALL_TOP_END,
  WALL_SIDE_RIGHT_END,
  WALL_BOTTOM_LEFT,
  WALL_BOTTOM_END,
  WALL_SIDE,
  WALL_TOP_LEFT,
  WALL_SIDE_LEFT_T,
  WALL_SIDE_LEFT_END,
  WALL_BOTTOM_RIGHT,
  WALL_TOP,
  WALL_BOTTOM_T,
  WALL_TOP_RIGHT,
  WALL_SIDE_RIGHT_T,
  WALL_TOP_T,
  WALL_INTERSECTION,
  WALL_DOOR_LOCKED,
  WALL_DOOR_UNLOCKED,
  WALL_ENTRANCE,
  FLOOR,
  FLOOR_ALT,
  EMPTY,
  COUNT
};
```

这给每个`tile`类型一个字符串常量。因此，我们可以使用这些值而不是使用模糊的数字。有了这个，让我们开始吧。

# 定义生成区域

现在我们知道了前方的障碍，以及级别数据是如何存储的，让我们看看如何在我们的`roguelike`对象中随机生成物品的位置。

## 计算级别边界

第一步是计算级别边界。由于我们正在制作一个 2D`roguelike`对象，描述为一个 2D 数组，我们需要确定适合生成物品的 tile。如果这是为了一个 3D 游戏，你还需要考虑第三个轴。虽然我们可以找到地图的左上角点并计算到右下角的距离，但这几乎肯定会引起问题。

我们之前提到过，重要的是物品生成在有效的级别区域内。如果我们采用这种简单的方法，就有可能在墙壁上生成物品。以下伪代码显示了如何实现这一点：

```cpp
  for (int i = 0; i < GRID_WIDTH; ++i)
  {
    for (int j = 0; j < GRID_HEIGHT; ++j)
    {
      m_grid[i][j].markAsSpawnable();
    }
  }
```

如果我们在游戏中使用这种简单的方法，下面的截图显示了生成区域：

![计算级别边界](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_04_01.jpg)

正如我们所看到的，所创建的生成区域超出了可玩级别区域，尽管它在技术上是在级别边界内。

## 检查底层游戏网格

在我们的情况下，最简单的方法是检查底层游戏网格。由于级别网格中的每个地板 tile 都有一个唯一的 tile 类型，表示它是什么类型的 tile，我们可以遍历级别网格，并只标记具有有效类型的 tile 作为可能的生成位置。前面的伪代码已经被修改和更新，以便进行这个检查：

```cpp
for (int i = 0; i < GRID_WIDTH; ++i)
{
    for (int j = 0; j < GRID_HEIGHT; ++j)
    {
        if (m_grid[i][j].type == TILE::FLOOR || m_grid[i][j].type == TILE::FLOOR_ALT)
        { 
            m_grid[i][j].markAsSpawnable();
        }
    }
}
```

如果我们进行这样的检查，我们最终会得到以下可能的生成区域：

![检查底层游戏网格](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_04_02.jpg)

如您所见，这是一个更好的生成物品区域。下一步是在这个区域内选择一个点作为生成位置。

# 选择一个合适的游戏 tile

现在，为了找到合适的 tile，我们将生成随机的生成坐标。我们知道所有具有`TILE::FLOOR`或`TILE::FLOOR_ALT`类型的 tile 都是地板 tile。因此，我们可以随机选择一个 tile，并推断它是否适合生成物品。

为了避免自己进行这些检查，项目提供了`Level::IsFloor`函数。它相当不言自明；你可以传递一个 tile 或其索引，如果它是一个地板 tile，它将返回 true。从现在开始，我们将使用它来检查生成物品的 tile 是否有效。

## 随机选择一个 tile

我们将首先看的功能是从底层网格中选择一个值。在我们的情况下，级别数据是用 2D 数组描述的。因此，我们只需要生成一个随机列和一个行索引。

### 提示

记住，这个范围是行数和列数-1，因为所有索引都从 0 开始。如果我们有一个有 10 行和 10 列的网格，那么它们的编号是 0 到 9，总共是 10。

以下是一些伪代码，用于生成一个具有 10 行和 10 列的 2D 数组的随机索引：

```cpp
// Generate random indices.
int randomColumn = std::rand() % 10;
int randomRow = std::rand() % 10;

// Get the tile of the random tile.
Tile* tile = m_level.GetTile(randomColumn, randomRow);
```

要从级别中获取`Tile`对象，我们只需要调用`Level::GetTile`函数并传递随机生成的索引。

## 检查一个 tile 是否合适

要检查一个`tile`是否有效，我们可以使用之前看过的`Level::IsFloor`函数。以下伪代码将实现这一点：

```cpp
// Get the type of the random tile.
Tile* tile = m_level.GetTile(1, 1);

// Check if the tile is a floor tile.
if (m_level.IsFloor(*tile))
{
  // tile is valid
}
```

## 转换为绝对位置

现在我们可以在游戏网格中选择一个有效的`tile`，我们需要将该位置转换为绝对屏幕位置。要将索引转换为相对于网格的位置，我们只需要将它们乘以游戏中一个 tile 的宽度。在我们的情况下，tile 的大小是 50 个方形像素。例如，如果我们在网格中的位置是`[1][6]`，相对于网格的位置将是 50*300。

现在我们只需要将网格的位置添加到这些值中，使它们成为相对于我们窗口的绝对坐标。将网格位置转换为绝对位置的做法将会派上用场。所以让我们将这种行为封装在自己的函数中。

在`Level.h`中，添加以下代码：

```cpp
/**
 * Returns the position of a tile on the screen.
 */
sf::Vector2f GetActualTileLocation(int columnIndex, int rowIndex);
```

在`Level.cpp`中，添加以下函数的定义：

```cpp
sf::Vector2f Level::GetActualTileLocation(int columnIndex, int rowIndex)
{
    sf::Vector2f location;

    location.x = m_origin.x + (columnIndex * TILE_SIZE) + (TILE_SIZE / 2);
    location.y = m_origin.y + (rowIndex * TILE_SIZE) + (TILE_SIZE / 2);

    return location;
}
```

# 在随机位置生成物品

现在，让我们将所有这些内容联系起来，在地图中随机生成物品。以下是我们将采取的步骤的快速概述：

1.  从**level**数据中选择一个随机“瓷砖”。

1.  检查这个瓷砖是否是“地板”瓷砖。如果不是，返回到步骤 1。

1.  将瓷砖位置转换为绝对位置并将其提供给物品。

第一步是在**level**数据中选择一个随机瓷砖。在本章的前面，我们已经介绍了如何实现这一点：

```cpp
// Declare the variables we need.
int columnIndex(0), rowIndex(0);
Tile tileType;

// Generate a random index for the row and column.
columnIndex = std::rand() % GRID_WIDTH;
rowIndex = std::rand() % GRID_HEIGHT;

// Get the tile type.
tileType = m_level.GetTileType(columnIndex, rowIndex);
```

现在我们需要检查随机选择的瓷砖是否适合生成物品。我们知道可以通过检查瓷砖的类型来做到这一点，但我们需要将其纳入某种循环中，以便如果随机选择的瓷砖不合适，它将再次尝试。为了实现这一点，我们将随机选择瓷砖的代码包装在一个`while`语句中，如下所示：

```cpp
// Declare the variables we need.
int columnIndex(0), rowIndex(0);

// Loop until we select a floor tile.
while (!m_level.IsFloor(columnIndex, rowIndex))
{
    // Generate a random index for the row and column.
    columnIndex = std::rand() % GRID_WIDTH;
    rowIndex = std::rand() % GRID_HEIGHT;
}
```

### 提示

值得注意的是，在这里使用 while 循环并不适合所有类型的游戏。在我们的游戏中，可以生成物品的区域比不能生成的区域更多。因此，可以很容易地找到有效位置。如果情况不是这样，适合生成位置很少，那么 while 循环可能会无限期地阻塞游戏，因为它在循环中寻找区域。请极度谨慎地使用 while 语句。

现在，此代码将循环，直到找到一个合适但仍然随机的“瓷砖”，我们可以在其中生成物品。这非常有用，很可能会被多次重复使用。因此，我们将为该代码创建一个名为`Level::GetRandomSpawnLocation`的专用函数，如下所示：

```cpp
/**
 * Returns a valid spawn location from the currently loaded level
 */
sf::Vector2f GetRandomSpawnLocation();
```

现在，将以下代码添加到新函数的主体中：

```cpp
// Returns a valid spawn location from the currently loaded level.
sf::Vector2f Level::GetRandomSpawnLocation()
{
    // Declare the variables we need.
    int rowIndex(0), columnIndex(0);

    // Loop until we select a floor tile.
    while (!m_level.IsFloor(columnIndex, rowIndex))
    {
        // Generate a random index for the row and column.
        columnIndex = std::rand() % GRID_WIDTH;
        rowIndex = std::rand() % GRID_HEIGHT;
    }

    // Convert the tile position to absolute position.
    sf::Vector2f tileLocation(m_level.GetActualTileLocation(columnIndex, rowIndex));

    // Create a random offset.
    tileLocation.x += std::rand() % 21 - 10;
    tileLocation.y += std::rand() % 21 - 10;

    return tileLocation;
}
```

请注意，在函数的结尾，我们添加了一个`return`语句。当找到合适的“瓷砖”时，我们使用之前添加的函数获取绝对位置，然后返回该值。我们还对物品的坐标添加了随机偏移量，以便它们不都固定在所在“瓷砖”的中心位置。

现在我们有一个函数，它将返回在级别中适合生成位置的绝对坐标。非常方便！最后一步是将此函数合并到`Game::PopulateLevel`生成函数中。

目前，我们已经手动设置了物品的位置。要使用新函数，只需用`Level::GetRandomSpawnLocation()`函数的结果替换固定值：

```cpp
    item->SetPosition(sf::Vector2f(m_screenCenter.x, m_screenCenter.y));
    item->SetPosition(m_level.GetRandomSpawnLocation());
    m_items.push_back(std::move(item));
}
```

现在，每次创建物品时，其位置将随机生成。如果现在运行游戏，我们将看到物品随机分布在级别中，但只在有效的瓷砖上，玩家可以到达的瓷砖上：

![在随机位置生成物品](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_04_03.jpg)

## 扩展生成系统

在上一章中，我们介绍了枚举器的使用；我们将在这里充分利用它。我们将把物品“生成”代码分解为自己专用的函数。这将使我们更好地控制如何填充级别。我们还将扩展此系统以包括所有物品和敌人！

## 使用枚举器表示对象类型

构建此系统的第一步是查看物品。在`Util.h`中，所有物品类型都在以下枚举器中描述：

```cpp
// Spawnable items.
enum class ITEM {
  HEART,
  GEM,
  GOLD,
  POTION,
  KEY,
  COUNT
};
```

在决定生成哪些物品时，我们将从这些枚举值中选择随机值。

## 可选参数

在此系统中，我们将使用的另一种技术是使用可选参数。默认情况下，该函数将在随机位置生成物品，但有时我们可能希望使用固定位置覆盖此行为。这可以通过使用可选参数来实现。

考虑以下函数声明：

```cpp
void TestFunction(OBJECT object, sf::Vector2f position);
```

从此声明创建的`TestFunction()`函数需要传递需要生成坐标。我们可以只传递等于`{0.f, 0.f}`的`sf::Vector`值并忽略这些值，但这有点混乱。

可选参数是在函数声明中给定默认值的参数。如果在函数调用中没有提供这些参数，将使用默认值。让我们以以下方式重写相同的函数声明，这次利用可选参数：

```cpp
void TestFunction(OBJECT object, sf::Vector2f position = { -1.f, -1.f } );
```

### 提示

另一种方法是创建两个不同的函数。一个函数带有参数，另一个函数没有；您可以给它们不同的名称以突出差异。

现在，`position`变量的默认值是`{-1.f, -1.f}`。因此，如果在函数调用中没有传递值，将使用这些默认值。这是我们需要生成函数的行为。因此，考虑到这一点，让我们声明一个名为`Game::SpawnItem`的新函数，如下所示：

```cpp
/**
 * Spawns a given item in the level.
 */
void SpawnItem(ITEM itemType, sf::Vector2f position = { -1.f, -1.f });
```

设置了默认值后，现在需要确定是否应该使用它们。为了检查这一点，我们只需评估`position`变量的*x*和*y*值。如果*x*和*y*保持为`-1.f`，那么我们知道用户没有覆盖它们，并且希望随机生成值。然而，如果*x*和*y*不是`-1.f`，那么它们已经被覆盖，我们应该使用它们。

### 提示

我使用`-1.f`作为默认参数，因为它是一个无效的生成坐标。默认参数应该让您轻松确定它们是否已被覆盖。

以下代码将选择一个随机的生成位置：

```cpp
// Choose a random, unused spawn location if not overridden.
sf::Vector2f spawnLocation;
if ((position.x >= 0.f) || (position.y >= 0.f))
{
    spawnLocation = position;
}
else
{
    spawnLocation = m_level.GetRandomSpawnLocation();
}
```

由于`position`变量是可选的，以下函数调用都是有效的：

```cpp
SpawnITem(GOLD);
SpawnITem(GOLD, 100.f, 100.f);
```

## 完整的生成函数

现在，让我们把所有这些放在一起，创建`SpawnItem()`函数，如下所示：

```cpp
// Spawns a given object type at a random location within the map. Has the option to explicitly set a spawn location.
void Game::SpawnItem(ITEM itemType, sf::Vector2f position)
{
    std::unique_ptr<Item> item;

    int objectIndex = 0;

    // Choose a random, unused spawn location.
    sf::Vector2f spawnLocation;

    if ((position.x >= 0.f) || (position.y >= 0.f))
    {
        spawnLocation = position;
    }
    else
    {
        spawnLocation = m_level.GetRandomSpawnLocation();
    }

    // Check which type of object is being spawned.
    switch (itemType)
    {
        case ITEM::POTION:
            item = std::make_unique<Potion>();
        break;

        case ITEM::GEM:
            item = std::make_unique<Gem>();
        break;

        case ITEM::GOLD:
            item = std::make_unique<Gold>();
        break;

        case ITEM::KEY:
            item = std::make_unique<Key>();
        break;

        case ITEM::HEART:
            item = std::make_unique<Heart>();
        break;
    }

    // Set the item position.
    item->SetPosition(spawnLocation);

    // Add the item to the list of all items.
    m_items.push_back(std::move(item));
}
```

为了测试新函数，我们可以以以下方式更新`Game::PopulateLevel`函数：

```cpp
if (canSpawn)
{
  int itemIndex = std::rand() % 2;
 SpawnItem(static_cast<ITEM>(itemIndex));
  std::unique_ptr<Item> item;

  switch (itemIndex)
  {
  case 0:
    item = std::make_unique<Gold>();
    break;

  case 1:
    item = std::make_unique<Gem>();
    break;
  }

  item->SetPosition(sf::Vector2f(m_screenCenter.x, m_screenCenter.y));
  item->SetPosition(m_level.GetRandomSpawnLocation());
  m_items.push_back(std::move(item));
}
```

这可能看起来是为了一个看似不影响游戏玩法的小改变而做了很多工作，但这是重要的。软件应该以易于维护和可扩展的方式构建。现在这个系统已经建立，我们可以通过一个函数调用生成一个物品。太棒了！

游戏的快速运行确认了代码按预期工作，并且我们迈出了朝着完全程序化的环境迈出了一大步，如下截图所示：

![完整的生成函数](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_04_04.jpg)

## 更新生成代码

现在`Game::SpawnItem`函数已经启动运行，让我们稍微重构一下`Game::PopulatelLevel`函数。在`Game.h`中，让我们声明以下静态`const`：

```cpp
static int const MAX_ITEM_SPAWN_COUNT = 50;
```

我们可以使用这个常量来代替`for`循环的硬编码限制。这样做的目的是从代码中删除所有硬编码的值。如果我们在这里硬编码一个值而不使用`const`，每次想要更改值时都必须手动更改。这既耗时又容易出错。使用`const`，我们只需更改它的值，这将影响到它被使用的每个实例。

现在我们已经熟悉了函数的功能，可以整理一些变量，如下所示：

```cpp
// Populate the level with items.
void Game::PopulateLevel()
{
    // Spawn items.
    for (int i = 0; i < MAX_ITEM_SPAWN_COUNT; i++)
    {
        if (std::rand() % 2)
        {
            SpawnItem(static_cast<ITEM>(std::rand() % 2));
        }
    }
}
```

整理好了这些，现在我们可以将这种方法扩展到生成敌人到关卡中！

## 随机生成敌人

现在我们可以生成游戏中的物品，让我们使用相同的系统来生成敌人！我们将首先定义一个`Game::SpawnEnemy`函数，如下所示：

```cpp
/**
 * Spawns a given enemy in the level.
 */
void SpawnEnemy(ENEMY enemyType, sf::Vector2f position = { -1.f, -1.f });
```

另外，声明另一个静态`const`来限制我们可以生成的敌人的最大数量：

```cpp
  static int const MAX_ENEMY_SPAWN_COUNT = 20;
```

有了这个声明，我们现在可以添加函数的定义。它将类似于`Game::SpawnItem`函数，只是不再通过物品枚举中的值进行切换，而是创建在以下枚举中定义的敌人：

```cpp
// Enemy types.
enum class ENEMY {
  SLIME,
  HUMANOID,
  COUNT
};
```

让我们添加这个定义：

```cpp
// Spawns a given number of enemies in the level.
void Game::SpawnEnemy(ENEMY enemyType, sf::Vector2f position)
{
    // Spawn location of enemy.
    sf::Vector2f spawnLocation;

    // Choose a random, unused spawn location.
    if ((position.x >= 0.f) || (position.y >= 0.f))
    {
        spawnLocation = position;
    }
    else
    {
        spawnLocation = m_level.GetRandomSpawnLocation();
    }

    // Create the enemy.
    std::unique_ptr<Enemy> enemy;

    switch (enemyType)
    {
        case ENEMY::SLIME:
            enemy = std::make_unique<Slime>();
        break;
        case ENEMY::HUMANOID:
            enemy = std::make_unique<Humanoid>();
        break;
    }

    // Set spawn location.
    enemy->SetPosition(spawnLocation);

    // Add to list of all enemies.
    m_enemies.push_back(std::move(enemy));
}
```

现在，要调用这个函数，我们需要回到`Game::Populate`函数，并添加另一个循环，以类似于创建物品的方式创建敌人：

```cpp
// Populate the level with items.
void Game::PopulateLevel()
{
    // Spawn items.
    for (int i = 0; i < MAX_ITEM_SPAWN_COUNT; i++)
    {
        if (std::rand() % 2)
        {
            SpawnItem(static_cast<ITEM>(std::rand() % 2));
        }
    }

    // Spawn enemies.
    for (int i = 0; i < MAX_ENEMY_SPAWN_COUNT; i++)
    {
        if (std::rand() % 2)
        {
            SpawnEnemy(static_cast<ENEMY>(std::rand() % static_cast<int>(ENEMY::COUNT)));
        }
    }
}
```

有了这个，物品和敌人将在整个级别随机生成。这个系统非常灵活和简单。要添加另一个物品或敌人，我们只需要将其添加到相关的枚举器中，并添加相应的`switch`语句。这是在生成程序内容和系统时所需要的灵活方法。

让我们运行游戏，看看填充的级别：

![随机生成敌人](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_04_05.jpg)

# 生成随机瓷砖

环境特征的生成将在这里简要介绍，因为本书的最后一章专门讨论了程序生成游戏地图。这是我们的最终目标。因此，为了开始，我们将生成一些表面的环境特征，以备后来随机生成级别。

添加一个新的`tile`到游戏中将大大增加级别的多样性。程序生成的一个问题是环境可能会感觉过于不自然和通用。因此，这将有助于避免这种情况。

让我们将以下声明添加到`Game.h`中：

```cpp
/**
 * Spawns a given number of a certain tile at random locations in the level.
 */
void SpawnRandomTiles(TILE tileType, int count);
```

这个函数有两个参数。一个允许我们指定我们想要生成的`tile`索引，另一个允许我们指定数量。我们本可以跳过创建一个函数，直接在`Game::PopulateLevel`函数中硬编码行为，这样也可以工作，但不能用于其他用途。

然而，通过我们的方法，我们可以轻松地重用代码，指定需要使用的`tile`和我们希望生成的瓷砖数量。如果我们使用随机数来确定这些值，我们甚至可以在系统中获得更多的程序生成和随机性。在编写程序系统时，始终牢记这一点，并尽量避免使用硬编码的值。即使最终可能不会使用，也要创建选项。

## 添加一个新的游戏瓷砖

下一步是在级别对象中添加新的`tile`资源，`Level::AddTile()`函数就是这样做的。在`Game::Initialize`中，我们将调用这个函数并添加一个新的`tile`，如下所示：

```cpp
// Add the new tile type to level.
m_level.AddTile("../resources/tiles/spr_tile_floor_alt.png", TILE::FLOOR_ALT);
```

这个函数有两个参数，即`resource`的`path`和`tile`应该具有的`ID`参数值。在这种情况下，我们使用`TILE::FLOOR_ALT`值。

## 选择一个随机瓷砖

如果我们要在级别中随机生成瓷砖，我们需要首先在游戏网格中选择一个随机的地板瓷砖。幸运的是，我们已经编写了代码来做到这一点；它在`Level::GetRandomSpawnLocation()`函数中。因此，我们可以使用这段代码并将其添加到新的函数中。我们还为需要创建的瓷砖数量创建了一个参数。因此，我们将把所有内容都放在一个`for`循环中，以便正确重复这个过程的次数。

让我们给这个函数一个定义，如下所示：

```cpp
// Spawns a given number of a given tile randomly in the level.
void Game::SpawnRandomTiles(TILE tileType, int count)
{
    // Declare the variables we need.
    int rowIndex(0), columnIndex(0), tileIndex(0);

    // Loop the number of tiles we need.
    for (int i = 0; i < count; i++)
    {
        // Declare the variables we need.
        int columnIndex(0), rowIndex(0);

        // Loop until we select a floor tile.
        while (!m_level.IsFloor(columnIndex, rowIndex))
        {
            // Generate a random index for the row and column.
            columnIndex = std::rand() % GRID_WIDTH;
            rowIndex = std::rand() % GRID_HEIGHT;
        }

        // Now we change the selected tile.
        m_level.SetTile(columnIndex, rowIndex, tileType);
    }
}
```

一旦我们找到一个有效的地板瓷砖，我们就可以将其类型更新为传递的类型。

## 实现 SpawnRandomTiles 函数

最后一步是调用`Game::SpawnRandomTiles`。这个函数依赖于已经存在的级别网格。因此，我们将在`Game::Initialize`函数的末尾调用它，如下所示：

```cpp
// Change a selection of random tiles to the cracked tile sprite.
SpawnRandomTiles(TILE::FLOOR_ALT, 15);
```

### 提示

我在这里硬编码了参数，但为了使它更随机，你可以生成随机数来代替它们。我把这留作本章的一个练习！

现在只需运行游戏，看看我们的工作在下面的截图中的效果。我们可以看到，原来地板是单一瓷砖的地方，现在是随机分布的破碎瓷砖，我们可以通过我们设计的函数来控制精灵和它们的数量：

![实现 SpawnRandomTiles 函数](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/prcd-cont-gen-cpp-gm-dev/img/B04920_04_06.jpg)

# 练习

为了帮助你测试本章内容的知识，这里有一些练习，你应该去做。它们对本书的其余部分并不是必须的，但是做这些练习将帮助你评估自己在所学内容上的优势和劣势：

1.  向游戏中添加一个新物品。然后，将其与生成系统连接起来，以便它可以与现有物品随机生成。

1.  向游戏中添加你自己的`tile`。将其与生成代码连接起来，并更改底层级别网格，使玩家无法穿过它。

1.  检查在调用`Game::SpawnRandomTiles()`时我们创建的瓦片数量是否是硬编码的：

```cpp
// change a selection of random tiles to the cracked tile sprite
this->SpawnRandomTiles(tileIndex, 15);
```

在运行时使用 RNG 生成一个计数。

1.  现在我们有了 Game::SpawnItem 函数，更新我们的敌人物品掉落以使用它。

1.  由于我们现在有一个函数来计算实际的瓦片位置，更新我们的火炬生成代码，这样我们就不需要自己进行位置计算了。

# 总结

在本章中，我们实现了 RNG 来在关卡中以程序方式生成合适的生成位置，并将这一行为封装在自己的函数中。然后我们使用这个函数在地图周围的随机位置生成物品和敌人。

在下一章中，我们将讨论创建独特的、随机生成的游戏对象。在运行时，某些物品将以程序方式生成，这意味着可能会有几乎无限数量的可能组合。在前几章中，我们介绍了用于实现这一点的技能和技术，现在是时候把它们整合起来，建立我们自己的程序系统！
