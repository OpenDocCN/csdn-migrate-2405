# C++ 函数式编程实用指南（三）

> 原文：[`annas-archive.org/md5/873bfe33df74385c75906a2f129ca61f`](https://annas-archive.org/md5/873bfe33df74385c75906a2f129ca61f)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用类提高内聚性

我们之前讨论过如何使用函数和函数操作来组织我们的代码。然而，我们不能忽视过去几十年软件设计的主流范式——面向对象编程（OOP）。面向对象编程能够与函数式编程配合吗？它们之间是否存在任何兼容性，还是完全不相关？

事实证明，我们可以很容易地在类和函数之间进行转换。我通过我的朋友和导师 J.B. Rainsberger 学到，类只不过是一组部分应用的、内聚的纯函数。换句话说，我们可以使用类作为一个方便的位置，将内聚的函数组合在一起。但是，为了做到这一点，我们需要理解高内聚原则以及如何将函数转换为类，反之亦然。

本章将涵盖以下主题：

+   理解函数式编程和面向对象编程之间的联系

+   理解类如何等同于一组内聚的、部分应用的纯函数

+   理解高内聚性的必要性

+   如何将纯函数分组到类中

+   如何将一个类分解为纯函数

# 技术要求

您将需要一个支持 C++ 17 的编译器。我使用的是 GCC 7.3.0。

代码可以在 GitHub 的[https:/​/​github.​com/​PacktPublishing/​Hands-​On-​Functional-Programming-​with-​Cpp](https://github.%E2%80%8Bcom/PacktPublishing/Hands-On-Functional-Programming-with-Cpp)的`Chapter08`文件夹中找到。它包括并使用了`doctest`，这是一个单头开源单元测试库。您可以在其 GitHub 存储库中找到它，网址为[https:/​/github.​com/​onqtam/​doctest](https://github.%E2%80%8Bcom/onqtam/doctest)。

# 使用类提高内聚性

作为一名年轻的软件工程学生，我花了大量时间阅读面向对象编程的相关内容。我试图理解面向对象编程的工作原理，以及为什么它对现代软件开发如此重要。那时，大多数书籍都提到面向对象编程是将代码组织成具有封装、继承和多态三个重要属性的类。

近 20 年后，我意识到这种面向对象编程的观点相当有限。面向对象编程主要是在施乐帕克（Xerox PARC）开发的，这个实验室以产生大量高质量的想法而闻名，比如图形用户界面、点和点击、鼠标和电子表格等。艾伦·凯（Alan Kay）是面向对象编程的创始人之一，他在面对支持新的图形用户界面范式的大型代码库组织问题时，借鉴了自己作为生物学专业的知识。他提出了对象和类的概念，但多年后他表示，这种代码组织风格的主要思想是消息传递。他对对象的看法是，它们应该以与细胞类似的方式进行通信，在代码中模拟它们的化学信息传递。这就是为什么从他的观点来看，面向对象编程语言中的方法调用应该是一个从一个细胞或对象传递到另一个细胞或对象的消息。

一旦我们忘记了封装、继承和多态的概念，更加重视对象而不是类，函数式编程范式和面向对象编程之间的摩擦就消失了。让我们看看这种面向对象编程的基本观点会带我们去哪里。

# 从功能角度看待类

有多种方式来看待类。在知识管理方面，我将*类*概念化为分类——它是一种将具有相似属性的实例（或对象）分组的方式。如果我们以这种方式思考类，那么继承就是一种自然的属性——有一些对象类具有相似的属性，但它们在各种方面也有所不同；说它们继承自彼此是一种快速解释的方式。

然而，这种类的概念适用于我们的知识是准完全的领域。在软件开发领域，我们经常在应用领域的知识有限的情况下工作，而且领域随着时间的推移而不断扩展。因此，我们需要专注于代码结构，这些结构在概念之间有着薄弱的联系，使我们能够在了解领域的更多内容时进行更改或替换。那么，我们应该怎么处理类呢？

即使没有强大的关系，类在软件设计中也是一个强大的构造。它们提供了一种整洁的方法来分组方法，并将方法与数据结合在一起。与函数相比，它们可以帮助我们更好地导航更大的领域，因为我们最终可能会有成千上万个函数（如果不是更多）。那么，我们如何在函数式编程中使用类呢？

首先，正如你可能从我们之前的例子中注意到的那样，函数式编程将复杂性放在数据结构中。类通常是定义我们需要的数据结构的一种整洁方式，特别是在像 C++这样的语言中，它允许我们重写常见的运算符。常见的例子包括虚数、可测单位（温度、长度、速度等）和货币数据结构。每个例子都需要将数据与特定的运算符和转换进行分组。

其次，我们编写的不可变函数往往自然地分组成逻辑分类。在我们的井字棋示例中，我们有许多函数与我们称之为**line**的数据结构一起工作；我们的自然倾向是将这些函数分组在一起。虽然没有什么能阻止我们将它们分组在头文件中，但类提供了一个自然的地方来组合函数，以便以后能够找到它们。这导致了另一种类型的类——一个初始化一次的不可变对象，其每个操作都返回一个值，而不是改变其状态。

让我们更详细地看一下面向对象设计和函数结构之间的等价关系。

# 面向对象设计和函数式的等价关系

如果我们回到我们的井字棋结果解决方案，你会注意到有许多函数将`board`作为参数接收：

```cpp
auto allLines = [](const auto& board) {
...
};

auto allColumns = [](const auto& board) {
...
};

auto mainDiagonal = [](const auto& board){
...
};

auto secondaryDiagonal = [](const auto& board){
 ...
};

auto allDiagonals = [](const auto& board) -> Lines {
...
};

auto allLinesColumnsAndDiagonals = [](const auto& board) {
 ...
};
```

例如，我们可以定义一个棋盘如下：

```cpp
    Board board {
        {'X', 'X', 'X'},
        {' ', 'O', ' '},
        {' ', ' ', 'O'}
    };
```

然后，当我们将其传递给函数时，就好像我们将棋盘绑定到函数的参数上。现在，让我们为我们的`allLinesColumnsAndDiagonals` lambda 做同样的事情：

```cpp
auto bindAllToBoard = [](const auto& board){
    return map<string, function<Lines  ()>>{
        {"allLinesColumnsAndDiagonals",   
            bind(allLinesColumnsAndDiagonals, board)},
    };
};
```

前面的 lambda 和我们在早期章节中看到的许多其他例子都调用了其他 lambda，但它们没有捕获它们。例如，`bindAllToBoard` lambda 如何知道`allLinesColumnsAndDiagonal` lambda？这能够工作的唯一原因是因为 lambda 在全局范围内。此外，使用我的编译器，当尝试捕获`allLinesColumnsAndDiagonals`时，我会得到以下错误消息：`<lambda>` *cannot be captured because it does not have automatic storage duration*，因此如果我尝试捕获我使用的 lambda，它实际上不会编译。

我希望我即将说的是不言自明的，但我还是要说一下——对于生产代码，避免在全局范围内使用 lambda（以及其他任何东西）是一个好习惯。这也会迫使你捕获变量，这是一件好事，因为它会使依赖关系变得明确。

现在，让我们看看我们如何调用它：

```cpp
TEST_CASE("all lines, columns and diagonals with class-like structure"){
    Board board{
        {'X', 'X', 'X'},
        {' ', 'O', ' '},
        {' ', ' ', 'O'}
    };

    Lines expected{
        {'X', 'X', 'X'},
        {' ', 'O', ' '},
        {' ', ' ', 'O'},
        {'X', ' ', ' '},
        {'X', 'O', ' '},
        {'X', ' ', 'O'},
        {'X', 'O', 'O'},
        {'X', 'O', ' '}
    };

    auto boardObject = bindAllToBoard(board);
    auto all = boardObject["allLinesColumnsAndDiagonals"]();
    CHECK_EQ(expected, all);
}
```

这让你想起了什么吗？让我们看看我们如何在类中编写这个。我现在将其命名为`BoardResult`，因为我想不出更好的名字：

```cpp
class BoardResult{
    private:
        const vector<Line> board;

    public:
        BoardResult(const vector<Line>& board) : board(board){
        };

         Lines allLinesColumnsAndDiagonals() const {
             return concatenate3(allLines(board), allColumns(board),  
                 allDiagonals(board));
        }
};

TEST_CASE("all lines, columns and diagonals"){
 BoardResult boardResult{{
 {'X', 'X', 'X'},
 {' ', 'O', ' '},
 {' ', ' ', 'O'}
 }};

 Lines expected {
 {'X', 'X', 'X'},
 {' ', 'O', ' '},
 {' ', ' ', 'O'},
 {'X', ' ', ' '},
 {'X', 'O', ' '},
 {'X', ' ', 'O'},
 {'X', 'O', 'O'},
 {'X', 'O', ' '}
 };

 auto all = boardResult.allLinesColumnsAndDiagonals();
 CHECK_EQ(expected, all);
}
```

让我们回顾一下我们做了什么：

+   我们看到更多的函数将`board`作为参数。

+   我们决定使用一个单独的函数将`board`参数绑定到一个值，从而获得一个字符串表示函数名和与该值绑定的 lambda 之间的映射。

+   要调用它，我们需要先调用初始化函数，然后才能调用部分应用的 lambda。

+   *这看起来非常类似于一个类*——使用构造函数传递类方法之间共享的值，然后调用方法而不传递参数。

因此，*一个类只是一组部分应用的 lambda*。但我们如何将它们分组呢？

# 高内聚原则

在我们之前的例子中，我们根据它们都需要相同的参数`board`将函数分组在一起。我发现这是一个很好的经验法则。然而，我们可能会遇到更复杂的情况。

为了理解为什么，让我们看另一组函数（为了讨论的目的，实现已被忽略）：

```cpp
using Coordinate = pair<int, int>;

auto accessAtCoordinates = [](const auto& board, const Coordinate& coordinate)
auto mainDiagonalCoordinates = [](const auto& board)
auto secondaryDiagonalCoordinates = [](const auto& board)
auto columnCoordinates = [](const auto& board, const auto& columnIndex)
auto lineCoordinates = [](const auto& board, const auto& lineIndex)
auto projectCoordinates = [](const auto& board, const auto& coordinates)
```

这些函数应该是之前定义的`BoardResult`类的一部分吗？还是应该是另一个类`Coordinate`的一部分？或者我们应该将它们拆分，其中一些归入`BoardResult`类，另一些归入`Coordinate`类？

我们以前的方法并不适用于所有的功能。如果我们仅仅看它们的参数，所有之前的函数都需要`board`。然而，其中一些还需要`coordinate / coordinates`作为参数。`projectCoordinates`应该是`BoardResult`类的一部分，还是`Coordinate`类的一部分？

更重要的是，我们可以遵循什么基本原则将这些功能分组到类中呢？

由于代码的静态结构没有明确的答案，我们需要考虑代码的演变。我们需要问的问题是：

+   我们期望哪些函数一起改变？我们期望哪些函数分开改变？

+   这种推理方式引导我们到高内聚原则。但是，让我们先解开它。我们所说的内聚是什么意思？

作为一名工程师和科学迷，我在物理世界中遇到了内聚。例如，当我们谈论水时，构成液体的分子倾向于粘在一起。我也遇到了内聚作为一种社会力量。作为一个与试图采用现代软件开发实践的客户合作的变革者，我经常不得不处理群体凝聚力——人们围绕一种观点聚集在一起的倾向。

当我们谈论函数的内聚性时，没有物理力量将它们推在一起，它们绝对不会固守观点。那么，我们在谈论什么呢？我们在谈论一种神经力量，可以这么说。

人脑有着发现模式和将相关物品分组到类别中的巨大能力，再加上一种神奇的快速导航方式。将函数绑在一起的力量在我们的大脑中——它是从看似无关的功能组合中出现的统一目的的发现。

高内聚性很有用，因为它使我们能够理解和导航一些大概念（如棋盘、线和标记），而不是数十甚至数百个小函数。此外，当（而不是如果）我们需要添加新的行为或更改现有行为时，高内聚性将使我们能够快速找到新行为的位置，并且以最小的更改添加它到网络的其余部分。

内聚是软件设计的一个度量标准，由拉里·康斯坦丁在 20 世纪 60 年代作为他的*结构化设计*方法的一部分引入。通过经验，我们注意到高内聚性与低变更成本相关。

让我们看看如何应用这个原则来将我们的函数分组到类中。

# 将内聚的函数分组到类中

正如之前讨论的，我们可以从一个类的统一目的或概念的角度来看内聚。然而，我通常发现更彻底的方法是根据代码的演变来决定函数组，以及未来可能发生的变化以及它可能触发的其他变化。

你可能不会指望从我们的井字棋结果问题中学到很多东西。它相当简单，看起来相当容易控制。然而，网上的快速搜索会带我们找到一些井字棋的变体，包括以下内容：

+   *m x n*棋盘，赢家由一排中的*k*个项目决定。一个有趣的变体是五子棋，在*15 x 15*的棋盘上进行，赢家必须连成 5 个。

+   一个 3D 版本。

+   使用数字作为标记，并以数字的总和作为获胜条件。

+   使用单词作为标记，获胜者必须在一行中放置 3 个带有 1 个共同字母的单词。

+   使用*3 x 3*的 9 个棋盘进行游戏，获胜者必须连续获胜 3 个棋盘。

这些甚至不是最奇怪的变体，如果你感兴趣，可以查看维基百科上关于这个主题的文章[`en.wikipedia.org/wiki/Tic-tac-toe_variants`](https://en.wikipedia.org/wiki/Tic-tac-toe_variants)。

那么，在我们的实现中可能会发生什么变化呢？以下是一些建议：

+   棋盘大小

+   玩家数量

+   标记

+   获胜规则（仍然是一行，但条件不同）

+   棋盘拓扑——矩形、六边形、三角形或 3D 而不是正方形

幸运的是，如果我们只是改变了棋盘的大小，我们的代码实际上不会有太大变化。事实上，我们可以传入一个更大的棋盘，一切仍然可以正常工作。改变玩家数量只需要做很小的改动；我们假设他们有不同的标记，我们只需要将`tokenWins`函数绑定到不同的标记值上。

那么获胜规则呢？我们假设规则仍然考虑了行、列和对角线，因为这是井字游戏的基本要求，所有变体都使用它们。然而，我们可能不考虑完整的行、列或对角线；例如，在五子棋中，我们需要在大小为 15 的行、列或对角线上寻找 5 个标记。从我们的代码来看，这只是选择其他坐标组的问题；我们不再需要寻找被标记`X`填满的完整行，而是需要选择所有可能的五连坐标集。这意味着我们的与坐标相关的函数需要改变——`lineCoordinates`、`mainDiagonalCoordinates`、`columnCoordinates`和`secondaryDiagonalCoordinates`。它们将返回一个五连坐标的向量，这将导致`allLines`、`allColumns`和`allDiagonals`的变化，以及我们连接它们的方式。

如果标记是一个单词，获胜条件是找到单词之间的共同字母呢？好吧，坐标是一样的，我们获取行、列和对角线的方式也是一样的。唯一的变化在于`fill`条件，所以这相对容易改变。

这引出了最后一个可能的变化——棋盘拓扑。改变棋盘拓扑将需要改变棋盘数据结构，以及所有的坐标和相应的函数。但是这是否需要改变行、列和对角线的规则呢？如果我们切换到 3D，那么我们将有更多的行、更多的列，以及一个不同的对角线寻址方式——所有坐标的变化。矩形棋盘本身并没有对角线；我们需要使用部分对角线，比如在五子棋的情况下。至于六边形或三角形的棋盘，目前还没有明确的变体，所以我们可以暂时忽略它们。

这告诉我们，如果我们想要为变化做好准备，我们的函数应该围绕以下几个方面进行分组：

+   规则（也称为**填充条件**）

+   坐标和投影——并为多组行、列和对角线准备代码

+   基本的棋盘结构允许基于坐标进行访问

这就解决了问题——我们需要将坐标与棋盘本身分开。虽然坐标数据类型将与棋盘数据类型同时改变，但由于游戏规则的原因，提供行、列和对角线坐标的函数可能会发生变化。因此，我们需要将棋盘与其拓扑分开。

在**面向对象设计**（**OOD**）方面，我们需要在至少三个内聚的类之间分离程序的责任——`Rules`，`Topology`和`Board`。`Rules`类包含游戏规则——基本上是我们如何计算获胜条件，当我们知道是平局时，或者游戏何时结束。`Topology`类涉及坐标和棋盘的结构。`Board`类应该是我们传递给算法的结构。

那么，我们应该如何组织我们的函数？让我们列个清单：

+   **规则**：`xWins`，`oWins`，`tokenWins`，`draw`和`inProgress`

+   **Topology**：`lineCoordinates`，`columnCoordinates`，`mainDiagonalCoordinates`和`secondaryDiagonalCoordinates`

+   **Board**：`accessAtCoordinates`和`allLinesColumnsAndDiagonals`

+   **未决**：`allLines`，`allColumns`，`allDiagonals`，`mainDiagonal`和`secondaryDiagonal`

总是有一系列函数可以成为更多结构的一部分。在我们的情况下，`allLines`应该是`Topology`类还是`Board`类的一部分？我可以为两者找到同样好的论点。因此，解决方案留给编写代码的程序员的直觉。

然而，这显示了你可以用来将这些函数分组到类中的方法——考虑可能发生的变化，并根据哪些函数将一起变化来分组它们。

然而，对于练习这种方法有一个警告——避免陷入过度分析的陷阱。代码相对容易更改；当你对可能发生变化的事情知之甚少时，让它工作并等待直到同一代码区域出现新的需求。然后，你会对函数之间的关系有更好的理解。这种分析不应该花费你超过 15 分钟；任何额外的时间很可能是过度工程。

# 将一个类分割成纯函数

我们已经学会了如何将函数分组到一个类中。但是我们如何将代码从一个类转换为纯函数？事实证明，这是相当简单的——我们只需要使函数成为纯函数，将它们移出类，然后添加一个初始化器，将它们绑定到它们需要的数据上。

让我们举另一个例子，一个执行两个整数操作数的数学运算的类：

```cpp
class Calculator{
    private:
        int first;
        int second;

    public:
        Calculator(int first, int second): first(first), second(second){}

        int add() const {
            return first + second;
        }

        int multiply() const {
            return first * second;
        }

        int mod() const {
            return first % second;
        }

};

TEST_CASE("Adds"){
    Calculator calculator(1, 2);

    int result = calculator.add();

    CHECK_EQ(result, 3);
}

TEST_CASE("Multiplies"){
    Calculator calculator(3, 2);

    int result = calculator.multiply();

    CHECK_EQ(result, 6);
}

TEST_CASE("Modulo"){
    Calculator calculator(3, 2);

    int result = calculator.mod();

    CHECK_EQ(result, 1);
}
```

为了使它更有趣，让我们添加另一个函数，用于反转第一个参数：

```cpp
class Calculator{
...
    int negateInt() const {
        return -first;
    }
...
}

TEST_CASE("Revert"){
    Calculator calculator(3, 2);

    int result = calculator.negateInt();

    CHECK_EQ(result, -3);
}
```

我们如何将这个类分割成函数？幸运的是，这些函数已经是纯函数。很明显，我们可以将函数提取为 lambda：

```cpp
auto add = [](const auto first, const auto second){
    return first + second;
};

auto multiply = [](const auto first, const auto second){
    return first * second;
};

auto mod = [](const auto first, const auto second){
    return first % second;
};

auto negateInt = [](const auto value){
    return -value;
};
```

如果你真的需要，让我们添加初始化器：

```cpp
auto initialize = [] (const auto first, const auto second) -> map<string, function<int()>>{
    return  {
        {"add", bind(add, first, second)},
        {"multiply", bind(multiply, first, second)},
        {"mod", bind(mod, first, second)},
        {"revert", bind(revert, first)}
    };
};
```

然后，可以进行检查以确定一切是否正常工作：

```cpp
TEST_CASE("Adds"){
    auto calculator = initialize(1, 2);

    int result = calculator["add"]();

    CHECK_EQ(result, 3);
}

TEST_CASE("Multiplies"){
    auto calculator = initialize(3, 2);

    int result = calculator["multiply"]();

    CHECK_EQ(result, 6);
}

TEST_CASE("Modulo"){
    auto calculator = initialize(3, 2);

    int result = calculator["mod"]();

    CHECK_EQ(result, 1);
}

TEST_CASE("Revert"){
    auto calculator = initialize(3, 2);

    int result = calculator["revert"]();

    CHECK_EQ(result, -3);
}

```

这让我们只剩下一个未决问题——如何将不纯的函数转变为纯函数？我们将在第十二章中详细讨论这个问题，*重构为纯函数*。现在，让我们记住本章的重要结论——*一个类只不过是一组内聚的、部分应用的函数*。

# 总结

在本章中，我们有一个非常有趣的旅程！我们成功地以一种非常优雅的方式将两种看似不相关的设计风格——面向对象编程和函数式编程联系起来。纯函数可以根据内聚性原则分组到类中。我们只需要发挥想象力，想象一下函数可能发生变化的情景，并决定哪些函数应该分组在一起。反过来，我们总是可以通过使它们成为纯函数并反转部分应用，将函数从一个类移动到多个 lambda 中。

面向对象设计和函数式编程之间没有摩擦；它们只是实现功能的代码的两种不同结构方式。

我们使用函数进行软件设计的旅程还没有结束。在下一章中，我们将讨论如何使用**测试驱动开发**（**TDD**）设计函数。


# 第九章：函数式编程的测试驱动开发

**测试驱动开发**（**TDD**）是一种设计软件的非常有用的方法。该方法如下——我们首先编写一个失败的单一测试，然后实现最少的代码使测试通过，最后进行重构。我们在短时间内进行小循环来完成这个过程。

我们将看看纯函数如何简化测试，并提供一个应用 TDD 的函数示例。纯函数允许我们编写简单的测试，因为它们始终为相同的输入参数返回相同的值；因此，它们相当于大数据表。因此，我们可以编写模拟输入和预期输出的数据表的测试。

本章将涵盖以下主题：

+   如何使用数据驱动测试利用纯函数的优势

+   了解 TDD 周期的基础

+   如何使用 TDD 设计纯函数

# 技术要求

您将需要一个支持**C++ 17**的编译器。我使用了**GCC 7.3.0**。

代码可以在 GitHub 上找到，网址为[https:/​/​github.​com/​PacktPublishing/​Hands-​On-​Functional-Programming-​with-​Cpp](https://github.%E2%80%8Bcom/PacktPublishing/Hands-On-Functional-Programming-with-Cpp)，在`Chapter09`文件夹中。它包括并使用`doctest`，这是一个单头开源单元测试库。您可以在其 GitHub 存储库上找到它，网址为[https:/​/github.​com/​onqtam/​doctest](https://github.%E2%80%8Bcom/onqtam/doctest)。

# 函数式编程的 TDD

20 世纪 50 年代的编程与今天的编程非常不同。我们现在所知道的程序员的工作被分为三个角色。程序员会编写要实现的算法。然后，专门的打字员会使用特殊的机器将其输入到穿孔卡片中。然后，程序员必须手动验证穿孔卡片是否正确——尽管有数百张。一旦确认穿孔卡片正确，程序员会将它们交给大型机操作员。由于当时唯一存在的计算机非常庞大且价格昂贵，因此在计算机上花费的时间必须受到保护。大型机操作员负责计算机，确保最重要的任务优先进行，因此新程序可能需要等待几天才能运行。运行后，程序将打印完整的堆栈跟踪。如果出现错误，程序员必须查看一张充满奇怪符号的非常长的纸，并找出可能出错的地方。这个过程缓慢、容易出错且不可预测。

然而，一些工程师提出了一个想法。如果他们不是从失败的程序中获得复杂的输出，而是得到明确指出问题的信息会怎样？他们决定开始编写额外的代码，检查生产代码并生成通过或失败的输出。他们不是运行程序，或者在运行程序的同时，他们会运行单元测试。

一旦程序员拥有了更短的反馈循环，如终端的发明，后来是个人电脑和强大的调试器，单元测试的实践就被遗忘了。然而，它从未完全消失，突然以不同的形式回来了。

直到 20 世纪 90 年代，单元测试才意外地重新出现。包括 Kent Beck、Ward Cunningham 和 Ron Jeffries 在内的一群程序员尝试将开发实践推向极端。他们的努力的结果被称为**极限编程**（**XP**）。其中一种实践就是单元测试，结果非常有趣。

常见的单元测试实践是在编写代码后写一些测试，作为测试期间的一部分。这些测试通常由测试人员编写——与实现功能的程序员不同的一个组。

然而，最初的 XPers 尝试了一种不同的单元测试方式。如果我们在编写代码的同时编写测试呢？更有趣的是，如果我们在*实现之前*编写测试呢？这导致了两种不同的技术——**测试驱动编程**（**TFP**），它包括首先编写一些测试，然后编写一些代码使测试通过，以及我们将在更详细地讨论的 TDD。

当我第一次听说这些技术时，我既感到困惑又着迷。你怎么能为不存在的东西编写测试呢？这有什么好处呢？幸运的是，在 J.B. Rainsberger 的支持下，我很快意识到了 TFP/TDD 的力量。我们的客户和利益相关者希望尽快在软件中获得可用的功能。然而，往往他们无法解释他们想要的功能。从测试开始意味着你完全理解了要实现什么，并且会引发有用和有趣的对话，澄清需求。一旦需求明确，我们就可以专注于实现。此外，在 TDD 中，我们尽快清理代码，以免随着时间的推移造成混乱。这真的是一种非常强大的技术！

但让我们从头开始。我们如何编写单元测试呢？更重要的是，对于我们的目的来说，为纯函数编写单元测试更容易吗？

# 纯函数的单元测试

让我们首先看一下单元测试是什么样子的。在本书中，我已经使用了一段时间，我相信你能理解这段代码。但是现在是时候看一个特定的例子了：

```cpp
TEST_CASE("Greater Than"){
    int first = 3;
    int second = 2;

    bool result = greater<int>()(first, second);

    CHECK(result);
}
```

我们首先使用特定值初始化两个变量（单元测试的*安排*部分）。然后我们调用生产代码（单元测试的*行动*部分）。最后，我们检查结果是否符合我们的预期（单元测试的*断言*部分）。我们正在使用的名为`doctest`的库提供了允许我们编写单元测试的宏的实现。虽然 C++存在更多的单元测试库，包括 GTest 和`Boost::unit_test`等，但它们提供给程序员的功能相当相似。

在谈论单元测试时，更重要的是找出使其有用的特征。前面的测试是小型、专注、快速的，只能因为一个原因而失败。所有这些特征使测试有用，因为它易于编写、易于维护、清晰明了，并且在引入错误时提供有用和快速的反馈。

在技术方面，前面的测试是基于示例的，因为它使用一个非常具体的示例来检查代码的特定行为。我们将在第十一章中看到一种名为**基于属性的测试**的不同单元测试方法，*基于属性的测试*。由于这是基于示例的测试，一个有趣的问题出现了：如果我们想测试`greaterThan`函数，还有哪些其他示例会很有趣呢？

好吧，我们想要查看函数的所有可能行为。那么，它可能的输出是什么？以下是一个列表：

+   如果第一个值大于第二个值，则为 True

+   如果第一个值小于第二个值，则为 False

然而，这还不够。让我们添加边缘情况：

+   如果第一个值等于第二个值，则为 False

还有，不要忘记可能的错误。传入值的域是什么？可以传入负值吗？浮点数值？复数？这是与该函数的利益相关者进行有趣对话。

现在让我们假设最简单的情况——该函数将仅接受有效的整数。这意味着我们需要另外两个单元测试来检查第一个参数小于第二个参数的情况以及两者相等的情况：

```cpp
TEST_CASE("Not Greater Than when first is less than second"){
    int first = 2;
    int second = 3;

    bool result = greater<int>()(first, second);

    CHECK_FALSE(result);
}

TEST_CASE("Not Greater Than when first equals second"){
    int first = 2;

    bool result = greater<int>()(first, first);

    CHECK_FALSE(result);
}
```

在第七章中，*使用功能操作去除重复*，我们讨论了代码相似性以及如何去除它。在这里，我们有一个测试之间的相似性。去除它的一种方法是编写所谓的**数据驱动测试**（**DDT**）。在 DDT 中，我们编写一组输入和期望的输出，并在每行数据上重复测试。不同的测试框架提供了不同的编写这些测试的方式；目前，`doctest`对 DDT 的支持有限，但我们仍然可以按照以下方式编写它们：

```cpp
TEST_CASE("Greater than") {
    struct Data {
        int first;
        int second;
        bool expected;
 } data;

    SUBCASE("2 is greater than 1") { data.first = 2; data.second = 1; 
        data.expected = true; }
    SUBCASE("2 is not greater than 2") { data.first = 2; data.second = 
         2; data.expected = false; }
    SUBCASE("2 is not greater than 3") { data.first = 2; data.second = 
         3; data.expected = false; }

    CAPTURE(data);

    CHECK_EQ(greaterThan(data.first, data.second), data.expected);
}
```

如果我们忽略管道代码（`struct Data`定义和对`CAPTURE`宏的调用），这显示了一种非常方便的编写测试的方式——特别是对于纯函数。鉴于纯函数根据定义在接收相同输入时返回相同输出，用一组输入/输出进行测试是很自然的。

DDT 的另一个便利之处在于，我们可以通过向列表添加新行来轻松添加新的测试。这在使用纯函数进行 TDD 时特别有帮助。

# TDD 循环

TDD 是一个常见的开发循环，通常如下所示：

+   **红色**：编写一个失败的测试。

+   **绿色**：通过对生产代码进行尽可能小的更改来使测试通过。

+   **重构**：重新组织代码以包含新引入的行为。

然而，TDD 的实践者（比如我自己）会急于提到 TDD 循环始于另一步骤——思考。更准确地说，在编写第一个测试之前，让我们理解我们要实现的内容，并找到现有代码中添加行为的好位置。

这个循环看起来简单得令人误解。然而，初学者经常在第一个测试应该是什么以及之后的测试应该是什么方面挣扎，同时编写过于复杂的代码。**重构**本身就是一门艺术，需要对代码异味、设计原则和设计模式有所了解。总的来说，最大的错误是过于考虑你想要获得的代码结构，并编写导致那种结构的测试。

相反，TDD 需要一种心态的改变。我们从行为开始，在小步骤中完善适合该行为的代码结构。一个好的实践者会有小于 15 分钟的步骤。但这并不是 TDD 的唯一惊喜。

TDD 最大的惊喜是，它可以通过允许您探索同一问题的各种解决方案来教您软件设计。您愿意探索的解决方案越多，您在设计代码方面就会变得越好。当以适当的好奇心进行实践时，TDD 是一个持续的学习经验。

我希望我引起了你对 TDD 的好奇心。关于这个主题还有很多要学习的，但是对于我们的目标来说，尝试一个例子就足够了。而且，由于我们正在谈论函数式编程，我们将使用 TDD 来设计一个纯函数。

# 例子——使用 TDD 设计一个纯函数

再次，我们需要一个问题来展示 TDD 的实际应用。由于我喜欢使用游戏来练习开发实践，我查看了 Coding Dojo Katas（[`codingdojo.org/kata/PokerHands/`](http://codingdojo.org/kata/)）的列表，并选择了扑克牌问题来进行练习。

# 扑克牌问题

问题的描述如下——给定两个或多个扑克牌手，我们需要比较它们并返回排名较高的手以及它赢得的原因。

每手有五张牌，这些牌是从一副普通的 52 张牌的牌组中挑选出来的。牌组由四种花色组成——梅花、方块、红桃和黑桃。每种花色从`2`开始，以 A 结束，表示如下——`2`、`3`、`4`、`5`、`6`、`7`、`8`、`9`、`T`、`J`、`Q`、`K`、`A`（`T`表示 10）。

扑克牌手中的牌将形成不同的组合。手的价值由这些组合决定，按以下降序排列：

+   **同花顺**：五张相同花色的牌，连续的值。例如，`2♠`，`3♠`，`4♠`，`5♠`和`6♠`。起始值越高，同花顺的价值就越高。

+   **四条**：四张相同牌值的牌。最高的是四张 A——`A♣`，`A♠`，`A♦`和`A♥`。

+   **葫芦**：三张相同牌值的牌，另外两张牌也是相同的牌值（但不同）。最高的是——`A♣`，`A♠`，`A♦`，`K♥`和`K♠`。

+   **同花**：五张相同花色的牌。例如——`2♠`，`3♠`，`5♠`，`6♠`和`9♠`。

+   **顺子**：五张连续值的牌。例如——`2♣`，`3♠`，`4♥`，`5♣`和`6♦`。

+   **三条**：三张相同牌值的牌。例如——`2♣`，`2♠`和`2♥`。

+   **两对**：见对子。例如——`2♣`，`2♠`，`3♥`和`3♣`。

+   **对子**：两张相同牌值的牌。例如——`2♣`和`2♠`。

+   **高牌**：当没有其他组合时，比较每手中最高的牌，最高的获胜。如果最高的牌具有相同的值，则比较下一个最高的牌，以此类推。

# 要求

我们的目标是实现一个程序，比较两个或更多个扑克牌手，并返回赢家和原因。例如，让我们使用以下输入：

+   **玩家 1**：`*2♥ 4♦ 7♣ 9♠ K♦*`

+   **玩家 2**：`*2♠ 4♥ 8♣ 9♠ A♥*`

对于这个输入，我们应该得到以下输出：

+   *玩家 2 以他们的高牌——一张 A 赢得比赛*

# 步骤 1 - 思考

让我们更详细地看一下问题。更准确地说，我们试图将问题分解为更小的部分，而不要过多考虑实现。我发现查看可能的输入和输出示例，并从一个简化的问题开始，可以让我尽快实现一些有效的东西，同时保持问题的本质。

很明显，我们有很多组合要测试。那么，什么是限制我们测试用例的问题的有用简化呢？

一个明显的方法是从手中的牌较少开始。我们可以从一张牌开始，而不是五张牌。这将限制我们的规则为高牌。下一步是有两张牌，这引入了*对子>高牌*，*更高的对子>更低的对子*，依此类推。

另一种方法是从五张牌开始，但限制规则。从高牌开始，然后实现一对，然后两对，依此类推；或者，从同花顺一直到对子和高牌。

TDD 的有趣之处在于，这些方法中的任何一个都将以相同的方式产生结果，尽管通常使用不同的代码结构。TDD 的一个优势是通过改变测试的顺序来帮助您访问相同问题的多种设计。

不用说，我以前做过这个问题，但我总是从手中的一张牌开始。让我们有些乐趣，尝试一种不同的方式，好吗？我选择用五张牌开始，从同花顺开始。为了保持简单，我现在只支持两个玩家，而且由于我喜欢给他们起名字，我会用 Alice 和 Bob。

# 例子

对于这种情况，有一些有趣的例子是什么？让我们先考虑可能的输出：

+   Alice 以同花顺获胜。

+   Bob 以同花顺获胜。

+   Alice 和 Bob 有同样好的同花顺。

+   未决（即尚未实施）。

现在，让我们写一些这些输出的输入示例：

```cpp
Case 1: Alice wins

Inputs:
 Alice: 2♠, 3♠, 4♠, 5♠, 6♠
 Bob: 2♣, 4♦, 7♥, 9♠, A♥

Output:
 Alice wins with straight flush

Case 2: Bob wins

Inputs:
    Alice: 2♠, 3♠, 4♠, 5♠, 9♠
    Bob: 2♣, 3♣, 4♣, 5♣, 6♣

Output:
    Bob wins with straight flush

Case 3: Alice wins with a higher straight flush

Inputs:
    Alice: 3♠, 4♠, 5♠, 6♠, 7♠
    Bob: 2♣, 3♣, 4♣, 5♣, 6♣

Output:
    Alice wins with straight flush

Case 4: Draw

Inputs:
    Alice: 3♠, 4♠, 5♠, 6♠, 7♠
    Bob: 3♣, 4♣, 5♣, 6♣, 7♣

Output:
    Draw (equal straight flushes)

Case 5: Undecided

Inputs:
    Alice: 3♠, 3♣, 5♠, 6♠, 7♠
    Bob: 3♣, 4♣, 6♣, 6♥, 7♣

Output:
    Not implemented yet.

```

有了这些例子，我们准备开始编写我们的第一个测试！

# 第一个测试

根据我们之前的分析，我们的第一个测试如下：

```cpp
Case 1: Alice wins

Inputs:
 Alice: 2♠, 3♠, 4♠, 5♠, 6♠
 Bob: 2♣, 4♦, 7♥, 9♠, A♥

Output:
 Alice wins with straight flush
```

让我们写吧！我们期望这个测试失败，所以在这一点上我们可以做任何我们想做的事情。我们需要用前面的卡片初始化两只手。现在，我们将使用`vector<string>`来表示每只手。然后，我们将调用一个函数（目前还不存在）来比较这两只手，我们想象这个函数将在某个时候实现。最后，我们将检查结果是否与之前定义的预期输出消息相匹配：

```cpp
TEST_CASE("Alice wins with straight flush"){
    vector<string> aliceHand{"2♠", "3♠", "4♠", "5♠", "6♠"};
    vector<string> bobHand{"2♣", "4♦", "7♥", "9♠", "A♥"};

    auto result = comparePokerHands(aliceHand, bobHand);

    CHECK_EQ("Alice wins with straight flush", result);
}
```

现在，这个测试无法编译，因为我们甚至还没有创建`comparePokerHands`函数。是时候继续前进了。

# 使第一个测试通过

让我们先写这个函数。这个函数需要返回一些东西，所以我们暂时只返回空字符串：

```cpp
auto comparePokerHands = [](const auto& aliceHand, const auto& bobHand){
    return "";
};
```

使测试通过的最简单实现是什么？这是 TDD 变得更加奇怪的地方。使测试通过的最简单实现是将预期结果作为硬编码值返回：

```cpp
auto comparePokerHands = [](const auto& aliceHand, const auto& bobHand){
    return "Alice wins with straight flush";
};
```

此时，我的编译器抱怨了，因为我打开了所有警告，并且将所有警告报告为错误。编译器注意到我们没有使用这两个参数并抱怨。这是一个合理的抱怨，但我计划很快开始使用这些参数。C++语言给了我们一个简单的解决方案——只需删除或注释掉参数名，如下面的代码所示：

```cpp
auto comparePokerHands = [](const auto& /*aliceHand*/, const auto&  
    /*bobHand*/){
        return "Alice wins with straight flush";
};
```

我们运行测试，我们的第一个测试通过了！太棒了，有东西可以用了！

# 重构

有什么需要重构的吗？嗯，我们有两个被注释掉的参数名，我通常会把它们删除掉，因为注释掉的代码只会增加混乱。但是，我决定暂时保留它们，因为我知道我们很快会用到它们。

我们还有一个重复的地方——在测试和实现中都出现了相同的“Alice 以顺子获胜”的字符串。值得把它提取为一个常量或者公共变量吗？如果这是我们的实现的最终结果，那当然可以。但我知道这个字符串实际上是由多个部分组成的——获胜玩家的名字，以及根据哪种手牌获胜的规则。我想暂时保持它原样。

因此，没有什么需要重构的。让我们继续吧！

# 再次思考

当前的实现感觉令人失望。只是返回一个硬编码的值并不能解决太多问题。或者呢？

这是学习 TDD 时需要的心态转变。我知道这一点，因为我经历过。我习惯于看最终结果，将这个解决方案与我试图实现的目标进行比较，感觉令人失望。然而，有一种不同的看待方式——我们有一个可以工作的东西，而且我们有最简单的实现。还有很长的路要走，但我们已经可以向利益相关者展示一些东西。而且，正如我们将看到的，我们总是在坚实的基础上构建，因为我们编写的代码是经过充分测试的。这两件事是非常令人振奋的；我只希望你在尝试 TDD 时也能有同样的感受。

但是，接下来我们该怎么办呢？我们有几个选择。

首先，我们可以写另一个测试，其中 Alice 以顺子获胜。然而，这不会改变实现中的任何东西，测试会立即通过。虽然这似乎违反了 TDD 循环，但为了我们的安心，增加更多的测试并没有错。绝对是一个有效的选择。

其次，我们可以转移到下一个测试，其中 Bob 以顺子获胜。这肯定会改变一些东西。

这两个选项都不错，你可以选择其中任何一个。但由于我们想要看到 DDT 的实践，让我们先写更多的测试。

# 更多的测试

将我们的测试转换成 DDT 并添加更多的案例非常容易。我们只需改变 Alice 手牌的值，而保持 Bob 的手牌不变。结果如下：

```cpp
TEST_CASE("Alice wins with straight flush"){
    vector<string> aliceHand;
    const vector<string> bobHand {"2♣", "4♦", "7♥", "9♠", "A♥"};

    SUBCASE("2 based straight flush"){
        aliceHand = {"2♠", "3♠", "4♠", "5♠", "6♠"};
    };
    SUBCASE("3 based straight flush"){
        aliceHand = {"3♠", "4♠", "5♠", "6♠", "7♠"};
    };
    SUBCASE("4 based straight flush"){
        aliceHand = {"4♠", "5♠", "6♠", "7♠", "8♠"};
    };
    SUBCASE("10 based straight flush"){
        aliceHand = {"T♠", "J♠", "Q♠", "K♠", "A♠"};
    };

    CAPTURE(aliceHand);

    auto result = comparePokerHands(aliceHand, bobHand);

    CHECK_EQ("Alice wins with straight flush", result);
}
```

再次，所有这些测试都通过了。是时候继续进行我们的下一个测试了。

# 第二个测试

我们描述的第二个测试是 Bob 以顺子获胜：

```cpp
Case: Bob wins

Inputs:
 Alice: 2♠, 3♠, 4♠, 5♠, 9♠
 Bob: 2♣, 3♣, 4♣, 5♣, 6♣

Output:
 Bob wins with straight flush
```

让我们写吧！这一次，让我们从一开始就使用数据驱动的格式：

```cpp
TEST_CASE("Bob wins with straight flush"){
    const vector<string> aliceHand{"2♠", "3♠", "4♠", "5♠", "9♠"};
    vector<string> bobHand;

    SUBCASE("2 based straight flush"){
        bobHand = {"2♣", "3♣", "4♣", "5♣", "6♣"};
    };

    CAPTURE(bobHand);

    auto result = comparePokerHands(aliceHand, bobHand);

    CHECK_EQ("Bob wins with straight flush", result);
}
```

当我们运行这个测试时，它失败了，原因很简单——我们有一个硬编码的实现，说 Alice 获胜。现在怎么办？

# 使测试通过

再次，我们需要找到使这个测试通过的最简单方法。即使我们可能不喜欢这个实现，下一步是清理混乱。那么，最简单的实现是什么呢？

显然，我们需要在我们的实现中引入一个条件语句。问题是，我们应该检查什么？

再次，我们有几个选择。一个选择是再次伪装，使用与我们期望获胜的确切手牌进行比较：

```cpp
auto comparePokerHands = [](const vector<string>& /*aliceHand*/, const vector<string>& bobHand){
    const vector<string> winningBobHand {"2♣", "3♣", "4♣", "5♣", "6♣"};
    if(bobHand == winningBobHand){
        return "Bob wins with straight flush";
    }
    return "Alice wins with straight flush";
};
```

为了使其编译，我们还必须使`vector<string>` hands 的类型出现在各处。一旦这些更改完成，测试就通过了。

我们的第二个选择是开始实现实际的同花顺检查。然而，这本身就是一个小问题，要做好需要更多的测试。

我现在会选择第一种选项，重构，然后开始更深入地研究检查同花顺的实现。

# 重构

有什么需要重构的吗？我们仍然有字符串的重复。此外，我们在包含 Bob 的手的向量中添加了重复。但我们期望这两者很快都会消失。

然而，还有一件事让我感到不安——`vector<string>` 出现在各处。让我们通过为`vector<string>`类型命名为`Hand`来消除这种重复：

```cpp
using Hand = vector<string>;

auto comparePokerHands = [](const Hand& /*aliceHand*/, const Hand& bobHand){
    Hand winningBobHand {"2♣", "3♣", "4♣", "5♣", "6♣"};
    if(bobHand == winningBobHand){
        return "Bob wins with straight flush";
    }
    return "Alice wins with straight flush";
};

TEST_CASE("Bob wins with straight flush"){
    Hand aliceHand{"2♠", "3♠", "4♠", "5♠", "9♠"};
    Hand bobHand;

    SUBCASE("2 based straight flush"){
        bobHand = {"2♣", "3♣", "4♣", "5♣", "6♣"};
    };

    CAPTURE(bobHand);

    auto result = comparePokerHands(aliceHand, bobHand);

    CHECK_EQ("Bob wins with straight flush", result);
}
```

# 思考

再次思考。我们已经用硬编码的值实现了两种情况。对于 Alice 以同花顺获胜并不是一个大问题，但如果我们为 Bob 添加另一组不同的牌测试用例，这就是一个问题。我们可以进行更多的测试，但不可避免地，我们需要实际检查同花顺。我认为现在是一个很好的时机。

那么，什么是同花顺？它是一组有相同花色和连续值的五张牌。我们需要一个函数，它可以接受一组五张牌，并在是同花顺时返回`true`，否则返回`false`。让我们写下一些例子：

+   输入：`2♣ 3♣ 4♣ 5♣ 6♣` => 输出：`true`

+   输入：`2♠ 3♠ 4♠ 5♠ 6♠` => 输出：`true`

+   输入：`T♠ J♠ Q♠ K♠ A♠` => 输出：`true`

+   输入：`2♣ 3♣ 4♣ 5♣ 7♣` => 输出：`false`

+   输入：`2♣ 3♣ 4♣ 5♣ 6♠` => 输出：`false`

+   输入：`2♣ 3♣ 4♣ 5♣` => 输出：`false`（只有四张牌，需要正好五张）

+   输入：`[空向量]` => 输出：`false`（没有牌，需要正好五张）

+   输入：`2♣ 3♣ 4♣ 5♣ 6♣ 7♣` => 输出：`false`（六张牌，需要正好五张）

你会注意到我们也考虑了边缘情况和奇怪的情况。我们有足够的信息可以继续，所以让我们写下下一个测试。

# 下一个测试-简单的同花顺

我更喜欢从正面案例开始，因为它们往往会更推进实现。让我们看最简单的一个：

+   输入：`2♣ 3♣ 4♣ 5♣ 6♣` => 输出：`true`

测试如下：

```cpp
TEST_CASE("Hand is straight flush"){
    Hand hand;

    SUBCASE("2 based straight flush"){
        hand = {"2♣", "3♣", "4♣", "5♣", "6♣"};
    };

    CAPTURE(hand);

    CHECK(isStraightFlush(hand));
}
```

再次，测试无法编译，因为我们没有实现`isStraightFlush`函数。但测试是正确的，它失败了，所以是时候继续了。

# 使测试通过

再次，第一步是编写函数的主体并返回预期的硬编码值：

```cpp
auto isStraightFlush = [](const Hand&){
    return true;
};
```

我们运行了测试，它们通过了，所以现在我们完成了！

# 继续前进

嗯，你可以看到这是怎么回事。我们可以为正确的同花顺添加一些更多的输入，但它们不会改变实现。第一个将迫使我们推进实现的测试是我们的第一个不是同花顺的一组牌的例子。

对于本章的目标，我将快进。但我强烈建议你自己经历所有的小步骤，并将你的结果与我的进行比较。学习 TDD 的唯一方法是自己练习并反思自己的方法。

# 实现 isStraightFlush

让我们再次看看我们要达到的目标——同花顺，它由正好五张具有相同花色和连续值的牌定义。我们只需要在代码中表达这三个条件：

```cpp
auto isStraightFlush = [](const Hand& hand){
    return has5Cards(hand) && 
        isSameSuit(allSuits(hand)) && 
        areValuesConsecutive(allValuesInOrder(hand));
};
```

实现得到了一些不同的 lambda 的帮助。首先，为了检查组合的长度，我们使用`has5Cards`：

```cpp
auto has5Cards = [](const Hand& hand){
    return hand.size() == 5;
};
```

然后，为了检查它是否有相同的花色，我们使用`allSuits`来提取手中的花色，`isSuitEqual`来比较两个花色，`isSameSuit`来检查手中的所有花色是否相同：

```cpp
using Card = string;
auto suitOf = [](const Card& card){
    return card.substr(1);
};

auto allSuits = [](Hand hand){
    return transformAll<vector<string>>(hand, suitOf);
};

auto isSameSuit = [](const vector<string>& allSuits){
    return std::equal(allSuits.begin() + 1, allSuits.end(),  
        allSuits.begin());
};
```

最后，为了验证这些值是连续的，我们使用`valueOf`从一张牌中提取值，使用`allValuesInOrder`获取一手牌中的所有值并排序，使用`toRange`从一个初始值开始创建一系列连续的值，使用`areValuesConsecutive`检查一手牌中的值是否连续：

```cpp
auto valueOf = [](const Card& card){
    return charsToCardValues.at(card.front());
};

auto allValuesInOrder = [](const Hand& hand){
    auto theValues = transformAll<vector<int>>(hand, valueOf);
    sort(theValues.begin(), theValues.end());
    return theValues;
};

auto toRange = [](const auto& collection, const int startValue){
    vector<int> range(collection.size());
    iota(begin(range), end(range), startValue);
    return range;
};

auto areValuesConsecutive = [](const vector<int>& allValuesInOrder){
    vector<int> consecutiveValues = toRange(allValuesInOrder, 
        allValuesInOrder.front());

    return consecutiveValues == allValuesInOrder;
};
```

最后一块拼图是一个从`char`到`int`的映射，帮助我们将所有的牌值，包括`T`、`J`、`Q`、`K`和`A`，转换成数字：

```cpp
const std::map<char, int> charsToCardValues = {
    {'1', 1},
    {'2', 2},
    {'3', 3},
    {'4', 4},
    {'5', 5},
    {'6', 6},
    {'7', 7},
    {'8', 8},
    {'9', 9},
    {'T', 10},
    {'J', 11},
    {'Q', 12},
    {'K', 13},
    {'A', 14},
};
```

让我们也看一下我们的测试（显然都通过了）。首先是有效的顺子同花的测试；我们将检查以`2`、`3`、`4`和`10`开头的顺子同花，以及它们在数据区间上的变化：

```cpp
TEST_CASE("Hand is straight flush"){
    Hand hand;

    SUBCASE("2 based straight flush"){
        hand = {"2♣", "3♣", "4♣", "5♣", "6♣"};
    };

    SUBCASE("3 based straight flush"){
        hand = {"3♣", "4♣", "5♣", "6♣", "7♣"};
    };

    SUBCASE("4 based straight flush"){
        hand = {"4♣", "5♣", "6♣", "7♣", "8♣"};
    };

    SUBCASE("4 based straight flush on hearts"){
        hand = {"4♥", "5♥", "6♥", "7♥", "8♥"};
    };

    SUBCASE("10 based straight flush on hearts"){
        hand = {"T♥", "J♥", "Q♥", "K♥", "A♥"};
    };

    CAPTURE(hand);

    CHECK(isStraightFlush(hand));
}
```

最后，对于一组不是有效顺子同花的牌的测试。我们将使用几乎是顺子同花的手牌作为输入，除了花色不同、牌数不够或者牌数太多之外：

```cpp
TEST_CASE("Hand is not straight flush"){
    Hand hand;

    SUBCASE("Would be straight flush except for one card from another 
        suit"){
            hand = {"2♣", "3♣", "4♣", "5♣", "6♠"};
    };

    SUBCASE("Would be straight flush except not enough cards"){
        hand = {"2♣", "3♣", "4♣", "5♣"};
    };

    SUBCASE("Would be straight flush except too many cards"){
        hand = {"2♣", "3♣", "4♣", "5♣", "6♠", "7♠"};
    };

    SUBCASE("Empty hand"){
        hand = {};
    };

    CAPTURE(hand);

    CHECK(!isStraightFlush(hand));
}
```

现在是时候回到我们的主要问题了——比较扑克牌的手。

# 将检查顺子同花的代码重新插入到 comparePokerHands 中

尽管我们迄今为止实现了所有这些，但我们的`comparePokerHands`的实现仍然是硬编码的。让我们回顾一下它当前的状态：

```cpp
auto comparePokerHands = [](const Hand& /*aliceHand*/, const Hand& bobHand){
    const Hand winningBobHand {"2♣", "3♣", "4♣", "5♣", "6♣"};
    if(bobHand == winningBobHand){
        return "Bob wins with straight flush";
    }
    return "Alice wins with straight flush";
};
```

但是，现在我们有了检查顺子同花的方法！所以，让我们把我们的实现插入进去：

```cpp
auto comparePokerHands = [](Hand /*aliceHand*/, Hand bobHand){
    if(isStraightFlush(bobHand)) {
        return "Bob wins with straight flush";
    }
    return "Alice wins with straight flush";
};
```

所有的测试都通过了，所以我们快要完成了。是时候为我们的`Bob 赢得顺子同花`情况添加一些额外的测试，以确保我们没有遗漏。我们将保持 Alice 的相同手牌，一个几乎是顺子同花的手牌，然后改变 Bob 的手牌，从以`2`、`3`和`10`开头的顺子同花：

```cpp
TEST_CASE("Bob wins with straight flush"){
    Hand aliceHand{"2♠", "3♠", "4♠", "5♠", "9♠"};
    Hand bobHand;

    SUBCASE("2 based straight flush"){
        bobHand = {"2♣", "3♣", "4♣", "5♣", "6♣"};
    };

    SUBCASE("3 based straight flush"){
        bobHand = {"3♣", "4♣", "5♣", "6♣", "7♣"};
    };

    SUBCASE("10 based straight flush"){
        bobHand = {"T♣", "J♣", "Q♣", "K♣", "A♣"};
    };

    CAPTURE(bobHand);

    auto result = comparePokerHands(aliceHand, bobHand);

    CHECK_EQ("Bob wins with straight flush", result);
}
```

所有之前的测试都通过了。所以，我们已经完成了两种情况——当 Alice 或 Bob 有顺子同花而对手没有时。是时候转移到下一个情况了。

# 比较两个顺子同花

正如我们在本节开头讨论的那样，当 Alice 和 Bob 都有顺子同花时还有另一种情况，但是 Alice 用更高的顺子同花赢了：

```cpp
Case: Alice wins with a higher straight flush

Inputs:
 Alice: 3♠, 4♠, 5♠, 6♠, 7♠
 Bob: 2♣, 3♣, 4♣, 5♣, 6♣

Output:
 Alice wins with straight flush
```

让我们写下测试并运行它：

```cpp
TEST_CASE("Alice and Bob have straight flushes but Alice wins with higher straight flush"){
    Hand aliceHand;
    Hand bobHand{"2♣", "3♣", "4♣", "5♣", "6♣"};

    SUBCASE("3 based straight flush"){
        aliceHand = {"3♠", "4♠", "5♠", "6♠", "7♠"};
    };

    CAPTURE(aliceHand);

    auto result = comparePokerHands(aliceHand, bobHand);

    CHECK_EQ("Alice wins with straight flush", result);
}
```

测试失败了，因为我们的`comparePokerHands`函数返回 Bob 赢了，而不是 Alice。让我们用最简单的实现来修复这个问题：

```cpp
auto comparePokerHands = [](const Hand& aliceHand, const Hand& bobHand){
    if(isStraightFlush(bobHand) && isStraightFlush(aliceHand)){
         return "Alice wins with straight flush";
    }

    if(isStraightFlush(bobHand)) {
        return "Bob wins with straight flush";
    }

    return "Alice wins with straight flush";
};
```

我们的实现决定了如果 Alice 和 Bob 都有顺子同花，那么 Alice 总是赢。这显然不是我们想要的，但测试通过了。那么我们可以写什么测试来推动实现向前发展呢？

# 思考

事实证明，我们在之前的分析中漏掉了一个情况。我们看了当 Alice 和 Bob 都有顺子同花并且 Alice 赢的情况；但是如果 Bob 有更高的顺子同花呢？让我们写一个例子：

```cpp
Case: Bob wins with a higher straight flush

Inputs:
 Alice: 3♠, 4♠, 5♠, 6♠, 7♠
 Bob: 4♣, 5♣, 6♣, 7♣, 8♣

Output:
 Bob wins with straight flush
```

是时候写另一个失败的测试了。

# 比较两个顺子同花（续）

现在写这个测试已经相当明显了：

```cpp
TEST_CASE("Alice and Bob have straight flushes but Bob wins with higher 
    straight flush"){
        Hand aliceHand = {"3♠", "4♠", "5♠", "6♠", "7♠"};
        Hand bobHand;

        SUBCASE("3 based straight flush"){
            bobHand = {"4♣", "5♣", "6♣", "7♣", "8♣"};
    };

    CAPTURE(bobHand);

    auto result = comparePokerHands(aliceHand, bobHand);

    CHECK_EQ("Bob wins with straight flush", result);
}
```

测试再次失败了，因为我们的实现假设当 Alice 和 Bob 都有顺子同花时，Alice 总是赢。也许是时候检查哪个是它们中最高的顺子同花了。

为此，我们需要再次写下一些情况并进行 TDD 循环。我将再次快进到实现。我们最终得到了以下的辅助函数，用于比较两个顺子同花。如果第一手牌有更高的顺子同花，则返回`1`，如果两者相等，则返回`0`，如果第二手牌有更高的顺子同花，则返回`-1`：

```cpp
auto compareStraightFlushes = [](const Hand& first, const Hand& second){
    int firstHandValue = allValuesInOrder(first).front();
    int secondHandValue = allValuesInOrder(second).front();
    if(firstHandValue > secondHandValue) return 1;
    if(secondHandValue > firstHandValue) return -1;
    return 0;
};
```

通过改变我们的实现，我们可以让测试通过：

```cpp
auto comparePokerHands = [](const Hand& aliceHand, const Hand& bobHand){
    if(isStraightFlush(bobHand) && isStraightFlush(aliceHand)){
        int whichIsHigher = compareStraightFlushes(aliceHand, bobHand);
        if(whichIsHigher == 1) return "Alice wins with straight flush";
        if(whichIsHigher == -1) return "Bob wins with straight flush";
    }

    if(isStraightFlush(bobHand)) {
        return "Bob wins with straight flush";
    }

    return "Alice wins with straight flush";
};
```

这让我们留下了最后一种情况——平局。测试再次非常明确：

```cpp
TEST_CASE("Draw due to equal straight flushes"){
    Hand aliceHand;
    Hand bobHand;

    SUBCASE("3 based straight flush"){
        aliceHand = {"3♠", "4♠", "5♠", "6♠", "7♠"};
    };

    CAPTURE(aliceHand);
    bobHand = aliceHand;

    auto result = comparePokerHands(aliceHand, bobHand);

    CHECK_EQ("Draw", result);
}
```

而且实现的改变非常直接：

```cpp
auto comparePokerHands = [](Hand aliceHand, Hand bobHand){
    if(isStraightFlush(bobHand) && isStraightFlush(aliceHand)){
        int whichIsHigher = compareStraightFlushes(aliceHand, bobHand);
        if(whichIsHigher == 1) return "Alice wins with straight flush";
        if(whichIsHigher == -1) return "Bob wins with straight flush";
        return "Draw";
    }

    if(isStraightFlush(bobHand)) {
        return "Bob wins with straight flush";
    }

    return "Alice wins with straight flush";
};
```

这不是最漂亮的函数，但它通过了我们所有的顺子同花比较测试。我们肯定可以将它重构为更小的函数，但我会在这里停下来，因为我们已经达到了我们的目标——使用 TDD 和 DDT 设计了不止一个纯函数。

# 总结

在本章中，你学会了如何编写单元测试，如何编写数据驱动测试，以及如何将数据驱动测试与 TDD 结合起来设计纯函数。

TDD 是有效软件开发的核心实践之一。虽然有时可能看起来奇怪和违反直觉，但它有一个强大的优势——每隔几分钟，你都有一个可以演示的工作内容。通过测试通过不仅是一个演示点，而且也是一个保存点。如果在尝试重构或实现下一个测试时发生任何错误，你总是可以回到上一个保存点。我发现这种实践在 C++中更有价值，因为有很多事情可能会出错。事实上，我自第三章 *深入了解 Lambda*以来，都是采用 TDD 方法编写的所有代码。这非常有帮助，因为我知道我的代码是有效的——在没有这种方法的情况下编写技术书籍时，这是相当困难的。我强烈建议你更深入地了解 TDD 并亲自实践；这是你成为专家的唯一途径。

函数式编程与 TDD 完美契合。当将其与命令式面向对象的代码一起使用时，我们经常需要考虑到变异，这使事情变得更加困难。通过纯函数和数据驱动的测试，添加更多的测试实践变得尽可能简单，并允许我们专注于实现。在函数操作的支持下，在许多情况下使测试通过变得更容易。我个人发现这种组合非常有益；我希望你也会觉得同样有用。

现在是时候向前迈进，重新审视软件设计的另一个部分——设计模式。它们在函数式编程中会发生变化吗？（剧透警告——实际上它们变得简单得多。）这是我们将在下一章讨论的内容。


# 第三部分：收获函数式编程的好处

我们已经学到了很多关于函数式编程的构建模块，如何在 C++中编写它们以及如何使用它们来构建以函数为中心的设计。现在是时候看一看与函数式编程密切相关的一些专门主题了。

首先，我们将深入探讨性能优化这一巨大的主题。我们将学习一些特别适合纯函数的优化技术（例如，记忆化和尾递归优化）。我们将同时关注内存占用和执行时间的优化，进行许多测量，并比较不同的方法。

然后，我们将研究函数式编程如何实现并行和异步执行。不变性导致了对共享状态的避免，因此，对并行执行模式的简化。

但我们可以利用更多的函数式编程。数据生成器和纯函数使得一种称为**基于属性的测试**的自动化测试范式成为可能，这使我们能够用很少的代码检查许多可能的场景。然后，如果我们需要重构复杂的现有代码，我们会发现我们可以首先将其重构为纯函数，快速为其编写测试，然后决定是否将其重新分发到类中或保留它们。

最后，我们将提升到更高的层次，基于不可变状态的架构范式，因此，与函数式编程密切相关的东西：事件溯源。

以下章节将在本节中涵盖：

+   第十章，性能优化

+   第十一章，基于属性的测试

+   第十二章，重构到和通过纯函数

+   第十三章，不变性和架构-事件溯源


# 第十章：性能优化

性能是选择 C++作为项目编程语言的关键驱动因素之一。现在是讨论如何在以函数式风格构建代码时改善性能的时候了。

虽然性能是一个庞大的主题，显然我们无法在一个章节中完全覆盖，但我们将探讨改善性能的关键思想，纯函数式语言如何优化性能，以及如何将这些优化转化为 C++。

本章将涵盖以下主题：

+   交付性能的流程

+   如何使用并行/异步来提高性能

+   理解什么是尾递归以及如何激活它

+   如何在使用函数式构造时改善内存消耗

+   功能性异步代码

# 技术要求

您需要一个支持 C++ 17 的编译器。我使用的是 GCC 7.3.0。

代码可以在 GitHub 上找到，位于[https:/​/​github.​com/​PacktPublishing/​Hands-​On-​Functional-Programming-​with-​Cpp](https://github.%E2%80%8Bcom/PacktPublishing/Hands-On-Functional-Programming-with-Cpp)的`Chapter10`文件夹中。它包括并使用`doctest`，这是一个单头文件的开源单元测试库。您可以在其 GitHub 存储库上找到它，网址为[https:/​/github.​com/​onqtam/​doctest](https://github.%E2%80%8Bcom/onqtam/doctest)。

# 性能优化

谈论性能优化就像谈论披萨。有些人喜欢和寻找菠萝披萨。其他人只吃传统的意大利披萨（或来自特定地区的披萨）。有些人只吃素食披萨，而其他人喜欢各种披萨。关键是，性能优化是与您的代码库和产品相关的。您正在寻找什么样的性能？对于您的用户来说，性能的最有价值的部分是什么？您需要考虑哪些约束？

我与合作的客户通常有一些性能要求，取决于主题：

+   *嵌入式产品*（例如汽车、能源或电信）通常需要在内存限制内工作。堆栈和堆通常很小，因此限制了长期存在的变量数量。增加内存的成本可能是禁止性的（一位客户告诉我们，他们需要超过 1000 万欧元才能在所有设备上增加 1MB 的额外内存）。因此，程序员需要通过尽可能避免不必要的内存分配来解决这些限制。这可能包括初始化、通过复制传递参数（特别是较大的结构）以及避免需要内存消耗的特定算法，等等。

+   *工程应用*（例如计算机辅助设计或 CAD）需要在非常大的数据集上使用从数学、物理和工程中衍生出的特定算法，并尽快返回结果。处理通常在现代 PC 上进行，因此 RAM 不是问题；然而，CPU 是问题。随着多核 CPU 的出现，专用 GPU 可以接管部分处理工作以及允许在多个强大或专用服务器之间分配工作负载的云技术的出现，开发人员的工作往往变成了在并行和异步世界中优化速度。

+   *桌面游戏和游戏引擎*有它们自己特别的关注点。图形必须尽可能好看，以便在中低端机器上优雅地缩放，并避免延迟。游戏通常会占据它们运行的机器，因此它们只需要与操作系统和系统应用程序（如防病毒软件或防火墙）争夺资源。它们还可以假定特定级别的 GPU、CPU 和 RAM。优化变得关于并行性（因为预期有多个核心）以及避免浪费，以保持整个游戏过程中的流畅体验。

+   *游戏服务器*，然而，是一个不同的问题。例如暴雪的战网（我作为*星际争霸 II*玩家经常使用的一个）需要快速响应，即使在压力下也是如此。在云计算时代，使用的服务器数量和性能并不重要；我们可以轻松地扩展或缩减它们。主要问题是尽可能快地响应大多数 I/O 工作负载。

+   *未来令人兴奋*。游戏的趋势是将处理移动到服务器，从而使玩家甚至可以在低端机器上玩游戏。这将为未来的游戏开辟令人惊人的机会。（如果你有 10 个 GPU，你能做什么？如果有 100 个呢？）但也将导致需要优化游戏引擎以进行服务器端、多机器、并行处理。远离游戏，物联网行业为嵌入式软件和可扩展的服务器端处理提供了更多机会。

考虑到所有这些可能性，我们可以在代码库中做些什么来提供性能？

# 提供性能的流程

正如您所看到的，性能优化在很大程度上取决于您要实现的目标。下一步可以快速总结如下：

1.  为性能设定明确的目标，包括指标和如何测量它们。

1.  为性能定义一些编码准则。保持它们清晰并针对代码的特定部分进行调整。

1.  使代码工作。

1.  在需要的地方测量和改进性能。

1.  监控和改进。

在我们更详细地了解这些步骤之前，重要的是要理解性能优化的一个重要警告——有两种优化类型。第一种来自清晰的设计和清晰的代码。例如，通过从代码中删除某些相似性，您可能会减少可执行文件的大小，从而为数据提供更多空间；数据可能会通过代码传输得更少，从而避免不必要的复制或间接；或者，它将允许编译器更好地理解代码并为您进行优化。根据我的经验，将代码重构为简单设计也经常提高了性能。

改进性能的第二种方法是使用点优化。这些是非常具体的方式，我们可以重写函数或流程，使代码能够更快地工作或消耗更少的内存，通常适用于特定的编译器和平台。结果代码通常看起来很聪明，但很难理解和更改。

点优化与编写易于更改和维护的代码存在天然冲突。这导致了唐纳德·克努斯说*过早优化是万恶之源*。这并不意味着我们应该编写明显缓慢的代码，比如通过复制大型集合。然而，这意味着我们应该首先优化设计以便更易更改，然后测量性能，然后优化它，并且只在绝对必要时使用点优化。平台的怪癖、特定的编译器版本或使用的库可能需要不时进行点优化；将它们分开并节制使用。

现在让我们来看看我们的性能优化流程。

# 为性能设定明确的目标，包括指标和如何测量它们

如果我们不知道我们要去哪里，那么我们去哪个方向都无所谓——我是从《爱丽丝梦游仙境》中引用的。因此，我们应该知道我们要去哪里。我们需要一个适合我们产品需求的性能指标列表。此外，对于每个性能指标，我们需要一个定义该指标的*好*值和*可接受*值的范围。让我们看几个例子。

如果您正在为具有 4MB 内存的设备构建*嵌入式产品*，您可能会关注诸如：

+   内存消耗：

+   很好：1-3 MB

+   好：3-4 MB

+   设备启动时间：

+   很好：<1 秒

+   好：1-3 秒

如果你正在构建一个*桌面 CAD 应用程序*，用于模拟建筑设计中的声波，其他指标也很有趣。

模拟声波建模的计算时间：

+   对于一个小房间：

+   很好：<1 分钟

+   好：<5 分钟

+   对于一个中等大小的房间：

+   很好：<2 分钟

+   好：<10 分钟

这里的数字仅供参考；你需要为你的产品找到自己的度量标准。

有了这些度量标准和好/很好的范围，我们可以在添加新功能后测量性能并进行相应的优化。它还可以让我们向利益相关者或业务人员简单地解释产品的性能。

# 为性能定义一些编码准则-保持清晰，并针对代码的特定部分进行定制

如果你问 50 个不同的 C++程序员关于优化性能的建议，你很快就会被淹没在建议中。如果你开始调查这些建议，结果会发现其中一些已经过时，一些非常具体，一些很好。

因此，对性能有编码准则是很重要的，但有一个警告。C++代码库往往很庞大，因为它们已经发展了很多年。如果你对你的代码库进行批判性审视，你会意识到只有一部分代码是性能瓶颈。举个例子，如果一个数学运算快了 1 毫秒，只有当这个运算会被多次调用时才有意义；如果它只被调用一两次，或者很少被调用，就没有必要进行优化。事实上，下一个版本的编译器或 CPU 可能会比你更擅长优化它。

由于这个事实，你应该了解你的代码的哪些部分对你定义的性能标准至关重要。找出哪种设计最适合这个特定的代码片段；制定清晰的准则，并遵循它们。虽然`const&`在任何地方都很有用，也许你可以避免浪费开发人员的时间对一个只做一次的非常小的集合进行排序。

# 让代码工作

牢记这些准则，并有一个新功能要实现，第一步应该始终是让代码工作。此外，结构化使其易于在你的约束条件内进行更改。不要试图在这里优化性能；再次强调，编译器和 CPU 可能比你想象的更聪明，做的工作也比你期望的多。要知道是否是这种情况，唯一的办法就是测量性能。

# 在需要的地方测量和改进性能

你的代码可以按照你的准则工作和结构化，并且为变更进行了优化。现在是时候写下一些关于优化它的假设，然后进行测试了。

由于你对性能有明确的度量标准，验证它们相对容易。当然，这需要正确的基础设施和适当的测量过程。有了这些，你就可以测量你在性能指标上的表现。

在这里应该欢迎额外的假设。比如- *如果我们像这样重构这段代码，我期望指标 X 会有所改善*。然后你可以继续测试你的假设-开始一个分支，改变代码，构建产品，经过性能指标测量过程，看看结果。当然，实际情况可能比我说的更复杂-有时可能需要使用不同的编译器进行构建，使用不同的优化选项，或者统计数据。如果你想做出明智的决定，这些都是必要的。投入一些时间来进行度量，而不是改变代码并使其更难理解会更好。否则，你最终会得到一笔技术债务，你将长期支付利息。

然而，如果你必须进行点优化，没有变通的办法。只需确保尽可能详细地记录它们。因为你之前已经测试过你的假设，你会有很多东西要写，对吧？

# 监控和改进

我们通过定义性能指标来开始循环。现在是时候结束了，我们需要监控这些指标（可能还有其他指标），并根据我们所学到的知识调整我们的间隔和编码准则。性能优化是一个持续的过程，因为目标设备也在不断发展。

我们已经看过了交付性能的流程，但这与函数式编程有什么关系呢？哪些用例使函数式代码结构发光，哪些又效果不佳？现在是时候深入研究我们的代码结构了。

# 并行性-利用不可变性

编写并行运行的代码一直是软件开发中的一大痛点。多线程、多进程或多服务器环境带来的问题似乎根本难以解决。死锁、饥饿、数据竞争、锁或调试多线程代码等术语让我们这些见过它们的人害怕再次遇到它们。然而，由于多核 CPU、GPU 和多个服务器，我们不得不面对并行代码。函数式编程能帮助解决这个问题吗？

每个人都同意这是函数式编程的一个强项，特别是源自不可变性。如果你的数据从不改变，就不会有锁，同步也会变得非常简单并且可以泛化。如果你只使用纯函数和函数转换（当然除了 I/O），你几乎可以免费获得并行化。

事实上，C++ 17 标准包括 STL 高级函数的执行策略，允许我们通过一个参数将算法从顺序改为并行。让我们来检查向量中是否所有数字都大于`5`的并行执行。我们只需要将`execution::par`作为`all_of`的执行策略即可：

```cpp
auto aVector = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
auto all_of_parallel = [&aVector](){
    return all_of(execution::par, aVector.begin(), aVector.end(),  
        [](auto value){return value > 5;});
};
```

然后，我们可以使用`chrono`命名空间的高分辨率计时器来衡量使用顺序和并行版本算法的差异，就像这样：

```cpp
auto measureExecutionTimeForF = [](auto f){
    auto t1 = high_resolution_clock::now();
    f();
    auto t2 = high_resolution_clock::now();
    chrono::nanoseconds duration = t2 - t1;
    return duration;
};
```

通常情况下，我现在会展示基于我的实验的执行差异。不幸的是，在这种情况下，我不能这样做。在撰写本文时，唯一实现执行策略的编译器是 MSVC 和英特尔 C++，但它们都不符合标准。然而，如下代码段所示，我在`parallelExecution.cpp`源文件中编写了代码，当你的编译器支持标准时，你可以通过取消注释一行来启用它：

```cpp
// At the time when I created this file, only MSVC had implementation  
    for execution policies.
// Since you're seeing this in the future, you can enable the parallel 
    execution code by uncommenting the following line 
//#define PARALLEL_ENABLED
```

当你运行这段代码时，它将显示顺序和并行运行`all_of`的比较持续时间，就像这样：

```cpp
TEST_CASE("all_of with sequential execution policy"){
    auto aVector = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    auto all_of_sequential = [&aVector](){
        return all_of(execution::seq, aVector.begin(), aVector.end(), 
            [](auto value){return value > 5;});
    };

    auto sequentialDuration = 
        measureExecutionTimeForF(all_of_sequential);
        cout << "Execution time for sequential policy:" << 
            sequentialDuration.count() << " ns" << endl;

    auto all_of_parallel = [&aVector](){
        return all_of(execution::par, aVector.begin(), aVector.end(), 
            [](auto value){return value > 5;});
    };

    auto parallelDuration = measureExecutionTimeForF(all_of_parallel);
    cout << "Execution time for parallel policy:" <<   
        parallelDuration.count() << " ns" << endl;
}
```

虽然我很想在这里分析一些执行数据，但也许最好的是我不能，因为这一章最重要的信息是要衡量、衡量、衡量，然后再优化。希望在合适的时候你也能进行一些衡量。

C++ 17 标准支持许多 STL 函数的执行策略，包括`sort`、`find`、`copy`、`transform`和`reduce`。也就是说，如果你在这些函数上进行链式调用并使用纯函数，你只需要为所有调用传递一个额外的参数（或者将高级函数绑定），就可以实现并行执行！我敢说，对于那些尝试自己管理线程或调试奇怪同步问题的人来说，这几乎就像魔法一样。事实上，在前几章中我们为井字棋和扑克牌手写的所有代码都可以很容易地切换到并行执行，只要编译器支持完整的 C++ 17 标准。

但是这是如何工作的？对于`all_of`来说，运行在多个线程中是相当容易的；每个线程在集合中的特定元素上执行谓词，返回一个布尔值，并且当第一个谓词返回`False`时，进程停止。只有当谓词是纯函数时才可能发生这种情况；以任何方式修改结果或向量都会创建竞争条件。文档明确指出程序员有责任保持谓词函数的纯净性——不会有警告或编译错误。除了是纯函数外，你的谓词不能假设元素被处理的顺序。

如果并行执行策略无法启动（例如，由于资源不足），执行将回退到顺序调用。在测量性能时，这是一个需要记住的有用事情：如果性能远低于预期，请首先检查程序是否可以并行执行。

这个选项对于使用多个 CPU 的计算密集型应用程序非常有用。如果你对它的内存消耗感兴趣，你需要测量一下，因为它取决于你使用的编译器和标准库。

# 记忆化

纯函数具有一个有趣的特性。对于相同的输入值，它们返回相同的输出。这使它们等同于一个大表格的值，其中每个输入参数的组合都对应一个输出值。有时，记住这个表格的部分比进行计算更快。这种技术称为**记忆化**。

纯函数式编程语言以及诸如 Python 和 Groovy 之类的语言，都有办法在特定函数调用上启用记忆化，从而提供了高度的控制。不幸的是，C++没有这个功能，所以我们必须自己编写它。

# 实现记忆化

要开始我们的实现，我们需要一个函数；最好是计算昂贵的。让我们选择`power`函数。一个简单的实现只是标准`pow`函数的包装器，如下面的代码片段所示：

```cpp
function<long long(int, int)> power = [](auto base, auto exponent){
    return pow(base, exponent);
};
```

我们如何开始实现记忆化？嗯，在其核心，记忆化就是缓存。每当一个函数第一次被调用时，它会正常运行，但同时也将结果与输入值组合存储起来。在后续的调用中，函数将搜索映射以查看值是否被缓存，并在有缓存时返回它。

这意味着我们需要一个缓存，其键是参数，值是计算结果。为了将参数组合在一起，我们可以简单地使用一对或元组：

```cpp
tuple<int, int> parameters
```

因此，缓存将是：

```cpp
    map<tuple<int, int>, long long> cache;
```

让我们改变我们的`power`函数以使用这个缓存。首先，我们需要在缓存中查找结果：

```cpp
    function<long long(int, int)> memoizedPower = &cache{
            tuple<int, int> parameters(base, exponent);
            auto valueIterator = cache.find(parameters);

```

如果没有找到任何东西，我们计算结果并将其存储在缓存中。如果找到了某些东西，那就是我们要返回的值：

```cpp
        if(valueIterator == cache.end()){
            result = pow(base, exponent);
            cache[parameters] = result;
        } else{
            result = valueIterator -> second;
        }
        return result; 
```

为了检查这种方法是否正常工作，让我们运行一些测试：

```cpp
    CHECK_EQ(power(1, 1), memoizedPower(1, 1));
    CHECK_EQ(power(3, 19), memoizedPower(3, 19));
    CHECK_EQ(power(2, 25), memoizedPower(2, 25));
```

一切都很顺利。现在让我们比较 power 的两个版本，在下面的代码片段中有和没有记忆化。下面的代码显示了我们如何提取一种更通用的方法来记忆化函数：

```cpp
    function<long long(int, int)> power = [](int base, int exponent){
        return pow(base, exponent);
    };

    map<tuple<int, int>, long long> cache;

    function<long long(int, int)> memoizedPower = &cache{
            tuple<int, int> parameters(base, exponent);
            auto valueIterator = cache.find(parameters);
            long long result;
            if(valueIterator == cache.end()){
 result = pow(base, exponent);
            cache[parameters] = result;
        } else{
            result = valueIterator -> second;
        }
        return result; 
    };
```

第一个观察是我们可以用原始 power 函数的调用替换粗体行，所以让我们这样做：

```cpp
    function<long long(int, int)> memoizedPower = &cache, &power{
            tuple<int, int> parameters(base, exponent);
            auto valueIterator = cache.find(parameters);
            long long result;
            if(valueIterator == cache.end()){
 result = power(base, exponent);
            cache[parameters] = result;
        } else{
            result = valueIterator -> second;
        }
        return result; 
    };
```

如果我们传入我们需要在记忆化期间调用的函数，我们将得到一个更通用的解决方案：

```cpp
    auto memoize = &cache{
            tuple<int, int> parameters(base, exponent);
            auto valueIterator = cache.find(parameters);
            long long result;
            if(valueIterator == cache.end()){
            result = functionToMemoize(base, exponent);
            cache[parameters] = result;
        } else{
            result = valueIterator -> second;
        }
        return result; 
    };

    CHECK_EQ(power(1, 1), memoize(1, 1, power));
    CHECK_EQ(power(3, 19), memoize(3, 19, power));
    CHECK_EQ(power(2, 25), memoize(2, 25, power));
```

但是返回一个记忆化的函数不是很好吗？我们可以修改我们的`memoize`函数，使其接收一个函数并返回一个记忆化的函数，该函数接收与初始函数相同的参数：

```cpp
    auto memoize = [](auto functionToMemoize){
        map<tuple<int, int>, long long> cache;
 return & {
            tuple<int, int> parameters(base, exponent);
            auto valueIterator = cache.find(parameters);
            long long result;
            if(valueIterator == cache.end()){
                result = functionToMemoize(base, exponent);
                cache[parameters] = result;
            } else{
                result = valueIterator -> second;
            }
            return result; 
            };
    };
    auto memoizedPower = memoize(power);
```

这个改变最初不起作用——我得到了一个分段错误。原因是我们在 lambda 内部改变了缓存。为了使它工作，我们需要使 lambda 可变，并按值捕获：

```cpp
    auto memoize = [](auto functionToMemoize){
        map<tuple<int, int>, long long> cache;
 return = mutable {
            tuple<int, int> parameters(base, exponent);
            auto valueIterator = cache.find(parameters);
            long long result;
            if(valueIterator == cache.end()){
                result = functionToMemoize(base, exponent);
                cache[parameters] = result;
            } else{
                result = valueIterator -> second;
            }
            return result; 
            };
    };
```

现在我们有一个可以对任何带有两个整数参数的函数进行记忆化的函数。通过使用一些类型参数，很容易使它更通用。我们需要一个返回值的类型，第一个参数的类型和第二个参数的类型：

```cpp
template<typename ReturnType, typename FirstArgType, typename 
    SecondArgType>
auto memoizeTwoParams = [](function<ReturnType(FirstArgType, SecondArgType)> functionToMemoize){
    map<tuple<FirstArgType, SecondArgType>, ReturnType> cache;
    return = mutable {
        tuple<FirstArgType, SecondArgType> parameters(firstArg, 
    secondArg);
        auto valueIterator = cache.find(parameters);
        ReturnType result;
        if(valueIterator == cache.end()){
            result = functionToMemoize(firstArg, secondArg);
            cache[parameters] = result;
        } else{
            result = valueIterator -> second;
        }
        return result; 
    };
};
```

我们已经实现了一个对具有两个参数的任何函数进行记忆化的函数。我们可以做得更好。C++允许我们使用具有未指定数量类型参数的模板，即所谓的**可变参数模板**。通过使用它们的魔力，我们最终得到了一个可以处理任何数量参数的函数的记忆化实现：

```cpp
template<typename ReturnType, typename... Args>
function<ReturnType(Args...)> memoize(function<ReturnType(Args...)> f){
    map<tuple<Args...>, ReturnType> cache;
    return (= mutable  {
            tuple<Args...> theArguments(args...);
            auto cached = cache.find(theArguments);
            if(cached != cache.end()) return cached -> second;
            auto result = f(args...);
            cache[theArguments] = result;
            return result;
    });
};
```

这个函数对缓存任何其他函数都有帮助；然而，有一个问题。到目前为止，我们使用了`power`的包装实现。以下是一个示例，如果我们自己编写它会是什么样子：

```cpp
function<long long(int, int)> power = & 
{
    return (exponent == 0) ? 1 : base * power(base, exponent - 1);
};
```

对这个函数进行记忆化只会缓存最终结果。然而，这个函数是递归的，我们的`memoize`函数调用不会记忆递归的中间结果。为了做到这一点，我们需要告诉我们的记忆化幂函数不要调用`power`函数，而是调用记忆化的`power`函数。

不幸的是，没有简单的方法可以做到这一点。我们可以将递归调用的函数作为参数传递，但这会因为实现原因改变原始函数的签名。或者我们可以重写函数以利用记忆化。

最终，我们得到了一个相当不错的解决方案。让我们来测试一下。

# 使用记忆化

让我们使用我们的`measureExecutionTimeForF`函数来测量调用我们的`power`函数所需的时间。现在也是时候考虑我们期望的结果了。我们确实缓存了重复调用的值，但这需要在每次调用函数时进行自己的处理和内存。所以，也许它会有所帮助，也许不会。在尝试之前，我们不会知道。

```cpp
TEST_CASE("Pow vs memoized pow"){
    function<int(int, int)> power = [](auto first, auto second){
        return pow(first, second);
    };

    cout << "Computing pow" << endl;
    printDuration("First call no memoization: ",  [&](){ return 
        power(5, 24);});
    printDuration("Second call no memoization: ", [&](){return power(3, 
        1024);});
    printDuration("Third call no memoization: ", [&](){return power(9, 
        176);});
    printDuration("Fourth call no memoization (same as first call): ", 
        [&](){return power(5, 24);});

    auto powerWithMemoization = memoize(power);
    printDuration("First call with memoization: ",  [&](){ return 
        powerWithMemoization(5, 24);});
    printDuration("Second call with memoization: ", [&](){return 
        powerWithMemoization(3, 1024);});
    printDuration("Third call with memoization: ", [&](){return 
        powerWithMemoization(9, 176);});
    printDuration("Fourth call with memoization (same as first call): 
        ", [&](){return powerWithMemoization(5, 24);});
    cout << "DONE computing pow" << endl;

    CHECK_EQ(power(5, 24),  powerWithMemoization(5, 24));
    CHECK_EQ(power(3, 1024),  powerWithMemoization(3, 1024));
    CHECK_EQ(power(9, 176),  powerWithMemoization(9, 176));
}
```

这段代码使用相同的值调用`power`函数，最后一次调用返回到第一次调用的值。然后继续做同样的事情，但在创建`power`的记忆化版本之后。最后，一个健全性检查——`power`函数的结果和记忆化的`power`函数的结果进行比较，以确保我们的`memoize`函数没有错误。

问题是——记忆化是否改善了执行系列中最后一个调用所需的时间（与系列中第一个调用完全相同）？在我的配置中，结果是混合的，如下面的片段所示：

```cpp
Computing pow
First call no memoization: 26421 ns
Second call no memoization: 5207 ns
Third call no memoization: 2058 ns
Fourth call no memoization (same as first call): 179 ns
First call with memoization: 2380 ns
Second call with memoization: 2207 ns
Third call with memoization: 1539 ns
Fourth call with memoization (same as first call): 936 ns
DONE computing pow

```

或者，为了更好地查看（首先是没有记忆化的调用），有以下内容：

```cpp
First call: 26421 ns > 2380 ns
Second call: 5207 ns > 2207 ns
Third call: 2058 ns > 1539 ns
Fourth call: 179 ns < 936 ns
```

总的来说，使用记忆化的调用更好，除非我们重复第一个调用。当然，重复运行测试时结果会有所不同，但这表明提高性能并不像只是使用缓存那么简单。背后发生了什么？我认为最有可能的解释是另一个缓存机制启动了——CPU 或其他机制。

无论如何，这证明了测量的重要性。不出乎意料的是，CPU 和编译器已经做了相当多的优化，我们在代码中能做的也有限。

如果我们尝试递归记忆化呢？我重写了`power`函数以递归使用记忆化，并将缓存与递归调用混合在一起。以下是代码：

```cpp
    map<tuple<int, int>, long long> cache;
    function<long long(int, int)> powerWithMemoization = & -> long long{
            if(exponent == 0) return 1;
            long long value;

            tuple<int, int> parameters(base, exponent);
            auto valueIterator = cache.find(parameters);
            if(valueIterator == cache.end()){
            value = base * powerWithMemoization(base, exponent - 1);
            cache[parameters] = value;
            } else {
            value = valueIterator->second;
        };
        return value;
    };
```

当我们运行它时，结果如下：

```cpp
Computing pow
First call no memoization: 1761 ns
Second call no memoization: 106994 ns
Third call no memoization: 8718 ns
Fourth call no memoization (same as first call): 1395 ns
First call with recursive memoization: 30921 ns
Second call with recursive memoization: 2427337 ns
Third call with recursive memoization: 482062 ns
Fourth call with recursive memoization (same as first call): 1721 ns
DONE computing pow
```

另外，以压缩视图（首先是没有记忆化的调用），有以下内容：

```cpp
First call: 1761 ns < 30921 ns
Second call: 106994 ns < 2427337 ns
Third call: 8718 ns < 482062 ns
Fourth call: 1395 ns < 1721 ns
```

正如你所看到的，构建缓存的时间是巨大的。然而，对于重复调用来说是值得的，但在这种情况下仍然无法击败 CPU 和编译器的优化。

那么，备忘录有帮助吗？当我们使用更复杂的函数时，它确实有帮助。接下来让我们尝试计算两个数字的阶乘之间的差异。我们将使用阶乘的一个简单实现，并首先尝试对阶乘函数进行备忘录，然后再对计算差异的函数进行备忘录。为了保持一致，我们将使用与之前相同的数字对。让我们看一下以下代码：

```cpp
TEST_CASE("Factorial difference vs memoized"){
    function<int(int)> fact = &fact{
        if(n == 0) return 1;
        return n * fact(n-1);
    };

    function<int(int, int)> factorialDifference = &fact{
            return fact(second) - fact(first);
    };
    cout << "Computing factorial difference" << endl;
    printDuration("First call no memoization: ",  [&](){ return 
        factorialDifference(5, 24);});
    printDuration("Second call no memoization: ", [&](){return 
        factorialDifference(3, 1024);});
    printDuration("Third call no memoization: ", [&](){return 
        factorialDifference(9, 176);});
    printDuration("Fourth call no memoization (same as first call): ", 
        [&](){return factorialDifference(5, 24);});

    auto factWithMemoization = memoize(fact);
    function<int(int, int)> factorialMemoizedDifference = 
        &factWithMemoization{
        return factWithMemoization(second) - 
            factWithMemoization(first);
    };
    printDuration("First call with memoized factorial: ",  [&](){ 
        return factorialMemoizedDifference(5, 24);});
    printDuration("Second call with memoized factorial: ", [&](){return 
        factorialMemoizedDifference(3, 1024);});
    printDuration("Third call with memoized factorial: ", [&](){return 
        factorialMemoizedDifference(9, 176);});
    printDuration("Fourth call with memoized factorial (same as first 
        call): ", [&](){return factorialMemoizedDifference(5, 24);});

    auto factorialDifferenceWithMemoization = 
        memoize(factorialDifference);
    printDuration("First call with memoization: ",  [&](){ return 
        factorialDifferenceWithMemoization(5, 24);});
    printDuration("Second call with memoization: ", [&](){return 
        factorialDifferenceWithMemoization(3, 1024);});
    printDuration("Third call with memoization: ", [&](){return 
        factorialDifferenceWithMemoization(9, 176);});
    printDuration("Fourth call with memoization (same as first call): 
        ", [&](){return factorialDifferenceWithMemoization(5, 24);});

    cout << "DONE computing factorial difference" << endl;

    CHECK_EQ(factorialDifference(5, 24),  
        factorialMemoizedDifference(5, 24));
    CHECK_EQ(factorialDifference(3, 1024),  
        factorialMemoizedDifference(3, 1024));
    CHECK_EQ(factorialDifference(9, 176),        
        factorialMemoizedDifference(9, 176));

    CHECK_EQ(factorialDifference(5, 24),  
        factorialDifferenceWithMemoization(5, 24));
    CHECK_EQ(factorialDifference(3, 1024),  
        factorialDifferenceWithMemoization(3, 1024));
    CHECK_EQ(factorialDifference(9, 176),  
        factorialDifferenceWithMemoization(9, 176));
}
```

结果是什么？让我们先看一下普通函数和使用备忘录阶乘函数之间的差异：

```cpp
Computing factorial difference
First call no memoization: 1727 ns
Second call no memoization: 79908 ns
Third call no memoization: 8037 ns
Fourth call no memoization (same as first call): 1539 ns
First call with memoized factorial: 4672 ns
Second call with memoized factorial: 41183 ns
Third call with memoized factrorial: 10029 ns
Fourth call with memoized factorial (same as first call): 1105 ns
```

让我们再次并排比较它们：

```cpp
First call: 1727 ns < 4672 ns
Second call: 79908 ns > 41183 ns
Third call: 8037 ns < 10029 ns
Fourth call: 1539 ns > 1105 ns
```

尽管其他调用的结果是混合的，但在命中缓存值时，备忘录函数比非备忘录函数有约 20%的改进。这似乎是一个小的改进，因为阶乘是递归的，所以理论上，备忘录应该会有很大的帮助。然而，*我们没有对递归进行备忘录*。相反，阶乘函数仍然递归调用非备忘录版本。我们稍后会回到这个问题；现在，让我们来看一下在备忘录`factorialDifference`函数时会发生什么：

```cpp
First call no memoization: 1727 ns
Second call no memoization: 79908 ns
Third call no memoization: 8037 ns
Fourth call no memoization (same as first call): 1539 ns
First call with memoization: 2363 ns
Second call with memoization: 39700 ns
Third call with memoization: 8678 ns
Fourth call with memoization (same as first call): 704 ns
```

让我们并排看一下结果：

```cpp
First call: 1727 ns < 2363 ns
Second call: 79908 ns > 39700 ns
Third call: 8037 ns < 8678 ns
Fourth call: 1539 ns > 704 ns
```

备忘录版本比非备忘录版本在缓存值上快两倍！这太大了！然而，当我们没有缓存值时，我们会因此而付出性能损失。而且，在第二次调用时出现了一些奇怪的情况；某种缓存可能会干扰我们的结果。

我们能通过优化阶乘函数的所有递归来使其更好吗？让我们看看。我们需要改变我们的阶乘函数，使得缓存适用于每次调用。为了做到这一点，我们需要递归调用备忘录阶乘函数，而不是普通的阶乘函数，如下所示：

```cpp
    map<int, int> cache;
    function<int(int)> recursiveMemoizedFactorial = 
        &recursiveMemoizedFactorial, &cache mutable{
        auto value = cache.find(n); 
        if(value != cache.end()) return value->second;
        int result;

        if(n == 0) 
            result = 1;
        else 
            result = n * recursiveMemoizedFactorial(n-1);

        cache[n] = result;
        return result;
    };
```

我们使用差异函数，递归地对阶乘的两次调用进行备忘录：

```cpp
    function<int(int, int)> factorialMemoizedDifference =  
        &recursiveMemoizedFactorial{
                return recursiveMemoizedFactorial(second) -  
                    recursiveMemoizedFactorial(first);
    };
```

通过并排运行初始函数和先前函数的相同数据，我得到了以下输出：

```cpp
Computing factorial difference
First call no memoization: 1367 ns
Second call no memoization: 58045 ns
Third call no memoization: 16167 ns
Fourth call no memoization (same as first call): 1334 ns
First call with recursive memoized factorial: 16281 ns
Second call with recursive memoized factorial: 890056 ns
Third call with recursive memoized factorial: 939 ns
Fourth call with recursive memoized factorial (same as first call): 798 ns 
```

我们可以并排看一下：

```cpp
First call: 1,367 ns < 16,281 ns
Second call: 58,045 ns < 890,056 ns Third call: 16,167 ns > 939 ns Fourth call: 1,334 ns > 798 ns
```

正如我们所看到的，缓存正在累积，对于第一个大计算来说惩罚很大；第二次调用涉及 1024！然而，由于缓存命中，随后的调用速度要快得多。

总之，我们可以说，当有足够的内存可用时，备忘录对于加速重复的复杂计算是有用的。它可能需要一些调整，因为缓存大小和缓存命中取决于对函数的调用次数和重复调用次数。因此，不要认为这是理所当然的——要进行测量，测量，测量。

# 尾递归优化

递归算法在函数式编程中非常常见。实际上，我们的命令式循环中的许多循环可以使用纯函数重写为递归算法。

然而，在命令式编程中，递归并不是很受欢迎，因为它有一些问题。首先，开发人员往往对递归算法的练习比起命令式循环要少。其次，可怕的堆栈溢出——递归调用默认情况下会被放到堆栈上，如果迭代次数太多，堆栈就会溢出并出现一个丑陋的错误。

幸运的是，编译器很聪明，可以为我们解决这个问题，同时优化递归函数。进入尾递归优化。

让我们来看一个简单的递归函数。我们将重用前一节中的阶乘，如下所示：

```cpp
    function<int(int)> fact = &fact{
        if(n == 0) return 1;
        return n * fact(n-1);
    };
```

通常，每次调用都会被放在堆栈上，因此每次调用堆栈都会增长。让我们来可视化一下：

```cpp
Stack content fact(1024)
1024 * fact(1023)
1023 * fact(1022)
...
1 * fact(0)
fact(0) = 1 => unwind the stack
```

我们可以通过重写代码来避免堆栈。我们注意到递归调用是在最后进行的；因此，我们可以将函数重写为以下伪代码：

```cpp
    function<int(int)> fact = &fact{
        if(n == 0) return 1;
        return n * (n-1) * (n-1-1) * (n-1-1-1) * ... * fact(0);
    };
```

简而言之，如果我们启用正确的优化标志，编译器可以为我们做的事情。这个调用不仅占用更少的内存，避免了堆栈溢出，而且速度更快。

到现在为止，你应该知道不要相信任何人的说法，包括我的，除非经过测量。所以，让我们验证这个假设。

首先，我们需要一个测试，用于测量对阶乘函数的多次调用的时间。我选择了一些值来进行测试：

```cpp
TEST_CASE("Factorial"){
    function<int(int)> fact = &fact{
        if(n == 0) return 1;
        return n * fact(n-1);
    };

    printDuration("Duration for 0!: ", [&](){return fact(0);});
    printDuration("Duration for 1!: ", [&](){return fact(1);});
    printDuration("Duration for 10!: ", [&](){return fact(10);});
    printDuration("Duration for 100!: ", [&](){return fact(100);});
    printDuration("Duration for 1024!: ", [&](){return fact(1024);});
}
```

然后，我们需要编译此函数，分别禁用和启用优化。**GNU 编译器集合**（**GCC**）优化尾递归的标志是`-foptimize-sibling-calls`；该名称指的是该标志同时优化了兄弟调用和尾调用。我不会详细介绍兄弟调用优化的作用；让我们只说它不会以任何方式影响我们的测试。

运行这两个程序的时间。首先，让我们看一下原始输出：

+   这是没有优化的程序：

```cpp
Duration for 0!: 210 ns
Duration for 1!: 152 ns
Duration for 10!: 463 ns
Duration for 100!: 10946 ns
Duration for 1024!: 82683 ns
```

+   这是带有优化的程序：

```cpp
Duration for 0!: 209 ns
Duration for 1!: 152 ns
Duration for 10!: 464 ns
Duration for 100!: 6455 ns
Duration for 1024!: 75602 ns
```

现在让我们一起看一下结果；没有优化的持续时间在左边：

```cpp
Duration for 0!: 210 ns > 209 ns
Duration for 1!: 152 ns  = 152 ns
Duration for 10!: 463 ns < 464 ns
Duration for 100!: 10946 ns > 6455 ns
Duration for 1024!: 82683 ns > 75602 ns
```

看起来在我的机器上，优化确实对较大的值起作用。这再次证明了在性能要求时度量的重要性。

在接下来的几节中，我们将以各种方式对代码进行实验，并测量结果。

# 完全优化的调用

出于好奇，我决定运行相同的程序，并打开所有安全优化标志。在 GCC 中，这个选项是`-O3`。结果令人震惊，至少可以这么说：

```cpp
Duration for 0!: 128 ns
Duration for 1!: 96 ns
Duration for 10!: 96 ns
Duration for 100!: 405 ns
Duration for 1024!: 17249 ns
```

让我们比较启用所有优化标志的结果（下一段代码中的第二个值）与仅尾递归优化的结果：

```cpp
Duration for 0!: 209 ns > 128 ns
Duration for 1!: 152 ns > 96 ns
Duration for 10!: 464 ns > 96 ns
Duration for 100!: 6455 ns > 405 ns
Duration for 1024!: 75602 ns > 17249 ns
```

差异是巨大的，正如你所看到的。结论是，尽管尾递归优化很有用，但启用编译器的 CPU 缓存命中和所有优化功能会更好。

但是我们使用了`if`语句；当我们使用`?:`运算符时，这会有不同的效果吗？

# if vs ?:

出于好奇，我决定使用`?:`运算符重写代码，而不是`if`语句，如下所示：

```cpp
    function<int(int)> fact = &fact{
        return (n == 0) ? 1 : (n * fact(n-1));
    };
```

我不知道会有什么结果，结果很有趣。让我们看一下原始输出：

+   没有优化标志：

```cpp
Duration for 0!: 633 ns
Duration for 1!: 561 ns
Duration for 10!: 1441 ns
Duration for 100!: 20407 ns
Duration for 1024!: 215600 ns
```

+   打开尾递归标志：

```cpp
Duration for 0!: 277 ns
Duration for 1!: 214 ns
Duration for 10!: 578 ns
Duration for 100!: 9573 ns
Duration for 1024!: 81182 ns
```

让我们比较一下结果；没有优化的持续时间首先出现：

```cpp
Duration for 0!: 633 ns > 277 ns
Duration for 1!: 561 ns > 214 ns
Duration for 10!: 1441 ns > 578 ns
Duration for 100!: 20407 ns > 9573 ns
Duration for 1024!: 75602 ns > 17249 ns
```

两个版本之间的差异非常大，这是我没有预料到的。像往常一样，这很可能是 GCC 编译器的结果，你应该自己测试一下。然而，看起来这个版本对于我的编译器来说更适合尾部优化，这是一个非常有趣的结果。

# 双递归

尾递归对双递归有效吗？我们需要想出一个例子，将递归从一个函数传递到另一个函数，以检查这一点。我决定编写两个函数，`f1`和`f2`，它们互相递归调用。`f1`将当前参数与`f2(n - 1 )`相乘，而`f2`将`f1(n)`添加到`f1(n-1)`。以下是代码：

```cpp
    function<int(int)> f2;
    function<int(int)> f1 = &f2{
        return (n == 0) ? 1 : (n * f2(n-1));
    };

    f2 = &f1{
        return (n == 0) ? 2 : (f1(n) + f1(n-1));
    };
```

让我们检查对`f1`的调用的时间，值从`0`到`8`：

```cpp
    printDuration("Duration for f1(0): ", [&](){return f1(0);});
    printDuration("Duration for f1(1): ", [&](){return f1(1);});
    printDuration("Duration for f1(2): ", [&](){return f1(2);});
    printDuration("Duration for f1(3): ", [&](){return f1(3);});
    printDuration("Duration for f1(4): ", [&](){return f1(4);});
    printDuration("Duration for f1(5): ", [&](){return f1(5);});
    printDuration("Duration for f1(6): ", [&](){return f1(6);});
    printDuration("Duration for f1(7): ", [&](){return f1(7);});
    printDuration("Duration for f1(8): ", [&](){return f1(8);});
```

这是我们得到的结果：

+   没有尾调用优化：

```cpp
Duration for f1(0): 838 ns
Duration for f1(1): 825 ns
Duration for f1(2): 1218 ns
Duration for f1(3): 1515 ns
Duration for f1(4): 2477 ns
Duration for f1(5): 3919 ns
Duration for f1(6): 5809 ns
Duration for f1(7): 9354 ns
Duration for f1(8): 14884 ns
```

+   使用调用优化：

```cpp
Duration for f1(0): 206 ns
Duration for f1(1): 327 ns
Duration for f1(2): 467 ns
Duration for f1(3): 642 ns
Duration for f1(4): 760 ns
Duration for f1(5): 1155 ns
Duration for f1(6): 2023 ns
Duration for f1(7): 3849 ns
Duration for f1(8): 4986 ns
```

让我们一起看一下结果；没有尾优化的调用持续时间在左边：

```cpp
f1(0): 838 ns > 206 ns
f1(1): 825 ns > 327 ns
f1(2): 1218 ns > 467 ns
f1(3): 1515 ns > 642 ns
f1(4): 2477 ns > 760 ns
f1(5): 3919 ns > 1155 ns
f1(6): 5809 ns > 2023 ns
f1(7): 9354 ns > 3849 ns
f1(8): 14884 ns > 4986 ns
```

差异确实非常大，显示代码得到了很大的优化。但是，请记住，对于 GCC，我们使用的是`-foptimize-sibling-calls`优化标志。该标志执行两种优化：尾调用和兄弟调用。兄弟调用是指对返回类型和参数列表总大小相同的函数的调用，因此允许编译器以与尾调用类似的方式处理它们。在我们的情况下，很可能两种优化都被应用了。

# 使用异步代码优化执行时间

当我们有多个线程时，我们可以使用两种近似技术来优化执行时间：并行执行和异步执行。我们已经在前一节中看到了并行执行的工作原理；异步调用呢？

首先，让我们回顾一下异步调用是什么。我们希望进行一次调用，然后在主线程上继续正常进行，并在将来的某个时候获得结果。对我来说，这听起来像是函数的完美工作。我们只需要调用函数，让它们执行，然后在一段时间后再与它们交谈。

既然我们已经谈到了 future，让我们来谈谈 C++中的`future`构造。

# Futures

我们已经确定，在程序中避免管理线程是理想的，除非进行非常专业化的工作，但我们需要并行执行，并且通常需要同步以从另一个线程获取结果。一个典型的例子是一个长时间的计算，它会阻塞主线程，除非我们在自己的线程中运行它。我们如何知道计算何时完成，以及如何获得计算的结果？

在 1976 年至 1977 年，计算机科学中提出了两个概念来简化解决这个问题的方法——futures 和 promises。虽然这些概念在各种技术中经常可以互换使用，在 C++中它们有特定的含义：

+   一个 future 可以从提供者那里检索一个值，同时进行同步处理

+   promise 存储了一个未来的值，并提供了一个同步点

由于它的性质，`future`对象在 C++中有一些限制。它不能被复制，只能被移动，并且只有在与共享状态相关联时才有效。这意味着我们只能通过调用`async`、`promise.get_future()`或`packaged_task.get_future()`来创建一个有效的 future 对象。

值得一提的是，promises 和 futures 在它们的实现中使用了线程库；因此，您可能需要添加对另一个库的依赖。在我的系统（Ubuntu 18.04，64 位）上，使用 g++编译时，我不得不添加一个对`pthread`库的链接依赖；如果您在 mingw 或 cygwin 配置上使用 g++，我希望您也需要相同的依赖。

让我们首先看看如何在 C++中同时使用`future`和`promise`。首先，我们将为一个秘密消息创建一个`promise`：

```cpp
    promise<string> secretMessagePromise;
```

接下来，让我们创建一个`future`并使用它启动一个新的线程。线程将使用一个 lambda 函数简单地打印出秘密消息：

```cpp
    future<string> secretMessageFuture = 
        secretMessagePromise.get_future();
    thread isPrimeThread(printSecretMessage, ref(secretMessageFuture));
```

注意我们需要避免复制`future`；在这种情况下，我们使用一个对`future`的引用包装器。

现在我们暂时只讨论这个线程；下一步是实现承诺，也就是设置一个值：

```cpp
    secretMessagePromise.set_value("It's a secret");
    isPrimeThread.join();
```

与此同时，另一个线程将做一些事情，然后要求我们信守诺言。嗯，不完全是；它将要求`promise`的值，这将阻塞它，直到调用`join()`：

```cpp
auto printSecretMessage = [](future<string>& secretMessageFuture) {
    string secretMessage = secretMessageFuture.get();
    cout << "The secret message: " << secretMessage << '\n';
};
```

正如您可能注意到的，这种方法将计算值的责任放在了主线程上。如果我们希望它在辅助线程上完成呢？我们只需要使用`async`。

假设我们想要检查一个数字是否是质数。我们首先编写一个 lambda 函数，以一种天真的方式检查这一点，对`2`到`x-1`之间的每个可能的除数进行检查，并检查`x`是否可以被它整除。如果它不能被任何值整除，那么它是一个质数：

```cpp
auto is_prime = [](int x) {
    auto xIsDivisibleBy = bind(isDivisibleBy, x, _1);
    return none_of_collection(
            rangeFrom2To(x - 1), 
            xIsDivisibleBy
        );
};
```

使用了一些辅助的 lambda 函数。一个用于生成这样的范围：

```cpp
auto rangeFromTo = [](const int start, const int end){
    vector<int> aVector(end);
    iota(aVector.begin(), aVector.end(), start);
    return aVector;
};
```

这是专门用于生成以`2`开头的范围：

```cpp
auto rangeFrom2To = bind(rangeFromTo, 2, _1);
```

然后，一个检查两个数字是否可被整除的谓词：

```cpp
auto isDivisibleBy = [](auto value, auto factor){
    return value % factor == 0;
};
```

要在主线程之外的一个单独线程中运行这个函数，我们需要使用`async`声明一个`future`：

```cpp
    future<bool> futureIsPrime(async(is_prime, 2597));
```

`async`的第二个参数是我们函数的输入参数。允许多个参数。

然后，我们可以做其他事情，最后，要求结果：

```cpp
TEST_CASE("Future with async"){
    future<bool> futureIsPrime(async(is_prime, 7757));
    cout << "doing stuff ..." << endl;
 bool result = futureIsPrime.get();

    CHECK(result);
}
```

粗体代码行标志着主线程停止等待来自辅助线程的结果的点。

如果您需要多个`future`，您可以使用它们。在下面的示例中，我们将使用四个不同的值在四个不同的线程中运行`is_prime`，如下所示：

```cpp
TEST_CASE("more futures"){
    future<bool> future1(async(is_prime, 2));
    future<bool> future2(async(is_prime, 27));
    future<bool> future3(async(is_prime, 1977));
    future<bool> future4(async(is_prime, 7757));

    CHECK(future1.get());
    CHECK(!future2.get());
    CHECK(!future3.get());
    CHECK(future4.get());
}
```

# 功能性异步代码

我们已经看到，线程的最简单实现是一个 lambda，但我们可以做得更多。最后一个示例使用多个线程异步地在不同的值上运行相同的操作，可以转换为一个功能高阶函数。

但让我们从一些简单的循环开始。首先，我们将输入值和预期结果转换为向量：

```cpp
    vector<int> values{2, 27, 1977, 7757};
    vector<bool> expectedResults{true, false, false, true};
```

然后，我们需要一个`for`循环来创建 futures。重要的是不要调用`future()`构造函数，因为这样做会由于尝试将新构造的`future`对象复制到容器中而失败。相反，将`async()`的结果直接添加到容器中：

```cpp
    vector<future<bool>> futures;
    for(auto value : values){
        futures.push_back(async(is_prime, value));
    }
```

然后，我们需要从线程中获取结果。再次，我们需要避免复制`future`，因此在迭代时将使用引用：

```cpp
    vector<bool> results;
    for(auto& future : futures){
        results.push_back(future.get());
    }
```

让我们来看看整个测试：

```cpp
TEST_CASE("more futures with loops"){
    vector<int> values{2, 27, 1977, 7757};
    vector<bool> expectedResults{true, false, false, true};

    vector<future<bool>> futures;
    for(auto value : values){
        futures.push_back(async(is_prime, value));
    }

    vector<bool> results;
    for(auto& future : futures){
        results.push_back(future.get());
    }

    CHECK_EQ(results, expectedResults);
}
```

很明显，我们可以将这些转换成几个 transform 调用。然而，我们需要特别注意避免复制 futures。首先，我创建了一个帮助创建`future`的 lambda：

```cpp
    auto makeFuture = [](auto value){
        return async(is_prime, value);
    };
```

第一个`for`循环然后变成了一个`transformAll`调用：

```cpp
    vector<future<bool>> futures = transformAll<vector<future<bool>>>
       (values, makeFuture);
```

第二部分比预期的要棘手。我们的`transformAll`的实现不起作用，所以我将内联调用`transform`：

```cpp
    vector<bool> results(values.size());
    transform(futures.begin(), futures.end(), results.begin(), []
        (future<bool>& future){ return future.get();});
```

我们最终得到了以下通过的测试：

```cpp
TEST_CASE("more futures functional"){
    vector<int> values{2, 27, 1977, 7757};

    auto makeFuture = [](auto value){
        return async(is_prime, value);
    };

    vector<future<bool>> futures = transformAll<vector<future<bool>>>
        (values, makeFuture);
    vector<bool> results(values.size());
    transform(futures.begin(), futures.end(), results.begin(), []
        (future<bool>& future){ return future.get();});

    vector<bool> expectedResults{true, false, false, true};

    CHECK_EQ(results, expectedResults);
}
```

我必须对你诚实，这是迄今为止实现起来最困难的代码。在处理 futures 时，有很多事情可能会出错，而且原因并不明显。错误消息相当没有帮助，至少对于我的 g++版本来说是这样。我成功让它工作的唯一方法是一步一步地进行，就像我在本节中向你展示的那样。

然而，这个代码示例展示了一个重要的事实；通过深思熟虑和测试使用 futures，我们可以并行化高阶函数。因此，如果您需要更好的性能，可以使用多个核心，并且不能等待标准中并行运行策略的实现，这是一个可能的解决方案。即使只是为了这一点，我认为我的努力是有用的！

由于我们正在谈论异步调用，我们也可以快速浏览一下响应式编程的世界。

# 响应式编程的一点体验

**响应式编程**是一种编写代码的范式，专注于处理数据流。想象一下需要分析一系列温度值的数据流，来自安装在自动驾驶汽车上的传感器的值，或者特定公司的股票值。在响应式编程中，我们接收这个连续的数据流并运行分析它的函数。由于新数据可能会不可预测地出现在流中，编程模型必须是异步的；也就是说，主线程不断等待新数据，当数据到达时，处理被委托给次要流。结果通常也是异步收集的——要么推送到用户界面，保存在数据存储中，要么传递给其他数据流。

我们已经看到，函数式编程的主要重点是数据。因此，函数式编程是处理实时数据流的良好选择并不足为奇。高阶函数的可组合性，如`map`、`reduce`或`filter`，以及并行处理的机会，使得函数式设计风格成为响应式编程的一个很好的解决方案。

我们不会详细讨论响应式编程。通常使用特定的库或框架来简化这种数据流处理的实现，但是根据我们目前拥有的元素，我们可以编写一个小规模的示例。

我们需要几样东西。首先，一个数据流；其次，一个接收数据并立即将其传递到处理管道的主线程；第三，一种获取输出的方式。

对于本例的目标，我将简单地使用标准输入作为输入流。我们将从键盘输入数字，并以响应式的方式检查它们是否是质数，从而始终保持主线程的响应。这意味着我们将使用`async`函数为我们从键盘读取的每个数字创建一个`future`。输出将简单地写入输出流。

我们将使用与之前相同的`is_prime`函数，但添加另一个函数，它将打印到标准输出该值是否是质数。

```cpp
auto printIsPrime = [](int value){
    cout << value << (is_prime(value) ? " is prime" : " is not prime")  
    << endl;
};
```

`main`函数是一个无限循环，它从输入流中读取数据，并在每次输入新值时启动一个`future`：

```cpp
int main(){
    int number;

    while(true){
        cin >> number;
        async(printIsPrime, number);
    }
}
```

使用一些随机输入值运行此代码会产生以下输出：

```cpp
23423
23423 is not prime
453576
453576 is not prime
53
53 is prime
2537
2537 is not prime
364544366
5347
54
534532
436
364544366 is not prime
5347 is prime
54 is not prime
534532 is not prime
436 is not prime
```

正如你所看到的，结果会尽快返回，但程序允许随时引入新数据。

我必须提到，为了避免每次编译本章的代码时都出现无限循环，响应式示例可以通过`make reactive`编译和运行。你需要用中断来停止它，因为它是一个无限循环。

这是一个基本的响应式编程示例。显然，它可以随着数据量的增加、复杂的流水线和每个流水线的并行化等变得更加复杂。然而，我们已经实现了本节的目标——让你了解响应式编程以及我们如何使用函数构造和异步调用使其工作。

我们已经讨论了如何优化执行时间，看了各种帮助我们实现更快性能的方法。现在是时候看一个情况，我们想要减少程序的内存使用。

# 优化内存使用

到目前为止，我们讨论的用于以函数方式构造代码的方法涉及多次通过被视为不可变的集合。因此，这可能会导致集合的复制。例如，让我们看一个简单的代码示例，它使用`transform`来增加向量的所有元素：

```cpp
template<typename DestinationType>
auto transformAll = [](const auto source, auto lambda){
    DestinationType result;
    transform(source.begin(), source.end(), back_inserter(result), 
        lambda);
    return result;
};

TEST_CASE("Memory"){
    vector<long long> manyNumbers(size);
    fill_n(manyNumbers.begin(), size, 1000L);

    auto result = transformAll<vector<long long>>(manyNumbers, 
        increment);

    CHECK_EQ(result[0], 1001);
}
```

这种实现会导致大量的内存分配。首先，`manyNumbers`向量被复制到`transformAll`中。然后，`result.push_back()`会自动调用，可能导致内存分配。最后，`result`被返回，但初始的`manyNumbers`向量仍然被分配。

我们可以立即改进其中一些问题，但讨论它们与其他可能的优化方法的比较也是值得的。

为了进行测试，我们需要处理大量的集合，并找到一种测量进程内存分配的方法。第一部分很容易——只需分配大量 64 位值（在我的编译器上是长长类型）；足够分配 1GB 的 RAM：

```cpp
const long size_1GB_64Bits = 125000000;
TEST_CASE("Memory"){
    auto size = size_1GB_64Bits;
    vector<long long> manyNumbers(size);
    fill_n(manyNumbers.begin(), size, 1000L);

    auto result = transformAll<vector<long long>>(manyNumbers, 
        increment);

    CHECK_EQ(result[0], 1001);
}
```

第二部分有点困难。幸运的是，在我的 Ubuntu 18.04 系统上，我可以在`/proc/PID/status`文件中监视进程的内存，其中 PID 是进程标识符。通过一些 Bash 魔法，我可以创建一个`makefile`配方，将每 0.1 秒获取的内存值输出到一个文件中，就像这样：

```cpp
memoryConsumptionNoMoveIterator: .outputFolder 
    g++ -DNO_MOVE_ITERATOR -std=c++17 memoryOptimization.cpp -Wall -
        Wextra -Werror -o out/memoryOptimization
    ./runWithMemoryConsumptionMonitoring memoryNoMoveIterator.log
```

你会注意到`-DNO_MOVE_ITERATOR`参数；这是一个编译指令，允许我为不同的目标编译相同的文件，以检查多个解决方案的内存占用。这意味着我们之前的测试是在`#if NO_MOVE_ITERATOR`指令内编写的。

只有一个注意事项——因为我使用了 bash `watch`命令来生成输出，你需要在运行`make memoryConsumptionNoMoveIterator`后按下一个键，以及对每个其他内存日志配方也是如此。

有了这个设置，让我们改进`transformAll`以减少内存使用，并查看输出。我们需要使用引用类型，并从一开始就为结果分配内存，如下所示：

```cpp
template<typename DestinationType>
auto transformAll = [](const auto& source, auto lambda){
    DestinationType result;
    result.resize(source.size());
    transform(source.begin(), source.end(), result.begin(), lambda);
    return result;
};
```

预期的结果是，改进的结果是最大分配从 0.99 GB 开始，但跳到 1.96 GB，大致翻了一番。

我们需要将这个值放在上下文中。让我们先测量一下一个简单的`for`循环能做什么，并将结果与使用`transform`实现的相同算法进行比较。

# 测量简单 for 循环的内存

使用`for`循环的解决方案非常简单：

```cpp
TEST_CASE("Memory"){
    auto size = size_1GB_64Bits;
    vector<long long> manyNumbers(size);
    fill_n(manyNumbers.begin(), size, 1000L);

    for(auto iter = manyNumbers.begin(); iter != manyNumbers.end(); 
        ++iter){
            ++(*iter);
    };

    CHECK_EQ(manyNumbers[0], 1001);
}
```

在测量内存时，没有什么意外——整个过程中占用的内存保持在 0.99 GB。我们能用`transform`也实现这个结果吗？嗯，有一个版本的`transform`可以就地修改集合。让我们来测试一下。

# 测量就地 transform 的内存

要就地使用`transform`，我们需要提供目标迭代器参数`source.begin()`，如下所示：

```cpp
auto increment = [](const auto value){
    return value + 1;
};

auto transformAllInPlace = [](auto& source, auto lambda){
    transform(source.begin(), source.end(), source.begin(), lambda);
};

TEST_CASE("Memory"){
    auto size = size_1GB_64Bits;
    vector<long long> manyNumbers(size);
    fill_n(manyNumbers.begin(), size, 1000L);

    transformAllInPlace(manyNumbers, increment);

    CHECK_EQ(manyNumbers[0], 1001);
}
```

根据文档，这应该在同一集合中进行更改；因此，它不应该分配更多的内存。如预期的那样，它具有与简单的`for`循环相同的行为，内存占用在整个程序运行期间保持在 0.99 GB。

然而，您可能会注意到我们现在不返回值以避免复制。我喜欢返回值，但我们还有另一个选择，使用移动语义：

```cpp
template<typename SourceType>
auto transformAllInPlace = [](auto& source, auto lambda) -> SourceType&& {
    transform(source.begin(), source.end(), source.begin(), lambda);
    return move(source);
};
```

为了使调用编译通过，我们需要在调用`transformAllInPlace`时传递源的类型，因此我们的测试变成了：

```cpp
TEST_CASE("Memory"){
    auto size = size_1GB_64Bits;
    vector<long long> manyNumbers(size);
    fill_n(manyNumbers.begin(), size, 1000L);

    auto result = transformAllInPlace<vector<long long>>(manyNumbers, 
        increment);

    CHECK_EQ(result[0], 1001);
}
```

让我们测量一下移动语义是否有所帮助。结果如预期；内存占用在整个运行时保持在 0.99 GB。

这引出了一个有趣的想法。如果我们在调用`transform`时使用移动语义呢？

# 使用移动迭代器进行 transform

我们可以将我们的`transform`函数重写为使用移动迭代器，如下所示：

```cpp
template<typename DestinationType>
auto transformAllWithMoveIterator = [](auto& source, auto lambda){
    DestinationType result(source.size());
    transform(make_move_iterator(source.begin()), 
        make_move_iterator(source.end()), result.begin(), lambda);
    source.clear();
    return result;
};
```

理论上，这应该是将值移动到目标而不是复制它们，从而保持内存占用低。为了测试一下，我们运行相同的测试并记录内存：

```cpp
TEST_CASE("Memory"){
    auto size = size_1GB_64Bits;
    vector<long long> manyNumbers(size);
    fill_n(manyNumbers.begin(), size, 1000L);

    auto result = transformAllWithMoveIterator<vector<long long>>
        (manyNumbers, increment);

    CHECK_EQ(result[0], 1001);
}
```

结果出乎意料；内存从 0.99 GB 开始上升到 1.96 GB（可能是在`transform`调用之后），然后又回到 0.99 GB（很可能是`source.clear()`的结果）。我尝试了多种变体来避免这种行为，但找不到保持内存占用在 0.99 GB 的解决方案。这似乎是移动迭代器实现的问题；我建议您在您的编译器上测试一下它是否有效。

# 比较解决方案

使用就地或移动语义的解决方案，虽然减少了内存占用，但只有在不需要源数据进行其他计算时才有效。如果您计划重用数据进行其他计算，那么保留初始集合是不可避免的。此外，不清楚这些调用是否可以并行运行；由于 g++尚未实现并行执行策略，我无法测试它们，因此我将把这个问题留给读者作为练习。

但是函数式编程语言为了减少内存占用做了什么呢？答案非常有趣。

# 不可变数据结构

纯函数式编程语言使用不可变数据结构和垃圾回收的组合。修改数据结构的每次调用都会创建一个似乎是初始数据结构的副本，只有一个元素被改变。初始结构不会受到任何影响。然而，这是使用指针来完成的；基本上，新的数据结构与初始数据结构相同，只是有一个指向改变值的指针。当丢弃初始集合时，旧值不再被使用，垃圾收集器会自动将其从内存中删除。

这种机制充分利用了不可变性，允许了 C++无法实现的优化。此外，实现通常是递归的，这也利用了尾递归优化。

然而，可以在 C++中实现这样的数据结构。一个例子是一个名为**immer**的库，你可以在 GitHub 上找到它，网址是[`github.com/arximboldi/immer`](https://github.com/arximboldi/immer)。Immer 实现了许多不可变的集合。我们将看看`immer::vector`；每当我们调用通常会修改向量的操作（比如`push_back`）时，`immer::vector`会返回一个新的集合。每个返回的值都可以是常量，因为它永远不会改变。我在本章的代码中使用 immer 0.5.0 编写了一个小测试，展示了`immer::vector`的用法，你可以在下面的代码中看到：

```cpp
TEST_CASE("Check immutable vector"){
    const auto empty = immer::vector<int>{};
    const auto withOneElement = empty.push_back(42);

    CHECK_EQ(0, empty.size());
    CHECK_EQ(1, withOneElement.size());
    CHECK_EQ(42, withOneElement[0]);
}
```

我不会详细介绍不可变数据结构；但是，我强烈建议你查看*immer*网站上的文档（[`sinusoid.es/immer/introduction.html`](https://sinusoid.es/immer/introduction.html)）并尝试使用该库。

# 总结

我们已经看到，性能优化是一个复杂的话题。作为 C++程序员，我们需要从我们的代码中获得更多的性能；本章中我们提出的问题是：是否可能优化以函数式风格编写的代码？

答案是——是的，如果你进行了测量，并且有一个明确的目标。我们需要特定的计算更快完成吗？我们需要减少内存占用吗？应用程序的哪个领域需要最大程度的性能改进？我们想要进行怪异的点优化吗，这可能需要在下一个编译器、库或平台版本中进行重写？这些都是你在优化代码之前需要回答的问题。

然而，我们已经看到，当涉及到利用计算机上的所有核心时，函数式编程有巨大的好处。虽然我们正在等待高阶函数的标准实现并行执行，但我们可以通过编写自己的并行算法来利用不可变性。递归是函数式编程的另一个基本特征，每当使用它时，我们都可以利用尾递归优化。

至于内存消耗，实现在第三方库中的不可变数据结构，以及根据目标谨慎优化我们使用的高阶函数，都可以帮助我们保持代码的简单性，而复杂性发生在代码的特定位置。当我们丢弃源集合时，可以使用移动语义，但记得检查它是否适用于并行执行。

最重要的是，我希望你已经了解到，测量是性能优化中最重要的部分。毕竟，如果你不知道自己在哪里，也不知道自己需要去哪里，你怎么能进行旅行呢？

我们将继续通过利用数据生成器来进行测试来继续我们的函数式编程之旅。现在是时候看看基于属性的测试了。
