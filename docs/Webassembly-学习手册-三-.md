# Webassembly 学习手册（三）

> 原文：[`annas-archive.org/md5/d5832e9a9d99a1607969f42f55873dd5`](https://annas-archive.org/md5/d5832e9a9d99a1607969f42f55873dd5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用 Emscripten 移植游戏

如 第七章 所示，*从头开始创建应用程序*，WebAssembly 在当前形式下仍然相对有限。Emscripten 提供了强大的 API，用于扩展 WebAssembly 的功能，以添加功能到您的应用程序。在某些情况下，编译为 WebAssembly 模块和 JavaScript 粘合代码（而不是可执行文件）可能只需要对现有的 C 或 C++源代码进行轻微更改。

在本章中，我们将接受一个用 C++编写的代码库，将其编译为传统可执行文件，然后更新代码，以便将其编译为 Wasm/JavaScript。我们还将添加一些额外功能，以更紧密地集成到浏览器中。

通过本章结束时，您将知道如何执行以下操作：

+   更新 C++代码库以编译为 Wasm 模块/JavaScript 粘合代码（而不是本机可执行文件）是很重要的

+   使用 Emscripten 的 API 将浏览器集成到 C++应用程序中

+   使用正确的`emcc`标志构建一个多文件的 C++项目

+   使用`emrun`在浏览器中运行和测试 C++应用程序

# 游戏概述

在本章中，我们将接受一个用 C++编写的俄罗斯方块克隆，并更新代码以集成 Emscripten 并编译为 Wasm/JS。原始形式的代码库利用 SDL2 编译为可执行文件，并可以从命令行加载。在本节中，我们将简要回顾一下俄罗斯方块是什么，如何获取代码（而无需从头开始编写），以及如何运行它。

# 什么是俄罗斯方块？

俄罗斯方块的主要目标是在游戏区域内旋转和移动各种形状的方块（*Tetriminos*），以创建没有间隙的一行方块。当创建了一整行时，它将从游戏区域中删除，并且您的得分将增加一分。在我们的游戏版本中，不会有获胜条件（尽管很容易添加）。

重要的是要了解游戏的规则和机制，因为代码使用算法来实现诸如碰撞检测和记分等概念。了解函数的目标有助于理解其中的代码。如果需要提高俄罗斯方块技能，我建议您在线尝试一下。您可以在[`emulatoronline.com/nes-games/classic-tetris/`](https://emulatoronline.com/nes-games/classic-tetris/)上玩，无需安装 Adobe Flash。它看起来就像原始的任天堂版本：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/60566c17-a951-44f8-a3f4-a1e2bf8c6115.png)

在 EmulatorOnline.com 上玩经典的俄罗斯方块

我们将要处理的版本不包含方块计数器、级别或分数（我们只关注行数），但其操作方式将相同。

# 源的源

事实证明，搜索 Tetris C++会提供大量的教程和示例存储库供选择。为了保持到目前为止使用的格式和命名约定，我将这些资源结合起来创建了自己的游戏版本。本章结束时的*进一步阅读*部分中有这些资源的链接，如果您有兴趣了解更多。无论来源如何，移植代码库的概念和过程都是适用的。在这一点上，让我们简要讨论一下移植的一般情况。

# 关于移植的说明

将现有代码库移植到 Emscripten 并不总是一项简单的任务。在评估 C、C++或 Rust 应用程序是否适合转换时，需要考虑几个变量。例如，使用多个第三方库的游戏，甚至使用几个复杂的第三方库可能需要大量的工作。Emscripten 提供了以下常用库：

+   `asio`：一个网络和低级 I/O 编程库

+   `Bullet`：一个实时碰撞检测和多物理模拟库

+   `Cocos2d`：一套开源的跨平台游戏开发工具

+   `FreeType`：用于呈现字体的库

+   `HarfBuzz`：一个 OpenType 文本整形引擎

+   `libpng`：官方 PNG 参考库

+   `Ogg`：一个多媒体容器格式

+   `SDL2`：设计用于提供对音频、键盘、鼠标、操纵杆和图形硬件的低级访问的库

+   `SDL2_image`：一个图像文件加载库

+   `SDL2_mixer`：一个示例多通道音频混音库

+   `SDL2_net`：一个小型的跨平台网络库

+   `SDL2_ttf`：一个示例库，允许您在 SDL 应用程序中使用 TrueType 字体

+   `Vorbis`：通用音频和音乐编码格式

+   `zlib`：无损数据压缩库

如果库尚未移植，您将需要自行移植。这将有利于社区，但需要大量的时间和资源投入。我们的俄罗斯方块示例只使用了 SDL2，这使得移植过程相对简单。

# 获取代码

本章的代码位于`learn-webassembly`存储库的`/chapter-08-tetris`文件夹中。`/chapter-08-tetris`中有两个目录：`/output-native`文件夹，其中包含原始（未移植）代码，以及`/output-wasm`文件夹，其中包含移植后的代码。

如果您想要使用 VS Code 的任务功能进行本地构建步骤，您需要在 VS Code 中打开`/chapter-08-tetris/output-native`文件夹，而不是顶层的`/learn-webassembly`文件夹。

# 构建本地项目

`/output-native`文件夹中的`/cmake`文件夹和`CMakeLists.txt`文件是构建项目所必需的。`README.md`文件包含了在每个平台上启动代码的说明。构建项目并不是必须要通过移植过程。在您的平台上安装所需的依赖项并成功构建项目的过程可能会耗费大量时间和精力。如果您仍然希望继续，您可以按照`README.md`文件中的说明，在选择任务 | 运行任务... 后从列表中选择构建可执行文件来通过 VS Code 的任务功能构建可执行文件。

# 游戏的运行情况

如果您成功构建了项目，您应该能够通过从 VS Code 菜单中选择**任务** | **运行任务...**并从列表中选择启动可执行任务来运行它。如果一切顺利，您应该会看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/34e1026f-bd47-4209-a611-671d81f98ede.png)

编译后的游戏可以本地运行

我们的游戏版本没有失败条件；它只是每清除一行就将行数增加一。如果俄罗斯方块中的一个方块触及到了板的顶部，游戏就结束了，板重新开始。这是游戏的一个基本实现，但是额外的功能会增加复杂性和所需的代码量。让我们更详细地审查代码库。

# 深入了解代码库

现在您已经可以使用代码了，您需要熟悉代码库。如果您不了解要移植的代码，那么您将更难成功地进行移植。在本章中，我们将逐个讨论每个 C++类和头文件，并描述它们在应用程序中的作用。

# 将代码分解为对象

C++是围绕面向对象的范式设计的，这正是俄罗斯方块代码库用来简化应用程序管理的方式。代码库由 C++类文件组成

（`.cpp`）和头文件（`.h`）代表游戏上下文中的对象。我使用了*什么是俄罗斯方块？*部分的游戏概述来推断我需要哪些对象。

游戏方块（Tetriminos）和游戏区（称为井或矩阵）是类的良好候选对象。也许不那么直观，但同样有效的是*游戏*本身。类不一定需要像实际对象那样具体 —— 它们非常适合存储共享代码。我很喜欢少打字，所以我选择使用`Piece`来表示一个 Tetrimino，`Board`来表示游戏区（尽管*井*这个词更短，但并不太合适）。我创建了一个头文件来存储全局变量（`constants.h`），一个`Game`类来管理游戏过程，以及一个`main.cpp`文件，它作为游戏的入口点。以下是`/src`文件夹的内容：

```cpp
├── board.cpp
├── board.h
├── constants.h
├── game.cpp
├── game.h
├── main.cpp
├── piece.cpp
└── piece.h
```

每个文件（除了`main.cpp`和`constants.h`）都有一个类（`.cpp`）和头文件（`.h`）。头文件允许您在多个文件中重用代码并防止代码重复。*进一步阅读*部分包含了一些资源，供您了解更多关于头文件的知识。`constants.h`文件几乎在应用程序的所有其他文件中都被使用，所以让我们首先来回顾一下它。

# 常量文件

我选择使用一个包含我们将要使用的常量的头文件，而不是在代码库中到处使用令人困惑的*魔术数字*。这个文件的内容如下：

```cpp
#ifndef TETRIS_CONSTANTS_H
#define TETRIS_CONSTANTS_H

namespace Constants {
    const int BoardColumns = 10;
    const int BoardHeight = 720;
    const int BoardRows = 20;
    const int BoardWidth = 360;
    const int Offset = BoardWidth / BoardColumns;
    const int PieceSize = 4;
    const int ScreenHeight = BoardHeight + 50;
}

#endif // TETRIS_CONSTANTS_H
```

文件第一行的`#ifndef`语句是一个`#include`保护，它可以防止在编译过程中多次包含头文件。这些保护在应用程序的所有头文件中都被使用。每个常量的目的将在我们逐个讨论每个类时变得清晰。我首先包含它是为了提供各种元素大小及其相互关系的上下文。

让我们继续看一下代表游戏各个方面的各种类。`Piece`类代表最低级别的对象，所以我们从这里开始，逐步向上到`Board`和`Game`类。

# 方块类

方块，或*Tetrimino*，是可以在棋盘上移动和旋转的元素。有七种不同的 Tetriminos — 每种都用一个字母表示，并有对应的颜色：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/bc6eabd2-b522-4990-9973-6d5432055b3d.png)

Tetrimino 颜色，取自维基百科

我们需要一种方式来定义每个方块的形状、颜色和当前方向。每个方块有四种不同的方向（每次旋转 90 度），这导致了所有方块的 28 种总变化。颜色不会改变，所以只需要分配一次。有了这个想法，让我们首先看一下头文件（`piece.h`）：

```cpp
#ifndef TETRIS_PIECE_H
#define TETRIS_PIECE_H

#include <SDL2/SDL.h>
#include "constants.h"

class Piece {
 public:
  enum Kind { I = 0, J, L, O, S, T, Z };

  explicit Piece(Kind kind);

  void draw(SDL_Renderer *renderer);
  void move(int columnDelta, int rowDelta);
  void rotate();
  bool isBlock(int column, int row) const;
  int getColumn() const;
  int getRow() const;

 private:
  Kind kind_;
  int column_;
  int row_;
  int angle_;
};

#endif // TETRIS_PIECE_H
```

游戏使用 SDL2 来渲染各种图形元素并处理键盘输入，这就是为什么我们将`SDL_Renderer`传递给`draw()`函数。您将看到 SDL2 是如何在`Game`类中使用的，但现在只需知道它被包含在内即可。头文件定义了`Piece`类的接口；让我们来看一下`piece.cpp`中的实现。我们将逐段代码进行讨论并描述功能。

# 构造函数和 draw()函数

代码的第一部分定义了`Piece`类的构造函数和`draw()`函数：

```cpp
#include "piece.h"

using namespace Constants;

Piece::Piece(Piece::Kind kind) :
    kind_(kind),
    column_(BoardColumns / 2 - PieceSize / 2),
    row_(0),
    angle_(0) {
}

void Piece::draw(SDL_Renderer *renderer) {
    switch (kind_) {
        case I:
            SDL_SetRenderDrawColor(renderer,
                /* Cyan: */ 45, 254, 254, 255);
            break;
        case J:
            SDL_SetRenderDrawColor(renderer,
                /* Blue: */ 11, 36, 251, 255);
            break;
        case L:
            SDL_SetRenderDrawColor(renderer,
                /* Orange: */ 253, 164, 41, 255);
            break;
        case O:
            SDL_SetRenderDrawColor(renderer,
                /* Yellow: */ 255, 253, 56, 255);
            break;
       case S:
            SDL_SetRenderDrawColor(renderer,
                /* Green: */ 41, 253, 47, 255);
            break;
        case T:
            SDL_SetRenderDrawColor(renderer,
                /* Purple: */ 126, 15, 126, 255);
            break;
        case Z:
            SDL_SetRenderDrawColor(renderer,
                /* Red: */ 252, 13, 28, 255);
            break;
        }

        for (int column = 0; column < PieceSize; ++column) {
            for (int row = 0; row < PieceSize; ++row) {
                if (isBlock(column, row)) {
                    SDL_Rect rect{
                        (column + column_) * Offset + 1,
                        (row + row_) * Offset + 1,
                        Offset - 2,
                        Offset - 2
                    };
                SDL_RenderFillRect(renderer, &rect);
            }
        }
    }
}
```

构造函数用默认值初始化类。`BoardColumns`和`PieceSize`的值是来自`constants.h`文件的常量。`BoardColumns`表示棋盘上可以放置的列数，在这种情况下是`10`。`PieceSize`常量表示方块在列中占据的区域或块，为`4`。分配给私有`columns_`变量的初始值表示棋盘的中心。

`draw()`函数循环遍历棋盘上所有可能的行和列，并填充任何由棋子占据的单元格与其对应的颜色。判断单元格是否被棋子占据是在`isBlock()`函数中执行的，接下来我们将讨论这个函数。

# move()、rotate()和 isBlock()函数

第二部分包含移动或旋转方块并确定其当前位置的逻辑：

```cpp
void Piece::move(int columnDelta, int rowDelta) {
    column_ += columnDelta;
    row_ += rowDelta;
}

void Piece::rotate() {
    angle_ += 3;
    angle_ %= 4;
}

bool Piece::isBlock(int column, int row) const {
    static const char *Shapes[][4] = {
        // I
        {
            " *  "
            " *  "
            " *  "
            " *  ",
            "    "
            "****"
            "    "
            "    ",
            " *  "
            " *  "
            " *  "
            " *  ",
            "    "
            "****"
            "    "
            "    ",
        },
        // J
        {
            "  * "
            "  * "
            " ** "
            "    ",
            "    "
            "*   "
            "*** "
            "    ",
            " ** "
            " *  "
            " *  "
            "    ",
            "    "
            "    "
            "*** "
            " *  ",
        },
        ...
    };
    return Shapes[kind_][angle_][column + row * PieceSize] == '*';
}

int Piece::getColumn() const {
 return column_;
}
int Piece::getRow() const {
 return row_;
}
```

`move()`函数更新了私有`column_`和`row_`变量的值，从而决定了方块在棋盘上的位置。`rotate()`函数将私有`angle_`变量的值设置为`0`、`1`、`2`或`3`（这就是为什么使用`%= 4`）。

确定显示哪种类型的方块，它的位置和旋转是在`isBlock()`函数中执行的。我省略了`Shapes`多维数组的除了前两个元素之外的所有内容，以避免文件混乱，但是剩下的五种方块类型在实际代码中是存在的。我承认这不是最优雅的实现，但它完全适合我们的目的。

私有的`kind_`和`angle_`值被指定为`Shapes`数组中的维度，以选择四个相应的`char*`元素。这四个元素代表方块的四种可能的方向。如果字符串中的`column + row * PieceSize`索引是一个星号，那么方块就存在于指定的行和列。如果你决定通过网络上的一个俄罗斯方块教程（或者查看 GitHub 上的许多俄罗斯方块存储库之一）来学习，你会发现有几种不同的方法来计算一个单元格是否被方块占据。我选择了这种方法，因为它更容易可视化方块。

# `getColumn()`和`getRow()`函数

代码的最后一部分包含了获取方块的行和列的函数：

```cpp
int Piece::getColumn() const {
    return column_;
}

int Piece::getRow() const {
    return row_;
}
```

这些函数只是简单地返回私有`column_`或`row_`变量的值。现在你对`Piece`类有了更好的理解，让我们继续学习`Board`。

# Board 类

`Board`包含`Piece`类的实例，并且需要检测方块之间的碰撞，行是否已满，以及游戏是否结束。让我们从头文件（`board.h`）的内容开始：

```cpp
#ifndef TETRIS_BOARD_H
#define TETRIS_BOARD_H

#include <SDL2/SDL.h>
#include <SDL2/SDL2_ttf.h>
#include "constants.h"
#include "piece.h"

using namespace Constants;

class Board {
 public:
  Board();
  void draw(SDL_Renderer *renderer, TTF_Font *font);
  bool isCollision(const Piece &piece) const;
  void unite(const Piece &piece);

 private:
  bool isRowFull(int row);
  bool areFullRowsPresent();
  void updateOffsetRow(int fullRow);
  void displayScore(SDL_Renderer *renderer, TTF_Font *font);

  bool cells_[BoardColumns][BoardRows];
  int currentScore_;
};

#endif // TETRIS_BOARD_H
```

`Board`有一个`draw()`函数，类似于`Piece`类，还有一些其他函数用于管理行和跟踪棋盘上哪些单元格被占据。`SDL2_ttf`库用于在窗口底部渲染带有当前分数（清除的行数）的“ROWS:”文本。现在，让我们来看看实现文件（`board.cpp`）的每个部分。

# 构造函数和 draw()函数

代码的第一部分定义了`Board`类的构造函数和`draw()`函数：

```cpp
#include <sstream>
#include "board.h"

using namespace Constants;

Board::Board() : cells_{{ false }}, currentScore_(0) {}

void Board::draw(SDL_Renderer *renderer, TTF_Font *font) {
    displayScore(renderer, font);
    SDL_SetRenderDrawColor(
        renderer,
        /* Light Gray: */ 140, 140, 140, 255);
    for (int column = 0; column < BoardColumns; ++column) {
        for (int row = 0; row < BoardRows; ++row) {
            if (cells_[column][row]) {
                SDL_Rect rect{
                    column * Offset + 1,
                    row * Offset + 1,
                    Offset - 2,
                    Offset - 2
                };
                SDL_RenderFillRect(renderer, &rect);
            }
        }
    }
}
```

`Board`构造函数将私有`cells_`和`currentScore_`变量的值初始化为默认值。`cells_`变量是一个布尔值的二维数组，第一维表示列，第二维表示行。如果一个方块占据特定的列和行，数组中相应的值为`true`。`draw()`函数的行为类似于`Piece`中的`draw()`函数，它用颜色填充包含方块的单元格。然而，这个函数只填充被已经到达底部的方块占据的单元格，颜色为浅灰色，不管是什么类型的方块。

# isCollision()函数

代码的第二部分包含了检测碰撞的逻辑：

```cpp
bool Board::isCollision(const Piece &piece) const {
    for (int column = 0; column < PieceSize; ++column) {
        for (int row = 0; row < PieceSize; ++row) {
            if (piece.isBlock(column, row)) {
                int columnTarget = piece.getColumn() + column;
                int rowTarget = piece.getRow() + row;
                if (
                    columnTarget < 0
                    || columnTarget >= BoardColumns
                    || rowTarget < 0
                    || rowTarget >= BoardRows
                ) {
                    return true;
                }
                if (cells_[columnTarget][rowTarget]) return true;
            }
        }
    }
    return false;
}
```

`isCollision()`函数循环遍历棋盘上的每个单元格，直到找到由作为参数传递的`&piece`占据的单元格。如果方块即将与棋盘的任一侧碰撞，或者已经到达底部，函数返回`true`，否则返回`false`。

# unite()函数

代码的第三部分包含了将方块与顶行合并的逻辑，当方块停止时。

```cpp
void Board::unite(const Piece &piece) {
    for (int column = 0; column < PieceSize; ++column) {
        for (int row = 0; row < PieceSize; ++row) {
            if (piece.isBlock(column, row)) {
                int columnTarget = piece.getColumn() + column;
                int rowTarget = piece.getRow() + row;
                cells_[columnTarget][rowTarget] = true;
            }
        }
    }

    // Continuously loops through each of the rows until no full rows are
    // detected and ensures the full rows are collapsed and non-full rows
    // are shifted accordingly:
    while (areFullRowsPresent()) {
        for (int row = BoardRows - 1; row >= 0; --row) {
            if (isRowFull(row)) {
                updateOffsetRow(row);
                currentScore_ += 1;
                for (int column = 0; column < BoardColumns; ++column) {
                    cells_[column][0] = false;
                }
            }
        }
    }
}

bool Board::isRowFull(int row) {
    for (int column = 0; column < BoardColumns; ++column) {
        if (!cells_[column][row]) return false;
    }
    return true;
}

bool Board::areFullRowsPresent() {
    for (int row = BoardRows - 1; row >= 0; --row) {
        if (isRowFull(row)) return true;
    }
    return false;
}

void Board::updateOffsetRow(int fullRow) {
    for (int column = 0; column < BoardColumns; ++column) {
        for (int rowOffset = fullRow - 1; rowOffset >= 0; --rowOffset) {
            cells_[column][rowOffset + 1] =
            cells_[column][rowOffset];
        }
    }
}
```

`unite()`函数和相应的`isRowFull()`、`areFullRowsPresent()`和`updateOffsetRow()`函数执行多个操作。它通过将适当的数组位置设置为`true`，使用指定的`&piece`参数更新了私有的`cells_`变量，该参数占据了行和列。它还通过将相应的`cells_`数组位置设置为`false`来清除棋盘上的任何完整行（所有列都填满），并增加了`currentScore_`。清除行后，`cells_`数组被更新，将清除的行上面的行向下移动`1`。

# displayScore()函数

代码的最后部分在游戏窗口底部显示分数：

```cpp
void Board::displayScore(SDL_Renderer *renderer, TTF_Font *font) {
    std::stringstream message;
    message << "ROWS: " << currentScore_;
    SDL_Color white = { 255, 255, 255 };
    SDL_Surface *surface = TTF_RenderText_Blended(
        font,
        message.str().c_str(),
        white);
    SDL_Texture *texture = SDL_CreateTextureFromSurface(
        renderer,
        surface);
    SDL_Rect messageRect{ 20, BoardHeight + 15, surface->w, surface->h };
    SDL_FreeSurface(surface);
    SDL_RenderCopy(renderer, texture, nullptr, &messageRect);
    SDL_DestroyTexture(texture);
}
```

`displayScore()`函数使用`SDL2_ttf`库在窗口底部（在棋盘下方）显示当前分数。`TTF_Font *font`参数从`Game`类传递进来，以避免在更新分数时每次初始化字体。`stringstream message`变量用于创建文本值，并将其设置为`TTF_RenderText_Blended()`函数内的 C `char*`。其余代码绘制文本在`SDL_Rect`上，以确保正确显示。

这就是`Board`类的全部内容；让我们继续看看`Game`类是如何组合在一起的。

# 游戏类

`Game`类包含循环函数，使您可以通过按键在棋盘上移动方块。以下是头文件（`game.h`）的内容：

```cpp
#ifndef TETRIS_GAME_H
#define TETRIS_GAME_H

#include <SDL2/SDL.h>
#include <SDL2/SDL2_ttf.h>
#include "constants.h"
#include "board.h"
#include "piece.h"

class Game {
 public:
  Game();
  ~Game();
  bool loop();

 private:
  Game(const Game &);
  Game &operator=(const Game &);

  void checkForCollision(const Piece &newPiece);
  void handleKeyEvents(SDL_Event &event);

  SDL_Window *window_;
  SDL_Renderer *renderer_;
  TTF_Font *font_;
  Board board_;
  Piece piece_;
  uint32_t moveTime_;
};

#endif // TETRIS_GAME_H
```

`loop()`函数包含游戏逻辑，并根据事件管理状态。在`private:`标头下的前两行防止创建多个游戏实例，这可能会导致内存泄漏。私有方法减少了`loop()`函数中的代码行数，简化了维护和调试。让我们继续看`game.cpp`中的实现。

# 构造函数和析构函数

代码的第一部分定义了在加载类实例（构造函数）和卸载类实例（析构函数）时执行的操作：

```cpp
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include "game.h"

using namespace std;
using namespace Constants;

Game::Game() :
    // Create a new random piece:
    piece_{ static_cast<Piece::Kind>(rand() % 7) },
    moveTime_(SDL_GetTicks())
{
    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        throw runtime_error(
            "SDL_Init(SDL_INIT_VIDEO): " + string(SDL_GetError()));
        }
        SDL_CreateWindowAndRenderer(
            BoardWidth,
            ScreenHeight,
            SDL_WINDOW_OPENGL,
            &window_,
            &renderer_);
        SDL_SetWindowPosition(
            window_,
            SDL_WINDOWPOS_CENTERED,
            SDL_WINDOWPOS_CENTERED);
        SDL_SetWindowTitle(window_, "Tetris");

    if (TTF_Init() != 0) {
        throw runtime_error("TTF_Init():" + string(TTF_GetError()));
    }
    font_ = TTF_OpenFont("PressStart2P.ttf", 18);
    if (font_ == nullptr) {
        throw runtime_error("TTF_OpenFont: " + string(TTF_GetError()));
    }
}

Game::~Game() {
    TTF_CloseFont(font_);
    TTF_Quit();
    SDL_DestroyRenderer(renderer_);
    SDL_DestroyWindow(window_);
    SDL_Quit();
}
```

构造函数代表应用程序的入口点，因此所有必需的资源都在其中分配和初始化。`TTF_OpenFont()`函数引用了从 Google Fonts 下载的 TrueType 字体文件，名为 Press Start 2P。您可以在[`fonts.google.com/specimen/Press+Start+2P`](https://fonts.google.com/specimen/Press+Start+2P)上查看该字体。它存在于存储库的`/resources`文件夹中，并在构建项目时复制到可执行文件所在的相同文件夹中。如果在初始化 SDL2 资源时发生错误，将抛出`runtime_error`并提供错误的详细信息。析构函数（`~Game()`）在应用程序退出之前释放我们为 SDL2 和`SDL2_ttf`分配的资源，以避免内存泄漏。

# loop()函数

代码的最后部分代表了`Game::loop`：

```cpp
bool Game::loop() {
    SDL_Event event;
    while (SDL_PollEvent(&event)) {
        switch (event.type) {
            case SDL_KEYDOWN:
                handleKeyEvents(event);
                break;
            case SDL_QUIT:
                return false;
            default:
                return true;
        }
    }

    SDL_SetRenderDrawColor(renderer_, /* Dark Gray: */ 58, 58, 58, 255);
    SDL_RenderClear(renderer_);
    board_.draw(renderer_, font_);
    piece_.draw(renderer_);

    if (SDL_GetTicks() > moveTime_) {
        moveTime_ += 1000;
        Piece newPiece = piece_;
        newPiece.move(0, 1);
        checkForCollision(newPiece);
    }
    SDL_RenderPresent(renderer_);
    return true;
}

void Game::checkForCollision(const Piece &newPiece) {
    if (board_.isCollision(newPiece)) {
        board_.unite(piece_);
        piece_ = Piece{ static_cast<Piece::Kind>(rand() % 7) };
        if (board_.isCollision(piece_)) board_ = Board();
    } else {
        piece_ = newPiece;
    }
}

void Game::handleKeyEvents(SDL_Event &event) {
    Piece newPiece = piece_;
    switch (event.key.keysym.sym) {
        case SDLK_DOWN:
            newPiece.move(0, 1);
            break;
        case SDLK_RIGHT:
            newPiece.move(1, 0);
            break;
        case SDLK_LEFT:
            newPiece.move(-1, 0);
            break;
        case SDLK_UP:
            newPiece.rotate();
            break;
        default:
            break;
     }
     if (!board_.isCollision(newPiece)) piece_ = newPiece;
}
```

`loop()`函数返回一个布尔值，只要`SDL_QUIT`事件尚未触发。每隔`1`秒，执行`Piece`和`Board`实例的`draw()`函数，并相应地更新棋盘上的方块位置。左、右和下箭头键控制方块的移动，而上箭头键将方块旋转 90 度。对按键的适当响应在`handleKeyEvents()`函数中处理。`checkForCollision()`函数确定活动方块的新实例是否与棋盘的任一侧发生碰撞，或者停在其他方块的顶部。如果是，就创建一个新方块。清除行的逻辑（通过`Board`的`unite()`函数）也在这个函数中处理。我们快要完成了！让我们继续看`main.cpp`文件。

# 主文件

`main.cpp`没有关联的头文件，因为它的唯一目的是作为应用程序的入口点。实际上，该文件只有七行：

```cpp
#include "game.h"

int main() {
    Game game;
    while (game.loop());
    return 0;
}
```

`while`语句在`loop()`函数返回`false`时退出，这发生在`SDL_QUIT`事件触发时。这个文件所做的就是创建一个新的`Game`实例并启动循环。这就是代码库的全部内容；让我们开始移植！

# 移植到 Emscripten

你对代码库有很好的理解，现在是时候开始用 Emscripten 移植了。幸运的是，我们能够利用一些浏览器的特性来简化代码，并完全移除第三方库。在这一部分，我们将更新代码以编译为 Wasm 模块和 JavaScript *glue*文件，并更新一些功能以利用浏览器。

# 为移植做准备

`/output-wasm`文件夹包含最终结果，但我建议你创建一个`/output-native`文件夹的副本，这样你就可以跟随移植过程。为本地编译和 Emscripten 编译设置了 VS Code 任务。如果你遇到困难，你可以随时参考`/output-wasm`的内容。确保你在 VS Code 中打开你复制的文件夹（文件 | 打开并选择你复制的文件夹），否则你将无法使用任务功能。

# 有什么改变？

这个游戏是移植的理想候选，因为它使用了 SDL2，这是一个广泛使用的库，已经有了 Emscripten 移植。在编译步骤中包含 SDL2 只需要传递一个额外的参数给`emcc`命令。`SDL2_ttf`库的 Emscripten 移植也存在，但保留它在代码库中并没有太多意义。它的唯一目的是以文本形式呈现得分（清除的行数）。我们需要将 TTF 文件与应用程序一起包含，并复杂化构建过程。Emscripten 提供了在我们的 C++中使用 JavaScript 代码的方法，所以我们将采取一个更简单的方法：在 DOM 中显示得分。

除了改变现有的代码，我们还需要创建一个 HTML 和 CSS 文件来在浏览器中显示和样式化游戏。我们编写的 JavaScript 代码将是最小的——我们只需要加载 Emscripten 模块，所有功能都在 C++代码库中处理。我们还需要添加一些`<div>`元素，并相应地布局以显示得分。让我们开始移植！

# 添加 web 资源

在你的项目文件夹中创建一个名为`/public`的文件夹。在`/public`文件夹中添加一个名为`index.html`的新文件，并填充以下内容：

```cpp
<!doctype html>
<html lang="en-us">
<head>
  <title>Tetris</title>
  <link rel="stylesheet" type="text/css" href="styles.css" />
</head>
<body>
  <div class="wrapper">
    <h1>Tetris</h1>
    <div>
      <canvas id="canvas"></canvas>
      <div class="scoreWrapper">
        <span>ROWS:</span><span id="score"></span>
      </div>
    </div>
  </div>
  <script type="application/javascript" src="img/index.js"></script>
  <script type="application/javascript">
    Module({ canvas: (() => document.getElementById('canvas'))() })
  </script>
</body>
</html>
```

在第一个`<script>`标签中加载的`index.js`文件尚不存在；它将在编译步骤中生成。让我们为元素添加一些样式。在`/public`文件夹中创建一个`styles.css`文件，并填充以下内容：

```cpp
@import url("https://fonts.googleapis.com/css?family=Press+Start+2P");

* {
  font-family: "Press Start 2P", sans-serif;
}

body {
  margin: 24px;
}

h1 {
  font-size: 36px;
}

span {
  color: white;
  font-size: 24px;
}

.wrapper {
  display: flex;
  align-items: center;
  flex-direction: column;
}

.titleWrapper {
  display: flex;
  align-items: center;
  justify-content: center;
}

.header {
  font-size: 24px;
  margin-left: 16px;
}

.scoreWrapper {
  background-color: #3A3A3A;
  border-top: 1px solid white;
  padding: 16px 0;
  width: 360px;
}

span:first-child {
  margin-left: 16px;
  margin-right: 8px;
}
```

由于我们使用的 Press Start 2P 字体托管在 Google Fonts 上，我们可以导入它以在网站上使用。这个文件中的 CSS 规则处理简单的布局和样式。这就是我们需要创建的与 web 相关的文件。现在，是时候更新 C++代码了。

# 移植现有代码

我们只需要编辑一些文件才能正确使用 Emscripten。为了简单和紧凑起见，只包含受影响的代码部分（而不是整个文件）。让我们按照上一节的顺序逐个文件进行，并从`constants.h`开始。

# 更新常量文件

我们将在 DOM 上显示清除的行数，而不是在游戏窗口本身上显示，所以你可以从文件中删除`ScreenHeight`常量。我们不再需要额外的空间来容纳得分文本：

```cpp
namespace Constants {
    const int BoardColumns = 10;
    const int BoardHeight = 720;
    const int BoardRows = 20;
    const int BoardWidth = 360;
    const int Offset = BoardWidth / BoardColumns;
    const int PieceSize = 4;
    // const int ScreenHeight = BoardHeight + 50; <----- Delete this line
}
```

不需要对`Piece`类文件（`piece.cpp`/`piece.h`）进行任何更改。但是，我们需要更新`Board`类。让我们从头文件（`board.h`）开始。从底部开始，逐步更新`displayScore()`函数。在`index.html`文件的`<body>`部分，有一个`id="score"`的`<span>`元素。我们将使用`emscripten_run_script`命令来更新此元素以显示当前分数。因此，`displayScore()`函数变得更短了。变化前后如下所示。

这是 Board 类的`displayScore()`函数的原始版本：

```cpp
void Board::displayScore(SDL_Renderer *renderer, TTF_Font *font) {
    std::stringstream message;
    message << "ROWS: " << currentScore_;
    SDL_Color white = { 255, 255, 255 };
    SDL_Surface *surface = TTF_RenderText_Blended(
        font,
        message.str().c_str(),
        white);
    SDL_Texture *texture = SDL_CreateTextureFromSurface(
        renderer,
        surface);
    SDL_Rect messageRect{ 20, BoardHeight + 15, surface->w, surface->h };
    SDL_FreeSurface(surface);
    SDL_RenderCopy(renderer, texture, nullptr, &messageRect);
    SDL_DestroyTexture(texture);
 }
```

这是`displayScore()`函数的移植版本：

```cpp
void Board::displayScore(int newScore) {
    std::stringstream action;
    action << "document.getElementById('score').innerHTML =" << newScore;
    emscripten_run_script(action.str().c_str());
 }
```

`emscripten_run_script`操作只是在 DOM 上找到`<span>`元素，并将`innerHTML`设置为当前分数。我们无法在这里使用`EM_ASM()`函数，因为 Emscripten 不识别`document`对象。由于我们可以访问类中的私有`currentScore_`变量，我们将把`draw()`函数中的`displayScore()`调用移动到`unite()`函数中。这限制了对`displayScore()`的调用次数，以确保只有在分数实际改变时才调用该函数。我们只需要添加一行代码来实现这一点。现在`unite()`函数的样子如下：

```cpp
void Board::unite(const Piece &piece) {
    for (int column = 0; column < PieceSize; ++column) {
        for (int row = 0; row < PieceSize; ++row) {
            if (piece.isBlock(column, row)) {
                int columnTarget = piece.getColumn() + column;
                int rowTarget = piece.getRow() + row;
                cells_[columnTarget][rowTarget] = true;
            }
        }
    }

    // Continuously loops through each of the rows until no full rows are
    // detected and ensures the full rows are collapsed and non-full rows
    // are shifted accordingly:
    while (areFullRowsPresent()) {
        for (int row = BoardRows - 1; row >= 0; --row) {
            if (isRowFull(row)) {
                updateOffsetRow(row);
                currentScore_ += 1;
                for (int column = 0; column < BoardColumns; ++column) {
                    cells_[column][0] = false;
                }
            }
        }
        displayScore(currentScore_); // <----- Add this line
    }
}
```

由于我们不再使用`SDL2_ttf`库，我们可以更新`draw()`函数的签名并删除`displayScore()`函数调用。更新后的`draw()`函数如下：

```cpp
void Board::draw(SDL_Renderer *renderer/*, TTF_Font *font */) {
                                        // ^^^^^^^^^^^^^^ <-- Remove this argument
    // displayScore(renderer, font); <----- Delete this line
    SDL_SetRenderDrawColor(
        renderer,
        /* Light Gray: */ 140, 140, 140, 255);
    for (int column = 0; column < BoardColumns; ++column) {
        for (int row = 0; row < BoardRows; ++row) {
            if (cells_[column][row]) {
                SDL_Rect rect{
                    column * Offset + 1,
                    row * Offset + 1,
                    Offset - 2,
                    Offset - 2
                };
                SDL_RenderFillRect(renderer, &rect);
            }
        }
    }
 }
```

`displayScore()`函数调用已从函数的第一行中删除，并且`TTF_Font *font`参数也被删除了。让我们在构造函数中添加一个对`displayScore()`的调用，以确保当游戏结束并开始新游戏时，初始值设置为`0`。

```cpp
Board::Board() : cells_{{ false }}, currentScore_(0) {
    displayScore(0); // <----- Add this line
}
```

课堂文件就到这里。由于我们更改了`displayScore()`和`draw()`函数的签名，并移除了对`SDL2_ttf`的依赖，我们需要更新头文件。从`board.h`中删除以下行：

```cpp
#ifndef TETRIS_BOARD_H
#define TETRIS_BOARD_H

#include <SDL2/SDL.h>
// #include <SDL2/SDL2_ttf.h> <----- Delete this line
#include "constants.h"
#include "piece.h"

using namespace Constants;

class Board {
 public:
  Board();
  void draw(SDL_Renderer *renderer /*, TTF_Font *font */);
                                    // ^^^^^^^^^^^^^^ <-- Remove this
  bool isCollision(const Piece &piece) const;
  void unite(const Piece &piece);

 private:
  bool isRowFull(int row);
  bool areFullRowsPresent();
  void updateOffsetRow(int fullRow);
  void displayScore(SDL_Renderer *renderer, TTF_Font *font);
                                         // ^^^^^^^^^^^^^^ <-- Remove this
  bool cells_[BoardColumns][BoardRows];
  int currentScore_;
};

#endif // TETRIS_BOARD_H
```

我们正在顺利进行！我们需要做的最后一个更改也是最大的一个。现有的代码库有一个`Game`类来管理应用程序逻辑，以及一个`main.cpp`文件来在`main()`函数中调用`Game.loop()`函数。循环机制是一个 while 循环，只要`SDL_QUIT`事件没有触发就会继续运行。我们需要改变我们的方法以适应 Emscripten。

Emscripten 提供了一个`emscripten_set_main_loop`函数，接受一个`em_callback_func`循环函数、`fps`和一个`simulate_infinite_loop`标志。我们不能包含`Game`类并将`Game.loop()`作为`em_callback_func`参数，因为构建会失败。相反，我们将完全消除`Game`类，并将逻辑移到`main.cpp`文件中。将`game.cpp`的内容复制到`main.cpp`（覆盖现有内容）并删除`Game`类文件（`game.cpp`/`game.h`）。由于我们不再声明`Game`类，因此从函数中删除`Game::`前缀。构造函数和析构函数不再有效（它们不再是类的一部分），因此我们需要将该逻辑移动到不同的位置。我们还需要重新排列文件以确保我们调用的函数出现在调用函数之前。最终结果如下：

```cpp
#include <emscripten/emscripten.h>
#include <SDL2/SDL.h>
#include <stdexcept>
#include "constants.h"
#include "board.h"
#include "piece.h"

using namespace std;
using namespace Constants;

static SDL_Window *window = nullptr;
static SDL_Renderer *renderer = nullptr;
static Piece currentPiece{ static_cast<Piece::Kind>(rand() % 7) };
static Board board;
static int moveTime;

void checkForCollision(const Piece &newPiece) {
    if (board.isCollision(newPiece)) {
        board.unite(currentPiece);
        currentPiece = Piece{ static_cast<Piece::Kind>(rand() % 7) };
        if (board.isCollision(currentPiece)) board = Board();
    } else {
        currentPiece = newPiece;
    }
}

void handleKeyEvents(SDL_Event &event) {
    Piece newPiece = currentPiece;
    switch (event.key.keysym.sym) {
        case SDLK_DOWN:
            newPiece.move(0, 1);
            break;
        case SDLK_RIGHT:
            newPiece.move(1, 0);
            break;
        case SDLK_LEFT:
            newPiece.move(-1, 0);
            break;
        case SDLK_UP:
            newPiece.rotate();
            break;
        default:
            break;
    }
    if (!board.isCollision(newPiece)) currentPiece = newPiece;
}

void loop() {
    SDL_Event event;
    while (SDL_PollEvent(&event)) {
        switch (event.type) {
            case SDL_KEYDOWN:
                handleKeyEvents(event);
                break;
            case SDL_QUIT:
                break;
            default:
                break;
        }
    }

    SDL_SetRenderDrawColor(renderer, /* Dark Gray: */ 58, 58, 58, 255);
    SDL_RenderClear(renderer);
    board.draw(renderer);
    currentPiece.draw(renderer);

    if (SDL_GetTicks() > moveTime) {
        moveTime += 1000;
        Piece newPiece = currentPiece;
        newPiece.move(0, 1);
        checkForCollision(newPiece);
    }
    SDL_RenderPresent(renderer);
}

int main() {
    moveTime = SDL_GetTicks();
    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        throw std::runtime_error("SDL_Init(SDL_INIT_VIDEO)");
    }
    SDL_CreateWindowAndRenderer(
        BoardWidth,
        BoardHeight,
        SDL_WINDOW_OPENGL,
        &window,
        &renderer);

    emscripten_set_main_loop(loop, 0, 1);

    SDL_DestroyRenderer(renderer);
    renderer = nullptr;
    SDL_DestroyWindow(window);
    window = nullptr;
    SDL_Quit();
    return 0;
}
```

`handleKeyEvents()`和`checkForCollision()`函数没有改变；我们只是将它们移到了文件的顶部。`loop()`函数的返回类型从`bool`改为`void`，这是`emscripten_set_main_loop`所需的。最后，构造函数和析构函数中的代码被移动到了`main()`函数中，并且移除了对`SDL2_ttf`的任何引用。我们不再使用调用`Game`的`loop()`函数的 while 语句，而是使用`emscripten_set_main_loop(loop, 0, 1)`。我们修改了文件顶部的`#include`语句以适应 Emscripten、SDL2 和我们的`Board`和`Piece`类。这就是所有的更改——现在是时候配置构建并测试游戏了。

# 构建和运行游戏

随着代码的更新和所需的 Web 资产的准备，现在是构建和测试游戏的时候了。编译步骤与本书中之前的示例类似，但我们将使用不同的技术来运行游戏。在本节中，我们将配置构建任务以适应 C++文件，并使用 Emscripten 提供的功能来运行应用程序。

# 使用 VS Code 任务进行构建

我们将以两种方式配置构建：使用 VS Code 任务和 Makefile。如果您喜欢使用 VS Code 以外的编辑器，Makefile 是一个不错的选择。`/.vscode/tasks.json`文件已经包含了构建项目所需的任务。Emscripten 构建步骤是默认的（还有一组本地构建任务）。让我们逐个检查`tasks`数组中的每个任务，看看发生了什么。第一个任务在构建之前删除任何现有的编译输出文件：

```cpp
{
  "label": "Remove Existing Web Files",
  "type": "shell",
  "command": "rimraf",
  "options": {
    "cwd": "${workspaceRoot}/public"
  },
  "args": [
    "index.js",
    "index.wasm"
  ]
}
```

第二个任务使用`emcc`命令进行构建：

```cpp
{
  "label": "Build WebAssembly",
  "type": "shell",
  "command": "emcc",
  "args": [
    "--bind", "src/board.cpp", "src/piece.cpp", "src/main.cpp",
    "-std=c++14",
    "-O3",
    "-s", "WASM=1",
    "-s", "USE_SDL=2",
    "-s", "MODULARIZE=1",
    "-o", "public/index.js"
  ],
  "group": {
    "kind": "build",
    "isDefault": true
  },
  "problemMatcher": [],
  "dependsOn": ["Remove Existing Web Files"]
}
```

相关的参数都放在同一行上。`args`数组中唯一的新的和陌生的添加是`--bind`参数和相应的`.cpp`文件。这告诉 Emscripten 所有在`--bind`之后的文件都是构建项目所需的。通过从菜单中选择任务|运行构建任务...或使用键盘快捷键*Cmd*/*Ctrl + Shift + B*来测试构建。构建需要几秒钟，但终端会在编译过程完成时通知您。如果成功，您应该在`/public`文件夹中看到一个`index.js`和一个`index.wasm`文件。

# 使用 Makefile 进行构建

如果您不想使用 VS Code，您可以使用 Makefile 来实现与 VS Code 任务相同的目标。在项目文件夹中创建一个名为`Makefile`的文件，并填充以下内容（确保文件使用制表符而不是空格）：

```cpp
# This allows you to just run the "make" command without specifying
# arguments:
.DEFAULT_GOAL := build

# Specifies which files to compile as part of the project:
CPP_FILES = $(wildcard src/*.cpp)

# Flags to use for Emscripten emcc compile command:
FLAGS = -std=c++14 -O3 -s WASM=1 -s USE_SDL=2 -s MODULARIZE=1 \
        --bind $(CPP_FILES)

# Name of output (the .wasm file is created automatically):
OUTPUT_FILE = public/index.js

# This is the target that compiles our executable
compile: $(CPP_FILES)
    emcc  $(FLAGS) -o $(OUTPUT_FILE)

# Removes the existing index.js and index.wasm files:
clean:
    rimraf $(OUTPUT_FILE)
    rimraf public/index.wasm

# Removes the existing files and builds the project:
build: clean compile
    @echo "Build Complete!"
```

所执行的操作与 VS Code 任务中执行的操作相同，只是使用更通用的工具格式。默认的构建步骤已在文件中设置，因此您可以在项目文件夹中运行以下命令来编译项目：

```cpp
make
```

现在您已经有了一个编译好的 Wasm 文件和 JavaScript 粘合代码，让我们尝试运行游戏。

# 运行游戏

我们将使用 Emscripten 工具链的内置功能`emrun`，而不是使用`serve`或`browser-sync`。它提供了一个额外的好处，即捕获`stdout`和`stderr`（如果您将`--emrun`链接标志传递给`emcc`命令），并在需要时将它们打印到终端。我们不会使用`--emrun`标志，但是在不必安装任何额外的依赖项的情况下拥有一个本地 Web 服务器是一个很好的附加功能。在项目文件夹中打开一个终端实例，并运行以下命令来启动游戏：

```cpp
emrun --browser chrome --no_emrun_detect public/index.html
```

如果您正在开发中使用`firefox`，可以为浏览器指定`firefox`。`--no_emrun_detect`标志会隐藏终端中的一条消息，指出 HTML 页面不支持`emrun`。如果您导航到`http://localhost:6931/index.html`，您应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/700df992-90f3-4452-84da-49e770e1a1c7.png)

在浏览器中运行的俄罗斯方块

尝试旋转和移动方块，以确保一切都正常工作。当成功清除一行时，行数应该增加一。您还可能注意到，如果您离棋盘边缘太近，您将无法旋转一些方块。恭喜，您已成功将一个 C++游戏移植到 Emscripten！

# 总结

在本章中，我们将一个使用 SDL2 编写的 C++ Tetris 克隆移植到 Emscripten，以便可以在浏览器中使用 WebAssembly 运行。我们介绍了 Tetris 的规则以及它们如何映射到现有代码库中的逻辑。我们还逐个审查了现有代码库中的每个文件以及必须进行的更改，以成功编译为 Wasm 文件和 JavaScript 粘合代码。更新现有代码后，我们创建了所需的 HTML 和 CSS 文件，然后使用适当的`emcc`标志配置了构建步骤。构建完成后，使用 Emscripten 的`emrun`命令运行游戏。

在第九章中，*与 Node.js 集成*，我们将讨论如何将 WebAssembly 集成到 Node.js 中，以及这种集成提供的好处。

# 问题

1.  Tetris 中的方块叫什么？

1.  选择不将现有的 C++代码库移植到 Emscripten 的一个原因是什么？

1.  我们用什么工具来将游戏编译成本机代码（例如，可执行文件）？

1.  `constants.h`文件的目的是什么？

1.  为什么我们能够消除 SDL2_ttf 库？

1.  我们使用了哪个 Emscripten 函数来开始运行游戏？

1.  我们在`emcc`命令中添加了哪个参数来构建游戏，它有什么作用？

1.  `emrun`相对于`serve`和 Browsersync 这样的工具有什么优势？

# 进一步阅读

+   C++中的头文件：[`www.sitesbay.com/cpp/cpp-header-files`](https://www.sitesbay.com/cpp/cpp-header-files)

+   GitHub 上的 SDL2 Tetris：[`github.com/andwn/sdl2-tetris`](https://github.com/andwn/sdl2-tetris)

+   GitHub 上的 Tetris：[`github.com/abesary/tetris`](https://github.com/abesary/tetris)

+   Tetris - Linux on GitHub: [`github.com/abesary/tetris-linux`](https://github.com/abesary/tetris-linux)


# 第九章：与 Node.js 集成

现代 Web 在开发和服务器端管理方面严重依赖 Node.js。随着越来越复杂的浏览器应用程序执行计算密集型操作，性能的提升将非常有益。在本章中，我们将描述通过各种示例集成 WebAssembly 与 Node.js 的各种方式。

本章的目标是理解以下内容：

+   将 WebAssembly 与 Node.js 集成的优势

+   如何与 Node.js 的 WebAssembly API 交互

+   如何在使用 Webpack 的项目中利用 Wasm 模块

+   如何使用`npm`库为 WebAssembly 模块编写单元测试

# 为什么选择 Node.js？

在第三章中，描述了 Node.js 作为异步事件驱动的 JavaScript 运行时，这是从官方网站上获取的定义。然而，Node.js 代表的是我们构建和管理 Web 应用程序方式的深刻转变。在本节中，我们将讨论 WebAssembly 和 Node.js 之间的关系，以及为什么这两种技术如此互补。

# 无缝集成

Node.js 在 Google 的 V8 JavaScript 引擎上运行，该引擎驱动着 Google Chrome。由于 V8 的 WebAssembly 实现遵循*核心规范*，因此您可以使用与浏览器相同的 API 与 WebAssembly 模块进行交互。您可以使用 Node.js 的`fs`模块将`.wasm`文件的内容读入缓冲区，然后对结果调用`instantiate()`，而不是执行`.wasm`文件的 fetch 调用。

# 互补技术

JavaScript 在服务器端也存在一些限制。使用 WebAssembly 的卓越性能可以优化昂贵的计算或处理大量数据。作为一种脚本语言，JavaScript 擅长自动化简单的任务。您可以编写一个脚本来将 C/C++编译为 Wasm 文件，将其复制到`build`文件夹中，并在浏览器中查看变化（如果使用类似`Browsersync`的工具）。

# 使用 npm 进行开发

Node.js 拥有一个庞大的工具和库生态系统，以`npm`的形式存在。Sven Sauleau 和其他开源社区成员创建了`webassemblyjs`，这是一个使用 Node.js 构建的 WebAssembly 工具套件。`webassemblyjs`网站[`webassembly.js.org`](https://webassembly.js.org)包括标语*WebAssembly 的工具链*。目前有超过 20 个`npm`包可执行各种任务并辅助开发，例如 ESLint 插件、AST 验证器和格式化程序。AssemblyScript 是一种 TypeScript 到 WebAssembly 的编译器，允许您编写高性能的代码，无需学习 C 或 C++即可编译为 Wasm 模块。Node.js 社区显然对 WebAssembly 的成功充满信心。

# 使用 Express 进行服务器端 WebAssembly

Node.js 可以以多种方式用于增加 WebAssembly 项目的价值。在本节中，我们将通过一个示例 Node.js 应用程序来介绍集成 WebAssembly 的方法。该应用程序使用 Express 和一些简单的路由来调用编译后的 Wasm 模块中的函数。

# 项目概述

该项目重用了我们在第七章中构建的应用程序（*从头开始创建应用程序*）的一些代码，以演示如何将 Node.js 与 WebAssembly 一起使用。本节的代码位于`learn-webassembly`存储库中的`/chapter-09-node/server-example`文件夹中。我们将审查与 Node.js 直接相关的应用程序部分。以下结构代表项目的文件结构：

```cpp
├── /lib
│    └── main.c
├── /src
|    ├── Transaction.js
|    ├── /assets
|    │   ├── db.json
|    │   ├── main.wasm
|    │   └── memory.wasm
|    ├── assign-routes.js
|    ├── index.js
|    └── load-assets.js
├── package.json
├── package-lock.json
└── requests.js
```

关于依赖项，该应用程序使用`express`和`body-parser`库来设置路由并解析来自请求主体的 JSON。对于数据管理，它使用`lowdb`，这是一个提供读取和更新 JSON 文件方法的库。JSON 文件位于`/src/assets/db.json`中，其中包含了从 Cook the Books 数据集中略微修改的数据。我们使用`nodemon`来监视`/src`文件夹中的更改并自动重新加载应用程序。我们使用`rimraf`来管理文件删除。该库作为依赖项包含在事件中，以防您没有在第三章中全局安装它，*设置开发环境*。最后，`node-fetch`库允许我们在测试应用程序时使用 fetch API 进行 HTTP 请求。

为了简化 JavaScript 和 C 文件中的功能，`rawAmount`和`cookedAmount`字段被替换为单个`amount`字段，`category`字段现在是`categoryId`，它映射到`db.json`中的`categories`数组。

# Express 配置

应用程序在`/src/index.js`中加载。该文件的内容如下所示：

```cpp
const express = require('express');
const bodyParser = require('body-parser');
const loadAssets = require('./load-assets');
const assignRoutes = require('./assign-routes');

// If you preface the npm start command with PORT=[Your Port] on
// macOS/Ubuntu or set PORT=[Your Port] on Windows, it will change the port
// that the server is running on, so PORT=3001 will run the app on
// port 3001:
const PORT = process.env.PORT || 3000;

const startApp = async () => {
  const app = express();

  // Use body-parser for parsing JSON in the body of a request:
  app.use(bodyParser.urlencoded({ extended: true }));
  app.use(bodyParser.json());

  // Instantiate the Wasm module and local database:
  const assets = await loadAssets();

  // Setup routes that can interact with Wasm and the database:
  assignRoutes(app, assets);

  // Start the server with the specified port:
  app.listen(PORT, (err) => {
    if (err) return Promise.reject(err);
    return Promise.resolve();
  });
};

startApp()
  .then(() => console.log(`Server is running on port ${PORT}`))
  .catch(err => console.error(`An error occurred: ${err}`));
```

该文件设置了一个新的 Express 应用程序，添加了`body-parser`中间件，加载了模拟数据库和 Wasm 实例，并分配了路由。让我们继续讨论在浏览器和 Node.js 中实例化 Wasm 模块的区别。

# 使用 Node.js 实例化 Wasm 模块

Wasm 文件在`/src/load-assets.js`中实例化。我们使用了来自 Cook the Books 的`memory.wasm`文件，但`/assets/main.wasm`文件是从位于`/lib`文件夹中的稍微不同版本的`main.c`编译而来。`loadWasm()`函数执行的操作与 Cook the Books 中的 Wasm 初始化代码相同，但是将`bufferSource`传递给`WebAssembly.instantiate()`的方法不同。让我们通过查看`load-assets.js`文件中`loadWasm()`函数的部分代码来进一步了解这一点：

```cpp
const fs = require('fs');
const path = require('path');

const assetsPath = path.resolve(__dirname, 'assets');

const getBufferSource = fileName => {
  const filePath = path.resolve(assetsPath, fileName);
  return fs.readFileSync(filePath); // <- Replaces the fetch() and .arrayBuffer()
};

// We're using async/await because it simplifies the Promise syntax
const loadWasm = async () => {
  const wasmMemory = new WebAssembly.Memory({ initial: 1024 });
  const memoryBuffer = getBufferSource('memory.wasm');
  const memoryInstance = await WebAssembly.instantiate(memoryBuffer, {
    env: {
      memory: wasmMemory
    }
  });
  ...
```

为了详细说明区别，以下是使用`fetch`实例化模块的一些代码：

```cpp
fetch('main.wasm')
  .then(response => {
    if (response.ok) return response.arrayBuffer();
    throw new Error('Unable to fetch WebAssembly file');
  })
  .then(bytes => WebAssembly.instantiate(bytes, importObj));
```

在使用 Node.js 时，`fetch`调用被`fs.readFileSync()`函数替换，不再需要`arrayBuffer()`函数，因为`fs.readFileSync()`返回一个可以直接传递给`instantiate()`函数的缓冲区。一旦 Wasm 模块被实例化，我们就可以开始与实例交互。

# 创建模拟数据库

`load-assets.js`文件还包含了创建模拟数据库实例的方法：

```cpp
const loadDb = () => {
  const dbPath = path.resolve(assetsPath, 'db.json');
  const adapter = new FileSync(dbPath);
  return low(adapter);
};
```

`loadDb()`函数将`/assets/db.json`的内容加载到`lowdb`的实例中。从`load-assets.js`中默认导出的函数调用了`loadWasm()`和`loadDb()`函数，并返回一个包含模拟数据库和 Wasm 实例的对象：

```cpp
module.exports = async function loadAssets() {
  const db = loadDb();
  const wasmInstance = await loadWasm();
  return {
    db,
    wasmInstance
  };
};
```

接下来，我将使用术语数据库来指代访问`db.json`文件的`lowdb`实例。现在资产已加载，让我们回顾一下应用程序如何与它们交互。

# 与 WebAssembly 模块交互

与数据库和 Wasm 实例的交互发生在`/src`文件夹中的两个文件中：`Transaction.js`和`assign-routes.js`。在我们的示例应用程序中，所有与 API 的通信都是通过 HTTP 请求完成的。向特定端点发送请求将触发服务器上与数据库/Wasm 实例的一些交互。让我们从直接与数据库和 Wasm 实例交互的`Transaction.js`开始回顾。

# 在 Transaction.js 中包装交互

就像 Cook the Books 一样，有一个类包装了 Wasm 交互代码并提供了一个清晰的接口。`Transaction.js`的内容与 Cook the Books 中的`/src/store/WasmTransactions.js`的内容非常相似。大部分更改是为了适应交易记录中存在`categoryId`和单个`amount`字段（不再有原始和烹饪金额）。还添加了与数据库交互的附加功能。例如，这是一个编辑现有交易的函数，既在数据库中，又在 Wasm 实例的链接列表中：

```cpp
getValidAmount(transaction) {
  const { amount, type } = transaction;
  return type === 'Withdrawal' ? -Math.abs(amount) : amount;
}

edit(transactionId, contents) {
  const updatedTransaction = this.db.get('transactions')
    .find({ id: transactionId })
    .assign(contents)
    .write();

  const { categoryId, ...transaction } = updatedTransaction;
  const amount = this.getValidAmount(transaction);
  this.wasmInstance._editTransaction(transactionId, categoryId, amount);

  return updatedTransaction;
}
```

`edit()`函数使用`contents`参数中的值更新与`transactionId`参数对应的数据库记录。`this.db`是在`load-assets.js`文件中创建的数据库实例。由于`updatedTransaction`记录上可用`categoryId`字段，我们可以直接将其传递给`this.wasmInstance._editTransaction()`。当创建`Transaction`的新实例时，它会被传递到构造函数中。

# 在 assign-routes.js 中的交易操作

`assign-routes.js`文件定义了路由并将它们添加到`index.js`中创建的`express`实例（`app`）中。在 Express 中，路由可以直接在`app`上定义（例如`app.get()`），也可以通过使用`Router`来定义。在这种情况下，使用了`Router`来将多个方法添加到相同的路由路径上。以下代码取自`assign-routes.js`文件，创建了一个`Router`实例并添加了两个路由：一个`GET`路由返回所有交易，一个`POST`路由创建一个新的交易。

```cpp
module.exports = function assignRoutes(app, assets) {
  const { db, wasmInstance } = assets;
  const transaction = new Transaction(db, wasmInstance);
  const transactionsRouter = express.Router();

  transactionsRouter
    .route('/')
    .get((req, res) => {
      const transactions = transaction.findAll();
      res.status(200).send(transactions);
    })
    .post((req, res) => {
      const { body } = req;
      if (!body) {
        return res.status(400).send('Body of request is empty');
      }
      const newRecord = transaction.add(body);
      res.status(200).send(newRecord);
    });

  ...

  // Set the base path for all routes on transactionsRouter:
  app.use('/api/transactions', transactionsRouter);
}
```

片段末尾的`app.use()`函数指定了在`transactionsRouter`实例上定义的所有路由都以`/api/transactions`为前缀。如果您在本地端口`3000`上运行应用程序，可以在浏览器中导航到`http://localhost:3000/api/transactions`，并以 JSON 格式查看所有交易的数组。

从`get()`和`post()`函数的主体中可以看出，与任何交易记录的交互都被委托给了第 3 行创建的`Transaction`实例。这完成了我们对代码库相关部分的审查。每个文件都包含描述文件功能和目的的注释，因此在继续下一部分之前，您可能需要审查这些内容。在下一部分中，我们将构建、运行并与应用程序交互。

# 构建和运行应用程序

在构建和测试项目之前，您需要安装`npm`依赖项。在`/server-example`文件夹中打开终端并运行以下命令：

```cpp
npm install
```

完成后，您可以继续进行构建步骤。

# 构建应用程序

在这个应用程序中，构建是指使用`emcc`命令将`lib/main.c`编译为`.wasm`文件。由于这是一个 Node.js 项目，我们可以使用`package.json`文件中的`scripts`键来定义任务。您仍然可以使用 VS Code 的任务功能，因为它会自动检测`package.json`文件中的脚本，并在选择任务时将它们呈现在任务列表中。以下代码包含了该项目`package.json`文件中`scripts`部分的内容：

```cpp
"scripts": {
  "prebuild": "rimraf src/assets/main.wasm",
  "build": "emcc lib/main.c -Os -s WASM=1 -s SIDE_MODULE=1
           -s BINARYEN_ASYNC_COMPILATION=0 -s ALLOW_MEMORY_GROWTH=1
           -o src/assets/main.wasm",
  "start": "node src/index.js",
  "watch": "nodemon src/* --exec 'npm start'"
},
```

`build`脚本被拆分成多行以便显示，因此您需要将这些行组合成有效的 JSON。`prebuild`脚本会删除现有的 Wasm 文件，而`build`脚本会使用所需的标志运行`emcc`命令，将`lib/main.c`编译并将结果输出到`src/assets/main.wasm`。要运行该脚本，请在`/server-example`文件夹中打开终端并运行以下命令：

```cpp
npm run build
```

如果`/src/assets`文件夹中包含名为`main.wasm`的文件，则构建已成功完成。如果发生错误，终端应提供错误的描述以及堆栈跟踪。

你可以创建`npm`脚本，在特定脚本之前或之后运行，方法是创建一个与相同名称的条目，并在前面加上`pre`或`post`。例如，如果你想在`build`脚本完成后运行一个脚本，你可以创建一个名为`"postbuild"`的脚本，并指定你想要运行的命令。

# 启动和测试应用程序

如果你正在对应用程序进行更改或尝试修复错误，你可以使用`watch`脚本来监视`/src`文件夹中内容的任何更改，并在有更改时自动重新启动应用程序。由于我们只是运行和测试应用程序，所以可以使用`start`命令。在终端中，确保你在`/server-example`文件夹中，并运行以下命令：

```cpp
npm start
```

你应该看到一个消息，上面写着`服务器正在 3000 端口上运行`。现在你可以向服务器发送 HTTP 请求了。要测试应用程序，在`server-example`目录中打开一个新的终端实例，并运行以下命令：

```cpp
node ./requests.js 1
```

这应该记录下对`/api/transactions`端点的`GET`调用的响应主体。`requests.js`文件包含了允许你对所有可用路由进行请求的功能。`getFetchActionForId()`函数返回一个带有端点和选项值的对象，对应于`assign-routes.js`文件中的一个路由。`actionId`是一个任意的数字，用于简化测试并减少运行命令时的输入量。例如，你可以运行以下命令：

```cpp
node ./requests.js 5
```

它将记录下*计算机与互联网*类别的所有交易的总和。如果你想要其他类别的总和，可以向`node`命令传递额外的参数。要获取*保险*类别的所有交易总和，运行以下命令：

```cpp
node ./requests.js 5 3
```

尝试通过每个请求（总共有八个）进行。如果你发出了一个添加、删除或编辑交易的请求，你应该在`/src/assets/db.json`文件中看到变化。这就是 Node.js 示例项目的全部内容。在下一节中，我们将利用 Webpack 来加载和与 Wasm 模块交互。

# 使用 Webpack 进行客户端 WebAssembly

Web 应用程序在复杂性和规模上继续增长。简单地提供一些手写的 HTML、CSS 和 JavaScript 文件对于大型应用程序来说是不可行的。为了管理这种复杂性，Web 开发人员使用捆绑器来实现模块化，确保浏览器兼容性，并减少 JavaScript 文件的大小。在本节中，我们将使用一种流行的捆绑器 Webpack 来利用 Wasm，而不使用`emcc`。

# 项目概述

示例 Webpack 应用程序扩展了我们在第五章的*编译 C 而不使用粘合代码*部分中编写的 C 代码的功能，*创建和加载 WebAssembly 模块*。我们不再展示一个蓝色矩形在红色背景上弹跳，而是展示一个飞船在马头星云中弹跳。碰撞检测功能已经修改，以适应在矩形内弹跳，所以飞船的移动将是随机的。本节的代码位于`learn-webassembly`存储库中的`/chapter-09-node/webpack-example`文件夹中。项目的文件结构如下所示：

```cpp
├── /src
│    ├── /assets
│    │    ├── background.jpg
│    │    └── spaceship.svg
│    ├── App.js
│    ├── index.html
│    ├── index.js
│    ├── main.c
│    └── styles.css
├── package.json
├── package-lock.json
└── webpack.config.js
```

我们将在后面的章节中审查 Webpack 配置文件。现在，让我们花一点时间更详细地讨论 Webpack。

# 什么是 Webpack？

在过去的几年里，JavaScript 生态系统一直在迅速发展，导致不断涌现新的框架和库。捆绑器的出现使开发人员能够将 JavaScript 应用程序分成多个文件，而不必担心管理全局命名空间、脚本加载顺序或 HTML 文件中的一长串`<script>`标签。捆绑器将所有文件合并为一个文件，并解决任何命名冲突。

截至撰写本文时，Webpack 是前端开发中最流行的打包工具之一。然而，它的功能远不止于合并 JavaScript 文件。它还执行复杂的任务，如代码拆分和摇树（死代码消除）。Webpack 采用了插件架构，这导致了大量由社区开发的插件。在`npm`上搜索 Webpack 目前返回超过 12,000 个包！这个详尽的插件列表，加上其强大的内置功能集，使 Webpack 成为一个功能齐全的构建工具。

# 安装和配置 Webpack

在开始应用程序演示之前，在`/webpack-example`文件夹中打开终端并运行以下命令：

```cpp
npm install 
```

# 依赖概述

应用程序使用 Webpack 的版本 4（在撰写本文时为最新版本）来构建我们的应用程序。我们需要使用 Webpack 插件来加载应用程序中使用的各种文件类型，并使用 Babel 来利用较新的 JavaScript 功能。以下片段列出了我们在项目中使用的`devDependencies`（取自`package.json`）：

```cpp
...
"devDependencies": {
  "@babel/core": "⁷.0.0-rc.1",
  "@babel/preset-env": "⁷.0.0-rc.1",
  "babel-loader": "⁸.0.0-beta.4",
  "cpp-wasm-loader": "0.7.7",
  "css-loader": "1.0.0",
  "file-loader": "1.1.11",
  "html-loader": "0.5.5",
  "html-webpack-plugin": "3.2.0",
  "mini-css-extract-plugin": "0.4.1",
  "rimraf": "2.6.2",
  "webpack": "4.16.5",
  "webpack-cli": "3.1.0",
  "webpack-dev-server": "3.1.5"
},
...
```

我为一些库指定了确切的版本，以确保应用程序能够成功构建和运行。任何以`-loader`或`-plugin`结尾的库都与 Webpack 一起使用。`cpp-wasm-loader`库允许我们直接导入 C 或 C++文件，而无需先将其编译为 Wasm。Webpack 4 内置支持导入`.wasm`文件，但无法指定`importObj`参数，这是使用 Emscripten 生成的模块所必需的。

# 在 webpack.config.js 中配置加载器和插件

除了 JavaScript 之外，我们还在应用程序中使用了几种不同的文件类型：CSS、SVG、HTML 等。安装`-loader`依赖项只是问题的一部分——您还需要告诉 Webpack 如何加载它们。您还需要为已安装的任何插件指定配置详细信息。您可以在项目的根文件夹中的`webpack.config.js`文件中指定加载和配置详细信息。以下片段包含了`/webpack-example/webpack.config.js`的内容：

```cpp
const HtmlWebpackPlugin = require('html-webpack-plugin');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');

module.exports = {
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            // We need this to use async/await:
            presets: [
              [
                '@babel/preset-env', {
                  targets: { node: '10' }
                }
              ]
            ]
          }
        }
      },
      {
        test: /\.html$/,
        use: {
          loader: 'html-loader',
          options: { minimize: true }
        }
      },
      {
        test: /\.css$/,
        use: [MiniCssExtractPlugin.loader, 'css-loader']
      },
      {
        test: /\.(c|cpp)$/,
        use: {
          loader: 'cpp-wasm-loader',
          options: {
            emitWasm: true
          }
        }
      },
      {
        test: /\.(png|jpg|gif|svg)$/,
        use: {
          loader: 'file-loader',
          options: {
            name: 'assets/[name].[ext]'
          }
        }
      }
    ]
  },
  plugins: [
    new HtmlWebpackPlugin({
      template: './src/index.html',
      filename: './index.html'
    }),
    // This is used for bundling (building for production):
    new MiniCssExtractPlugin({
      filename: '[name].css',
      chunkFilename: '[id].css'
    })
  ]
};
```

`rules`部分告诉 Webpack 使用哪个加载器来处理文件扩展名。数组中的第四项处理 C/C++文件（注意`test`字段值包含`c|cpp`）。`HtmlWebpackPlugin`获取`/src/index.html`的内容，添加任何所需的`<script>`标签，对其进行最小化，并在`build`文件夹中创建一个`index.html`，默认为`/dist`。`MiniCssExtractPlugin`将任何导入的 CSS 复制到`/dist`文件夹中的单个 CSS 文件中。我们将在后面的部分中讨论如何构建项目，所以让我们继续进行应用程序代码的讲解，从 C 文件开始。

# C 代码

由于我们可以直接导入 C 和 C++文件，因此 C 文件位于`/src`文件夹中。这个文件，`main.c`，包含了管理碰撞检测和移动飞船的逻辑。这段代码基于我们在第五章中创建的`without-glue.c`文件，*创建和加载 WebAssembly 模块*。我们不打算审查整个文件，只审查已更改并值得解释的部分。让我们从定义和声明部分开始，其中包括一个新的`struct`：`Bounds`。

# 定义和声明

包含定义和声明部分的代码如下所示：

```cpp
typedef struct Bounds {
  int width;
  int height;
} Bounds;

// We're using the term "Rect" to represent the rectangle the
// image occupies:
typedef struct Rect {
  int x;
  int y;
  int width;
  int height;
  // Horizontal direction of travel (L/R):
  char horizDir;
  // Vertical direction of travel (U/D):
  char vertDir;
} Rect;

struct Bounds bounds;
struct Rect rect;
```

对现有的`Rect`定义添加了新属性，以适应灵活的大小和在*x*和*y*方向上的移动跟踪。我们定义了一个新的`struct`，`Bounds`，并删除了现有的`#define`语句，因为`<canvas>`元素不再是具有静态尺寸的正方形。模块加载时声明了这两个元素的新实例。这些实例的尺寸属性在`start()`函数中赋值，接下来我们将介绍这个函数。

# start()函数

更新的`start()`函数，作为模块的入口点，如下所示：

```cpp
EMSCRIPTEN_KEEPALIVE
void start(int boundsWidth, int boundsHeight, int rectWidth,
           int rectHeight) {
    rect.x = 0;
    rect.y = 0;
    rect.horizDir = 'R';
    rect.vertDir = 'D';
    rect.width = rectWidth;
    rect.height = rectHeight;
    bounds.width = boundsWidth;
    bounds.height = boundsHeight;
    setIsRunning(true);
}
```

从 JavaScript 调用的任何函数都以`EMSCRIPTEN_KEEPALIVE`语句为前缀。现在，我们将`Bounds`和`Rect`元素的宽度和高度作为参数传递给`start()`函数，然后将其分配给本地的`bounds`和`rect`变量。这使我们可以轻松地更改任一元素的尺寸，而无需对碰撞检测逻辑进行任何更改。在这个应用程序的上下文中，`rect`表示飞船图像所在的矩形。我们设置了`rect`的默认水平和垂直方向，使图像最初向右和向下移动。让我们继续进行`rect`移动/碰撞检测代码。

# 更新`updateRectLocation()`函数

与碰撞检测和`Rect`移动相关的代码在`updateRectLocation()`函数中处理，如下所示：

```cpp
/**
 * Updates the rectangle location by +/- 1px in the x or y based on
 * the current location.
 */
void updateRectLocation() {
    // Determine if the bounding rectangle has "bumped" into either
    // the left/right side or top/bottom side. Depending on which side,
    // flip the direction:
    int xBouncePoint = bounds.width - rect.width;
    if (rect.x == xBouncePoint) rect.horizDir = 'L';
    if (rect.x == 0) rect.horizDir = 'R';

    int yBouncePoint = bounds.height - rect.height;
    if (rect.y == yBouncePoint) rect.vertDir = 'U';
    if (rect.y == 0) rect.vertDir = 'D';

    // If the direction has changed based on the x and y
    // coordinates, ensure the x and y points update
    // accordingly:
    int horizIncrement = 1;
    if (rect.horizDir == 'L') horizIncrement = -1;
    rect.x = rect.x + horizIncrement;

    int vertIncrement = 1;
    if (rect.vertDir == 'U') vertIncrement = -1;
    rect.y = rect.y + vertIncrement;
}
```

这段代码与我们在第五章中编写的代码的主要区别是碰撞检测逻辑。现在，函数不仅仅是水平跟踪`rect`实例的位置，并在其击中右边界时改变方向，而是现在函数同时跟踪水平和垂直方向，并独立管理每个方向。虽然这不是最高效的算法，但它确实实现了确保飞船在遇到`<canvas>`边缘时改变方向的目标。

# JavaScript 代码

我们应用程序唯一的生产依赖是 Vue。虽然应用程序只包含一个组件，但 Vue 使得管理数据、函数和组件生命周期比手动操作简单得多。`index.js`文件包含了 Vue 初始化代码，而渲染和应用程序逻辑在`/src/App.js`中。这个文件有很多部分，所以我们将像在上一节一样分块审查代码。让我们从`import`语句开始。

# 导入语句

以下代码演示了 Webpack 加载器的工作原理：

```cpp
// This is loaded using the css-loader dependency:
import './styles.css';

// This is loaded using the cpp-wasm-loader dependency:
import wasm from './main.c';

// These are loaded using the file-loader dependency:
import backgroundImage from './assets/background.jpg';
import spaceshipImage from './assets/spaceship.svg';
```

我们在`webpack.config.js`文件中配置的加载器知道如何处理 CSS、C 和图像文件。现在我们有了所需的资源，我们可以开始定义我们的组件状态。

# 组件状态

以下代码在`data()`函数中初始化了组件的本地状态：

```cpp
export default {
  data() {
    return {
      instance: null,
      bounds: { width: 800, height: 592 },
      rect: { width: 200, height: 120 },
      speed: 5
    };
  },
  ...
```

虽然`bounds`和`rect`属性永远不会改变，但我们在本地状态中定义它们，以便将组件使用的所有数据保存在一个位置。`speed`属性决定了飞船在`<canvas>`上移动的速度，并且范围为`1`到`10`。`instance`属性初始化为 null，但将用于访问编译后的 Wasm 模块的导出函数。让我们继续进行编译 Wasm 文件并填充`<canvas>`的 Wasm 初始化代码。

# Wasm 初始化

编译 Wasm 文件并填充`<canvas>`元素的代码如下所示：

```cpp
methods: {
  // Create a new Image instance to pass into the drawImage function
  // for the <canvas> element's context:
  loadImage(imageSrc) {
    const loadedImage = new Image();
    loadedImage.src = imageSrc;
    return new Promise((resolve, reject) => {
      loadedImage.onload = () => resolve(loadedImage);
      loadedImage.onerror = () => reject();
    });
  },

  // Compile/load the contents of main.c and assign the resulting
  // Wasm module instance to the components this.instance property:
  async initializeWasm() {
    const ctx = this.$refs.canvas.getContext('2d');

    // Create Image instances of the background and spaceship.
    // These are required to pass into the ctx.drawImage() function:
    const [bouncer, background] = await Promise.all([
      this.loadImage(spaceshipImage),
      this.loadImage(backgroundImage)
    ]);

    // Compile the C code to Wasm and assign the resulting
    // module.exports to this.instance:
    const { width, height } = this.bounds;
    return wasm
      .init(imports => ({
        ...imports,
        _jsFillRect(x, y, w, h) {
          ctx.drawImage(bouncer, x, y, w, h);
        },
        _jsClearRect() {
          ctx.drawImage(background, 0, 0, width, height);
        }
      }))
        .then(module => {
          this.instance = module.exports;
          return Promise.resolve();
        });
  },
  ...
```

在组件的`methods`键中定义了其他函数，但现在我们将专注于将导入的 C 文件编译为 Wasm 的代码。在为飞船和背景图像创建`Image`实例之后，将`main.c`文件（导入为`.wasm`）编译为 Wasm 模块，并将结果的`exports`分配给`this.instance`。完成这些操作后，可以从导出的 Wasm 模块中调用`start()`函数。由于`initializeWasm()`函数调用了`<canvas>`元素的`getContext()`函数，因此在调用此函数之前，组件需要被挂载。让我们审查`methods`定义的其余部分和`mounted()`事件处理程序。

# 组件挂载

其余的`methods`定义和`mounted()`事件处理程序函数如下所示：

```cpp
  ...
  // Looping function to move the spaceship across the canvas.
  loopRectMotion() {
    setTimeout(() => {
      this.instance.moveRect();
      if (this.instance.getIsRunning()) this.loopRectMotion();
    }, 15 - this.speed);
  },
  // Pauses/resumes the spaceship's movement when the button is
  // clicked:
  onActionClick(event) {
    const newIsRunning = !this.instance.getIsRunning();
    this.instance.setIsRunning(newIsRunning);
    event.target.innerHTML = newIsRunning ? 'Pause' : 'Resume';
    if (newIsRunning) this.loopRectMotion();
  }
},
mounted() {
  this.initializeWasm().then(() => {
    this.instance.start(
      this.bounds.width,
      this.bounds.height,
      this.rect.width,
      this.rect.height
    );
    this.loopRectMotion();
  });
},
```

一旦 Wasm 模块被编译，`start()`函数就可以在`this.instance`上访问。`bounds`和`rect`尺寸被传递到`start()`函数中，然后调用`loopRectFunction()`来开始移动飞船。`onActionClick()`事件处理程序函数根据飞船当前是否在运动来暂停或恢复飞船的移动。

`loopRectMotion()`函数的工作方式与第五章中的示例代码相同，*创建和加载 WebAssembly 模块*，只是现在速度是可调节的。`15 - this.speed`的计算可能看起来有点奇怪。由于图像的移动速度是基于函数调用之间经过的时间，增加这个数字实际上会减慢飞船的速度。因此，`this.speed`从`15`中减去，选择`15`是因为它略大于`10`，但不会在将`this.speed`增加到最大值时使飞船变得模糊。这就是组件逻辑；让我们继续到代码的渲染部分，其中定义了`template`。

# 组件渲染

`template`属性的内容，决定了要渲染的内容，如下所示：

```cpp
template: `
  <div class="flex column">
   <h1>SPACE WASM!</h1>
    <canvas
      ref="canvas"
      :height="bounds.height"
      :width="bounds.width">
    </canvas>
    <div class="flex controls">
      <div>
        <button class="defaultText" @click="onActionClick">
          Pause
        </button>
      </div>
    <div class="flex column">
      <label class="defaultText" for="speed">Speed: {{speed}}</label>
      <input
        v-model="speed"
        id="speed"
        type="range"
        min="1"
        max="10"
        step="1">
    </div>
  </div>
</div>

```

由于我们使用了 Vue，我们可以将 HTML 元素的属性和事件处理程序绑定到组件中定义的属性和方法。除了一个暂停/恢复按钮，还有一个范围`<input>`，允许您改变速度。通过将其向左或向右滑动，您可以减慢或加快飞船的速度，并立即看到变化。这就结束了我们的回顾；让我们看看 Webpack 如何用来构建或运行应用程序。

# 构建和运行应用程序

使用`cpp-wasm-loader`库可以消除构建步骤生成 Wasm 模块的需要，但我们仍然需要将应用程序捆绑起来进行分发。在`package.json`的`scripts`部分，有一个`build`和`start`脚本。运行`build`脚本会执行生成捆绑包的`webpack`命令。为了确保这一切都正常工作，打开`/webpack-example`文件夹中的终端实例，并运行以下命令：

```cpp
npm run build
```

第一次运行项目构建可能需要一分钟。这可能归因于 Wasm 编译步骤。但是，后续的构建应该会快得多。如果构建成功，您应该会看到一个新创建的`/dist`文件夹，其中包含以下内容：

```cpp
├── /assets
│    ├── background.jpg
│    └── spaceship.svg
├── index.html
├── main.css
├── main.js
└── main.wasm
```

# 测试构建

让我们尝试构建以确保一切都正常工作。在终端实例中运行以下命令来启动应用程序：

```cpp
serve -l 8080 dist
```

如果在浏览器中导航到`http://127.0.0.1:8080/index.html`，您应该会看到这个：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/9d3c1c1f-1f92-41e2-a5e6-27673bc221d8.png)

Webpack 应用程序在浏览器中运行

飞船图像（取自[`commons.wikimedia.org/wiki/File:Alien_Spaceship_-_SVG_Vector.svg`](https://commons.wikimedia.org/wiki/File:Alien_Spaceship_-_SVG_Vector.svg)）在 Horsehead 星云背景图像（取自[`commons.wikimedia.org/wiki/File:Horsehead_Nebula_Christmas_2017_Deography.jpg`](https://commons.wikimedia.org/wiki/File:Horsehead_Nebula_Christmas_2017_Deography.jpg)）的范围内弹来弹去。当按下暂停按钮时，按钮的标题会更改为恢复，飞船停止移动。再次按下按钮将会将标题更改回暂停，并且飞船将再次开始移动。调整速度滑块会增加或减少飞船的速度。

# 运行启动脚本

应用程序已安装`webpack-dev-server`库，它的操作方式类似于`Browsersync`。该库使用 LiveReloading，在您对`/src`中的文件进行任何更改时会自动更新应用程序。由于我们使用了 C 和 C++文件的 Webpack 加载器，因此如果您更改了 C 文件，自动更新事件也会触发。运行以下命令来启动应用程序并监视更改：

```cpp
npm start
```

当构建完成时，浏览器窗口应该会自动打开，然后将您引导到运行的应用程序。要查看实时重新加载功能的操作，请尝试将`main.c`中的`setIsRunning()`函数中的`isRunning`变量的值设置为 false，而不是`newIsRunning`：

```cpp
EMSCRIPTEN_KEEPALIVE
void setIsRunning(bool newIsRunning) {
    // isRunning = newIsRunning;

    // Set the value to always false:
    isRunning = false;
}
```

飞船应该被卡在左上角。如果您将其改回，飞船将重新开始移动。在下一节中，我们将编写 JavaScript 单元测试来测试 WebAssembly 模块。

# 使用 Jest 测试 WebAssembly 模块

经过充分测试的代码可以防止回归错误，简化重构，并减轻添加新功能时的一些挫折感。一旦您编译了一个 Wasm 模块，您应该编写测试来确保它的功能符合预期，即使您已经为您从中编译出来的 C、C++或 Rust 代码编写了测试。在本节中，我们将使用**Jest**，一个 JavaScript 测试框架，来测试编译后的 Wasm 模块中的函数。

# 正在测试的代码

此示例中使用的所有代码都位于`/chapter-09-node/testing-example`文件夹中。代码和相应的测试非常简单，不代表真实应用程序，但旨在演示如何使用 Jest 进行测试。以下代码表示`/testing-example`文件夹的文件结构：

```cpp
├── /src
|    ├── /__tests__
|    │    └── main.test.js
|    └── main.c
├── package.json
└── package-lock.json
```

我们将要测试的 C 文件的内容，`/src/main.c`，如下所示：

```cpp
int addTwoNumbers(int leftValue, int rightValue) {
    return leftValue + rightValue;
}

float divideTwoNumbers(float leftValue, float rightValue) {
    return leftValue / rightValue;
}

double findFactorial(float value) {
    int i;
    double factorial = 1;

    for (i = 1; i <= value; i++) {
        factorial = factorial * i;
    }
    return factorial;
}
```

文件中的所有三个函数都执行简单的数学运算。`package.json`文件包含一个脚本，用于将 C 文件编译为 Wasm 文件进行测试。运行以下命令来编译 C 文件：

```cpp
npm run build
```

`/src`目录中应该有一个名为`main.wasm`的文件。让我们继续描述测试配置步骤。

# 测试配置

在这个示例中，我们将使用 Jest 作为唯一的依赖项，Jest 是 Facebook 开发的 JavaScript 测试框架。Jest 是测试的绝佳选择，因为它包含大多数您需要的功能，如覆盖率、断言和模拟等。在大多数情况下，您可以在零配置的情况下使用它，具体取决于您的应用程序的复杂性。如果您想了解更多，请访问 Jest 的网站[`jestjs.io`](https://jestjs.io)。在`/chapter-09-node/testing-example`文件夹中打开一个终端实例，并运行以下命令来安装 Jest：

```cpp
npm install
```

在`package.json`文件中，`scripts`部分有三个条目：`build`、`pretest`和`test`。`build`脚本使用所需的标志执行`emcc`命令，将`/src/main.c`编译为`/src/main.wasm`。`test`脚本使用`--verbose`标志执行`jest`命令，为每个测试套件提供额外的细节。`pretest`脚本只是运行`build`脚本，以确保在运行任何测试之前存在`/src/main.wasm`。

# 测试文件审查

让我们来看一下位于`/src/__tests__/main.test.js`的测试文件，并审查代码的每个部分的目的。测试文件的第一部分实例化`main.wasm`文件，并将结果分配给本地的`wasmInstance`变量：

```cpp
const fs = require('fs');
const path = require('path');

describe('main.wasm Tests', () => {
  let wasmInstance;

  beforeAll(async () => {
    const wasmPath = path.resolve(__dirname, '..', 'main.wasm');
    const buffer = fs.readFileSync(wasmPath);
    const results = await WebAssembly.instantiate(buffer, {
      env: {
        memoryBase: 0,
        tableBase: 0,
        memory: new WebAssembly.Memory({ initial: 1024 }),
        table: new WebAssembly.Table({ initial: 16, element: 'anyfunc' }),
        abort: console.log
      }
    });
    wasmInstance = results.instance.exports;
  });
 ...
```

Jest 提供了生命周期方法来执行任何设置或拆卸操作以便在运行测试之前进行。您可以指定在所有测试之前或之后运行的函数（`beforeAll()`/`afterAll()`），或者在每个测试之前或之后运行的函数（`beforeEach()`/`afterEach()`）。我们需要一个编译后的 Wasm 模块实例，从中我们可以调用导出的函数，因此我们将实例化代码放在`beforeAll()`函数中。

我们将整个测试套件包装在文件的`describe()`块中。Jest 使用`describe()`函数来封装相关测试套件，使用`test()`或`it()`来表示单个测试。以下是这个概念的一个简单示例：

```cpp
const add = (a, b) => a + b;

describe('the add function', () => {
  test('returns 6 when 4 and 2 are passed in', () => {
    const result = add(4, 2);
    expect(result).toEqual(6);
  });

  test('returns 20 when 12 and 8 are passed in', () => {
    const result = add(12, 8);
    expect(result).toEqual(20);
  });
});
```

下一节代码包含了所有的测试套件和每个导出函数的测试：

```cpp
...
  describe('the _addTwoNumbers function', () => {
    test('returns 300 when 100 and 200 are passed in', () => {
      const result = wasmInstance._addTwoNumbers(100, 200);
      expect(result).toEqual(300);
    });

    test('returns -20 when -10 and -10 are passed in', () => {
      const result = wasmInstance._addTwoNumbers(-10, -10);
      expect(result).toEqual(-20);
    });
  });

  describe('the _divideTwoNumbers function', () => {
    test.each([
      [10, 100, 10],
      [-2, -10, 5],
    ])('returns %f when %f and %f are passed in', (expected, a, b) => {
      const result = wasmInstance._divideTwoNumbers(a, b);
      expect(result).toEqual(expected);
    });

    test('returns ~3.77 when 20.75 and 5.5 are passed in', () => {
      const result = wasmInstance._divideTwoNumbers(20.75, 5.5);
      expect(result).toBeCloseTo(3.77, 2);
    });
  });

  describe('the _findFactorial function', () => {
    test.each([
      [120, 5],
      [362880, 9.2],
    ])('returns %p when %p is passed in', (expected, input) => {
      const result = wasmInstance._findFactorial(input);
      expect(result).toEqual(expected);
    });
  });
});
```

第一个`describe()`块，用于`_addTwoNumbers()`函数，有两个`test()`实例，以确保函数返回作为参数传入的两个数字的总和。接下来的两个`describe()`块，用于`_divideTwoNumbers()`和`_findFactorial()`函数，使用了 Jest 的`.each`功能，允许您使用不同的数据运行相同的测试。`expect()`函数允许您对作为参数传入的值进行断言。最后一个`_divideTwoNumbers()`测试中的`.toBeCloseTo()`断言检查结果是否在`3.77`的两个小数位内。其余使用`.toEqual()`断言来检查相等性。

使用 Jest 编写测试相对简单，运行测试甚至更容易！让我们尝试运行我们的测试，并查看 Jest 提供的一些 CLI 标志。

# 运行测试

要运行测试，请在`/chapter-09-node/testing-example`文件夹中打开终端实例，并运行以下命令：

```cpp
npm test
```

您应该在终端中看到以下输出：

```cpp
main.wasm Tests
  the _addTwoNumbers function
    ✓ returns 300 when 100 and 200 are passed in (4ms)
    ✓ returns -20 when -10 and -10 are passed in
  the _divideTwoNumbers function
    ✓ returns 10 when 100 and 10 are passed in
    ✓ returns -2 when -10 and 5 are passed in (1ms)
    ✓ returns ~3.77 when 20.75 and 5.5 are passed in
  the _findFactorial function
    ✓ returns 120 when 5 is passed in (1ms)
    ✓ returns 362880 when 9.2 is passed in

Test Suites: 1 passed, 1 total
Tests: 7 passed, 7 total
Snapshots: 0 total
Time: 1.008s
Ran all test suites.
```

如果您有大量的测试，可以从`package.json`中的`test`脚本中删除`--verbose`标志，并仅在需要时将标志传递给`npm test`命令。您可以将其他几个 CLI 标志传递给`jest`命令。以下列表包含一些常用的标志：

+   `--bail`: 在第一个失败的测试套件后立即退出测试套件

+   `--coverage`: 收集测试覆盖率，并在测试运行后在终端中显示

+   `--watch`: 监视文件更改并重新运行与更改文件相关的测试

您可以通过在`--`之后添加这些标志来将这些标志传递给`npm`测试命令。例如，如果您想使用`--bail`标志，您可以运行以下命令：

```cpp
npm test -- --bail
```

您可以在官方网站上查看所有 CLI 选项的完整列表：[`jestjs.io/docs/en/cli`](https://jestjs.io/docs/en/cli)。

# 总结

在本章中，我们讨论了将 WebAssembly 与 Node.js 集成的优势，并演示了 Node.js 如何在服务器端和客户端使用。我们评估了一个使用 Wasm 模块执行会计交易计算的 Express 应用程序。然后，我们审查了一个基于浏览器的应用程序，该应用程序利用 Webpack 从 C 文件中导入和调用函数，而无需编写任何 Wasm 实例化代码。最后，我们看到了如何利用 Jest 测试框架来测试编译模块并确保其正常运行。在第十章中，*高级工具和即将推出的功能*，我们将介绍高级工具，并讨论 WebAssembly 即将推出的功能。

# 问题

1.  将 WebAssembly 与 Node.js 集成的优势之一是什么？

1.  Express 应用程序使用哪个库来读取和写入数据到 JSON 文件？

1.  在浏览器和 Node.js 中加载模块有什么区别？

1.  您可以使用什么技术在现有的`npm`脚本之前或之后运行一个`npm`脚本？

1.  Webpack 执行的任务名称是什么，以消除死代码？

1.  Webpack 中加载程序的目的是什么？

1.  Jest 中`describe()`和`test()`函数之间的区别是什么？

1.  如何将额外的 CLI 标志传递给`npm test`命令？

# 进一步阅读

+   Express: [`expressjs.com`](https://expressjs.com)

+   Webpack: [`webpack.js.org`](https://webpack.js.org)

+   Jest API: [`jestjs.io/docs/en/api`](https://jestjs.io/docs/en/api)
