# C++ 编程入门指南（七）

> 原文：[`annas-archive.org/md5/024671a6ef06ea57693023eca62b8eea`](https://annas-archive.org/md5/024671a6ef06ea57693023eca62b8eea)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：构建可玩关卡和碰撞检测

这一章可能是这个项目中最令人满意的一章。原因是到最后，我们将有一个可玩的游戏。虽然还有一些功能要实现（声音、粒子效果、HUD 和着色器效果），但 Bob 和 Thomas 将能够奔跑、跳跃和探索世界。此外，您将能够通过简单地在文本文件中制作平台和障碍物来创建几乎任何大小或复杂度的关卡设计。

通过本章的以下主题，我们将实现所有这些：

+   探索如何在文本文件中设计关卡

+   构建一个`LevelManager`类，它将从文本文件中加载关卡，将其转换为游戏可以使用的数据，并跟踪关卡细节，如生成位置、当前关卡和允许的时间限制

+   更新游戏引擎以使用`LevelManager`

+   编写一个多态函数来处理 Bob 和 Thomas 的碰撞检测

# 设计一些关卡

记得我们在第十二章中介绍的精灵表吗，*抽象和代码管理-更好地利用 OOP*。这里再次显示，用数字注释表示我们将从中构建关卡的每个瓷砖：

![设计一些关卡](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_14_001.jpg)

我将截图放在灰色背景上，这样您可以清楚地看到精灵表的不同细节。方格背景表示透明度级别。因此，除了数字 1 之外的所有瓷砖都会至少部分显示其背后的背景：

+   瓷砖 0 完全透明，将用于填补没有其他瓷砖的空白处

+   瓷砖 1 是 Thomas 和 Bob 将走在上面的平台

+   瓷砖 2 用于火砖，瓷砖 3 用于水砖

+   瓷砖 4，您可能需要仔细查看。它有一个白色的方形轮廓。这是 Thomas 和 Bob 必须一起到达的关卡目标。

在讨论设计关卡时，请记住这个截图。

我们将在文本文件中输入这些瓷砖编号的组合来设计布局。举个例子：

```cpp
0000000000000000000000000000000000000000000000 
0000000000000000000000000000000000000000000000 
0000000000000000000000000000000000000000000000 
0000000000000000000000000000000000000000000000 
0000000000000000000000000000000000000000000000 
0000000000000000000000000000000000000000000000 
1111111111000111111222222221111133111111111411 
0000000000000000001222222221000133100000001110 
0000000000000000001222222221000133100000000000 
0000000000000000001222222221000133100000000000 
0000000000000000001111111111000111100000000000 

```

先前的代码转换为以下关卡布局：

![设计一些关卡](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_14_002.jpg)

请注意，为了获得前一个截图中显示的视图，我必须缩小`View`。此外，截图被裁剪了。关卡的实际起始位置将看起来像下面的截图：

![设计一些关卡](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_14_003.jpg)

向您展示这些截图的目的有两个。首先，您可以看到如何使用简单和免费的文本编辑器快速构建关卡设计。

### 提示

只需确保使用等宽字体，以便所有数字大小相同。这样设计关卡就会更容易。

其次，这些截图展示了设计的游戏方面。在关卡中，Thomas 和 Bob 首先需要跳过一个小洞，否则他们将掉入死亡（重新生成）。然后他们需要穿过一大片火焰。实际上，Bob 不可能跳过那么多块砖。玩家们需要共同解决问题。Bob 清除火砖的唯一方法是站在 Thomas 的头上，然后从那里跳，如下截图所示：

![设计一些关卡](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_14_004.jpg)

然后很容易到达目标并进入下一关。

### 提示

我强烈建议您完成本章，然后花一些时间设计自己的关卡。

我已经包含了一些关卡设计供您参考。它们位于我们在第十二章中添加到项目中的`levels`文件夹中，*抽象和代码管理-更好地利用 OOP*。

接下来是游戏的一些缩小视图，以及关卡设计代码的屏幕截图。代码的屏幕截图可能比重现实际的文本内容更有用。如果您确实想看到代码，只需在`levels`文件夹中打开文件。

这就是代码的样子：

![设计一些关卡](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_14_005.jpg)

这是前面的代码将产生的关卡布局：

![设计一些关卡](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_14_006.jpg)

这个关卡是我在第十二章中提到的“信任之跃”关卡，*抽象和代码管理-更好地利用 OOP*：

![设计一些关卡](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_14_007.jpg)

我已经突出显示了平台，因为在缩小的屏幕截图中它们不太清晰：

![设计一些关卡](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_14_008.jpg)

提供的设计很简单。游戏引擎将能够处理非常大的设计。您可以自由发挥想象力，构建一些非常大且难以完成的关卡。

当然，除非我们学会如何加载它们并将文本转换为可玩的关卡，否则这些设计实际上不会做任何事情。此外，在实现碰撞检测之前，将无法站在任何平台上。

首先，让我们处理加载关卡设计。

# 构建 LevelManager 类

我们需要经过几个阶段的编码才能使我们的关卡设计起作用。我们将首先编写`LevelManager`头文件。这将使我们能够查看和讨论`LevelManger`类中的成员变量和函数。

接下来，我们将编写`LevelManager.cpp`文件，其中将包含所有的函数定义。由于这是一个很长的文件，我们将把它分成几个部分，以便编码和讨论。

一旦`LevelManager`类完成，我们将在游戏引擎（`Engine`类）中添加一个实例。我们还将在`Engine`类中添加一个新函数`loadLevel`，我们可以在需要新关卡时从`update`函数中调用。`loadLevel`函数不仅将使用`LevelManager`实例来加载适当的关卡，还将处理诸如生成玩家角色和准备时钟等方面。

如前所述，让我们通过编写`LevelManager.h`文件来概述`LevelManager`。

## 编码 LevelManager.h

在**解决方案资源管理器**中右键单击**头文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，通过左键单击**头文件（** `.h` **）**并在**名称**字段中键入`LevelManager.h`。最后，单击**添加**按钮。我们现在准备编写`LevelManager`类的头文件。

添加以下包含指令和私有变量，然后我们将讨论它们：

```cpp
#pragma once 

#include <SFML/Graphics.hpp> 
using namespace sf; 
using namespace std; 

class LevelManager 
{ 
private: 
   Vector2i m_LevelSize; 
   Vector2f m_StartPosition; 
   float m_TimeModifier = 1; 
   float m_BaseTimeLimit = 0; 
   int m_CurrentLevel = 0; 
   const int NUM_LEVELS = 4; 

// public declarations go here 

```

代码声明了`Vector2i``m_LevelSize`，用于保存当前地图包含的水平和垂直瓦片数的两个整数值。`Vector2f``m_StartPosition`包含 Bob 和 Thomas 应该生成的世界坐标。请注意，这不是与`m_LevelSize`单位相关的瓦片位置，而是关卡中的水平和垂直像素位置。

`m_TimeModifier`成员变量是一个浮点数，将用于乘以当前关卡中可用的时间。我们之所以要这样做，是因为通过改变（减少）这个值，我们将在玩家尝试同一关卡时缩短可用的时间。例如，如果玩家第一次尝试第一关有 60 秒的时间，那么 60 乘以 1 当然是 60。当玩家完成所有关卡并再次回到第一关时，`m_TimeModifier`将减少 10％。然后，当可用时间乘以 0.9 时，玩家可用的时间将是 54 秒。这比 60 少 10％。游戏将逐渐变得更加困难。

浮点变量`m_BaseTimeLimit`保存了我们刚刚讨论的原始未修改的时间限制。

您可能已经猜到`m_CurrentLevel`将保存当前正在播放的关卡编号。

`int` `NUM_LEVELS`常量将用于标记何时适合再次返回到第一关，并减少`m_TimeModifier`的值。

现在添加以下公共变量和函数声明：

```cpp
public: 

   const int TILE_SIZE = 50; 
   const int VERTS_IN_QUAD = 4; 

   float getTimeLimit(); 

   Vector2f getStartPosition(); 

   int** nextLevel(VertexArray& rVaLevel); 

   Vector2i getLevelSize(); 

   int getCurrentLevel(); 

}; 

```

在上一段代码中，有两个常量`int`成员。`TILE_SIZE`是一个有用的常量，提醒我们精灵表中的每个图块都是五十像素宽和五十像素高。`VERTS_IN_QUAD`是一个有用的常量，使我们对`VertexArray`的操作不那么容易出错。实际上，一个四边形中有四个顶点。现在我们不能忘记它。

`getTimeLimit`、`getStartPosition`、`getLevelSize`和`getCurrentLevel`函数是简单的 getter 函数，返回我们在上一段代码中声明的私有成员变量的当前值。

值得仔细研究的一个函数是`nextLevel`。这个函数接收一个`VertexArray`引用，就像我们在 Zombie Arena 游戏中使用的那样。函数可以在`VertexArray`上工作，所有的更改都将出现在调用代码中的`VertexArray`中。`nextLevel`函数返回一个指向指针的指针，这意味着我们可以返回一个地址，该地址是`int`值的二维数组的第一个元素。我们将构建一个`int`值的二维数组，该数组将表示每个关卡的布局。当然，这些`int`值将从关卡设计文本文件中读取。

## 编写`LevelManager.cpp`文件。

在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，通过左键单击**C++文件（**`.cpp`**）**，然后在**名称**字段中键入`LevelManager.cpp`。最后，单击**添加**按钮。现在我们准备编写`LevelManager`类的`.cpp`文件。

由于这是一个相当长的类，我们将把它分成六个部分进行讨论。前五部分将涵盖`nextLevel`函数，第六部分将涵盖其他所有内容。

添加以下包含指令和`nextLevel`函数的第一部分（共五部分）：

```cpp
#include "stdafx.h" 
#include <SFML/Graphics.hpp> 
#include <SFML/Audio.hpp> 
#include "TextureHolder.h" 
#include <sstream> 
#include <fstream> 
#include "LevelManager.h" 

using namespace sf; 
using namespace std; 

int** LevelManager::nextLevel(VertexArray& rVaLevel) 
{ 
   m_LevelSize.x = 0; 
   m_LevelSize.y = 0; 

   // Get the next level 
   m_CurrentLevel++; 
   if (m_CurrentLevel > NUM_LEVELS) 
   { 
      m_CurrentLevel = 1; 
      m_TimeModifier -= .1f; 
   } 

   // Load the appropriate level from a text file 
   string levelToLoad; 
   switch (m_CurrentLevel) 
   { 

   case 1: 
      levelToLoad = "levels/level1.txt"; 
      m_StartPosition.x = 100; 
      m_StartPosition.y = 100; 
      m_BaseTimeLimit = 30.0f; 
      break; 

   case 2: 
      levelToLoad = "levels/level2.txt"; 
      m_StartPosition.x = 100; 
      m_StartPosition.y = 3600; 
      m_BaseTimeLimit = 100.0f; 
      break; 

   case 3: 
      levelToLoad = "levels/level3.txt"; 
      m_StartPosition.x = 1250; 
      m_StartPosition.y = 0; 
      m_BaseTimeLimit = 30.0f; 
      break; 

   case 4: 
      levelToLoad = "levels/level4.txt"; 
      m_StartPosition.x = 50; 
      m_StartPosition.y = 200; 
      m_BaseTimeLimit = 50.0f; 
      break; 

   }// End switch 

```

在包含指令之后，代码将`m_LevelSize.x`和`m_LevelSize.y`初始化为零。

接下来，增加`m_CurrentLevel`。随后的`if`语句检查`m_CurrentLevel`是否大于`NUM_LEVELS`。如果是，则将`m_CurrentLevel`设置回`1`，并且`m_TimeModifier`减少`.1f`，以缩短所有关卡的允许时间。

然后，根据`m_CurrentLevel`的值进行代码切换。每个`case`语句都初始化文本文件的名称，该文件包含了关卡设计和 Thomas 和 Bob 的起始位置，以及`m_BaseTimeLimit`，这是该关卡的未修改时间限制。

### 提示

如果您设计自己的关卡，请在此处添加`case`语句和相应的值。还要编辑`LevelManager.h`文件中的`NUM_LEVELS`常量。

现在添加`nextLevel`函数的第二部分，如下所示。在上一段代码之后立即添加代码。在添加代码时，请仔细研究，以便我们可以讨论它。

```cpp
   ifstream inputFile(levelToLoad); 
   string s; 

   // Count the number of rows in the file 
   while (getline(inputFile, s)) 
   { 
      ++m_LevelSize.y; 
   } 

   // Store the length of the rows 
   m_LevelSize.x = s.length(); 

```

在我们刚刚编写的上一部分（第二部分）中，我们声明了一个名为`inputFile`的`ifstream`对象，它打开了一个流到`levelToLoad`中包含的文件名。

代码使用`getline`循环遍历文件的每一行，但不记录任何内容。它只是通过递增`m_LevelSize.y`来计算行数。在`for`循环之后，使用`s.length`将关卡的宽度保存在`m_LevelSize.x`中。这意味着所有行的长度必须相同，否则我们会遇到问题。

此时，我们知道并已保存了`m_LevelSize`中当前关卡的长度和宽度。

现在按照所示添加`nextLevel`函数的第三部分。在上一段代码之后立即添加代码。在添加代码时，请仔细研究代码，以便我们可以讨论它：

```cpp
   // Go back to the start of the file 
   inputFile.clear(); 
   inputFile.seekg(0, ios::beg); 

   // Prepare the 2d array to hold the int values from the file 
   int** arrayLevel = new int*[m_LevelSize.y]; 
   for (int i = 0; i < m_LevelSize.y; ++i) 
   { 
      // Add a new array into each array element 
      arrayLevel[i] = new int[m_LevelSize.x]; 
   } 

```

首先，使用其`clear`函数清除`inputFile`。使用带有`0, ios::beg`参数的`seekg`函数将流重置到第一个字符之前。

接下来，我们声明一个指向指针的`arrayLevel`。请注意，这是使用`new`关键字在自由存储/堆上完成的。一旦我们初始化了这个二维数组，我们就能够将其地址返回给调用代码，并且它将持续存在，直到我们删除它或游戏关闭。

`for`循环从 0 到`m_LevelSize.y -1`。在每次循环中，它向堆中添加一个新的`int`值数组，以匹配`m_LevelSize.x`的值。现在，我们有一个完全配置好的（对于当前级别）二维数组。唯一的问题是里面什么都没有。

现在按照所示添加`nextLevel`函数的第四部分。在上一段代码之后立即添加代码。在添加代码时，请仔细研究代码，以便我们可以讨论它：

```cpp
    // Loop through the file and store all the values in the 2d array 
   string row; 
   int y = 0; 
   while (inputFile >> row) 
   { 
      for (int x = 0; x < row.length(); x++) { 

         const char val = row[x]; 
         arrayLevel[y][x] = atoi(&val); 
      } 

      y++; 
   } 

   // close the file 
   inputFile.close(); 

```

首先，代码初始化一个名为`row`的`string`，它将一次保存一个级别设计的行。我们还声明并初始化一个名为`y`的`int`，它将帮助我们计算行数。

`while`循环重复执行，直到`inputFile`超过最后一行。在`while`循环内部有一个`for`循环，它遍历当前行的每个字符，并将其存储在二维数组`arrayLevel`中。请注意，我们使用`arrayLevel[y][x] =`准确地访问二维数组的正确元素。`atoi`函数将`char val`转换为`int`。这是必需的，因为我们有一个用于`int`而不是`char`的二维数组。

现在按照所示添加`nextLevel`函数的第五部分。在上一段代码之后立即添加代码。在添加代码时，请仔细研究代码，以便我们可以讨论它：

```cpp
   // What type of primitive are we using? 
   rVaLevel.setPrimitiveType(Quads); 

   // Set the size of the vertex array 
   rVaLevel.resize(m_LevelSize.x * m_LevelSize.y * VERTS_IN_QUAD); 

   // Start at the beginning of the vertex array 
   int currentVertex = 0; 

   for (int x = 0; x < m_LevelSize.x; x++) 
   { 
      for (int y = 0; y < m_LevelSize.y; y++) 
      { 
         // Position each vertex in the current quad 
         rVaLevel[currentVertex + 0].position =  
            Vector2f(x * TILE_SIZE,  
            y * TILE_SIZE); 

         rVaLevel[currentVertex + 1].position =  
            Vector2f((x * TILE_SIZE) + TILE_SIZE,  
            y * TILE_SIZE); 

         rVaLevel[currentVertex + 2].position =  
            Vector2f((x * TILE_SIZE) + TILE_SIZE,  
            (y * TILE_SIZE) + TILE_SIZE); 

         rVaLevel[currentVertex + 3].position =  
            Vector2f((x * TILE_SIZE),  
            (y * TILE_SIZE) + TILE_SIZE); 

         // Which tile from the sprite sheet should we use 
         int verticalOffset = arrayLevel[y][x] * TILE_SIZE; 

         rVaLevel[currentVertex + 0].texCoords =  
            Vector2f(0, 0 + verticalOffset); 

         rVaLevel[currentVertex + 1].texCoords =  
            Vector2f(TILE_SIZE, 0 + verticalOffset); 

         rVaLevel[currentVertex + 2].texCoords =  
            Vector2f(TILE_SIZE, TILE_SIZE + verticalOffset); 

         rVaLevel[currentVertex + 3].texCoords =  
            Vector2f(0, TILE_SIZE + verticalOffset); 

         // Position ready for the next four vertices 
         currentVertex = currentVertex + VERTS_IN_QUAD; 
      } 
   } 

   return arrayLevel; 
} // End of nextLevel function 

```

尽管这是我们将`nextLevel`分成五个部分中最长的代码部分，但它也是最直接的。这是因为我们在 Zombie Arena 项目中看到了非常相似的代码。

嵌套的`for`循环循环从零到级别的宽度和高度。对于数组中的每个位置，将四个顶点放入`VertexArray`，并从精灵表中分配四个纹理坐标。顶点和纹理坐标的位置是使用`currentVertex`变量、`TILE SIZE`和`VERTS_IN_QUAD`常量计算的。在内部`for`循环的每次循环结束时，`currentVertex`增加`VERTS_IN_QUAD`，很好地移动到下一个瓷砖。

关于这个`VertexArray`的重要一点是它是通过引用传递给`nextLevel`的。因此，`VertexArray`将在调用代码中可用。我们将从`Engine`类中的代码中调用`nextLevel`。

一旦调用了这个函数，`Engine`类将有一个`VertexArray`来图形化表示级别，并且有一个`int`值的二维数组作为级别中所有平台和障碍物的数值表示。

`LevelManager`的其余函数都是简单的 getter 函数，但请花时间熟悉哪个私有值由哪个函数返回。添加`LevelManager`类的其余函数：

```cpp
Vector2i LevelManager::getLevelSize() 
{ 
   return m_LevelSize; 
} 

int LevelManager::getCurrentLevel() 
{ 
   return m_CurrentLevel; 
} 

float LevelManager::getTimeLimit() 
{ 
   return m_BaseTimeLimit * m_TimeModifier; 

} 
Vector2f LevelManager::getStartPosition() 
{ 
   return m_StartPosition; 
} 

```

现在`LevelManager`类已经完成，我们可以继续使用它。我们将在 Engine 类中编写另一个函数来实现这一点。

# 编写 loadLevel 函数

要明确的是，这个函数是`Engine`类的一部分，尽管它将大部分工作委托给其他函数，包括我们刚刚构建的`LevelManager`类的函数。

首先，让我们将新函数的声明以及`Engine.h`文件中的一些其他新代码添加到`Engine.h`文件中。打开`Engine.h`文件，并添加以下`Engine.h`文件的摘要快照中显示的突出显示的代码行：

```cpp
#pragma once 
#include <SFML/Graphics.hpp> 
#include "TextureHolder.h" 
#include "Thomas.h" 
#include "Bob.h" 
#include "LevelManager.h" 

using namespace sf; 

class Engine 
{ 
private: 
   // The texture holder 
   TextureHolder th; 

   // Thomas and his friend, Bob 
   Thomas m_Thomas; 
   Bob m_Bob; 

 // A class to manage all the levels
   LevelManager m_LM; 

   const int TILE_SIZE = 50; 
   const int VERTS_IN_QUAD = 4; 

   // The force pushing the characters down 
   const int GRAVITY = 300; 

   // A regular RenderWindow 
   RenderWindow m_Window; 

   // The main Views 
   View m_MainView; 
   View m_LeftView; 
   View m_RightView; 

   // Three views for the background 
   View m_BGMainView; 
   View m_BGLeftView; 
   View m_BGRightView; 

   View m_HudView; 

   // Declare a sprite and a Texture for the background 
   Sprite m_BackgroundSprite; 
   Texture m_BackgroundTexture; 

   // Is the game currently playing? 
   bool m_Playing = false; 

   // Is character 1 or 2 the current focus? 
   bool m_Character1 = true; 

   // Start in full screen mode 
   bool m_SplitScreen = false; 

   // How much time is left in the current level 
   float m_TimeRemaining = 10; 
   Time m_GameTimeTotal; 

   // Is it time for a new/first level? 
   bool m_NewLevelRequired = true; 

 // The vertex array for the level tiles
   VertexArray m_VALevel;
   // The 2d array with the map for the level
   // A pointer to a pointer
   int** m_ArrayLevel =  NULL;
   // Texture for the level tiles
   Texture m_TextureTiles; 
   // Private functions for internal use only 
   void input(); 
   void update(float dtAsSeconds); 
   void draw();    

 // Load a new level
   void loadLevel(); 

public: 
   // The Engine constructor 
   Engine(); 

   ... 
   ...       
   ... 

```

您可以在前面的代码中看到以下内容：

+   我们包含了`LevelManager.h`文件

+   我们添加了一个名为`m_LM`的`LevelManager`实例

+   我们添加了一个名为`m_VALevel`的`VertexArray`

+   我们添加了一个指向`int`的指针，它将保存从`nextLevel`返回的二维数组

+   我们为精灵表添加了一个新的`Texture`对象

+   我们添加了`loadLevel`函数的声明，我们现在将编写这个函数

在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，突出显示（单击左键）**C++文件（** `.cpp` **）**，然后在**名称**字段中键入`LoadLevel.cpp`。最后，单击**添加**按钮。我们现在准备编写`loadLevel`函数。

将`loadLevel`函数的代码添加到`LoadLevel.cpp`文件中，然后我们可以讨论它：

```cpp
#include "stdafx.h" 
#include "Engine.h" 

void Engine::loadLevel() 
{ 
   m_Playing = false; 

   // Delete the previously allocated memory 
   for (int i = 0; i < m_LM.getLevelSize().y; ++i) 
   { 
      delete[] m_ArrayLevel[i]; 

   } 
   delete[] m_ArrayLevel; 

   // Load the next 2d array with the map for the level 
   // And repopulate the vertex array as well 
   m_ArrayLevel = m_LM.nextLevel(m_VALevel); 

   // How long is this new time limit 
   m_TimeRemaining = m_LM.getTimeLimit(); 

   // Spawn Thomas and Bob 
   m_Thomas.spawn(m_LM.getStartPosition(), GRAVITY); 
   m_Bob.spawn(m_LM.getStartPosition(), GRAVITY); 

   // Make sure this code isn't run again 
   m_NewLevelRequired = false; 
} 

```

首先，我们将`m_Playing`设置为 false，以阻止更新函数的部分执行。接下来，我们循环遍历`m_ArrayLevel`中的所有水平数组并删除它们。在`for`循环之后，我们删除`m_ArrayLevel`。

代码`m_ArrayLevel = m_LM.nextLevel(m_VALevel)`调用`nextLevel`，准备`VertexArray`和`m_VALevel`，以及二维`m_ArrayLevel`数组。关卡已经设置好，准备就绪。

通过调用`getTimeLimit`来初始化`m_TimeRemaining`，并使用`spawn`函数生成 Thomas 和 Bob，以及从`getStartPosition`返回的值。

最后，`m_NewLevelRequired`设置为`false`。正如我们将在几页后看到的，将`m_NewLevelRequired`设置为`true`会导致调用`loadLevel`。我们只想运行这个函数一次。

# 更新引擎

打开`Engine.cpp`文件，并在`Engine`构造函数的末尾添加突出显示的代码以加载精灵表纹理：

```cpp
Engine::Engine() 
{ 
   // Get the screen resolution and create an SFML window and View 
   Vector2f resolution; 
   resolution.x = VideoMode::getDesktopMode().width; 
   resolution.y = VideoMode::getDesktopMode().height; 

   m_Window.create(VideoMode(resolution.x, resolution.y), 
      "Thomas was late", 
      Style::Fullscreen); 

   // Initialize the full screen view 
   m_MainView.setSize(resolution); 
   m_HudView.reset( 
      FloatRect(0, 0, resolution.x, resolution.y)); 

   // Inititialize the split-screen Views 
   m_LeftView.setViewport( 
      FloatRect(0.001f, 0.001f, 0.498f, 0.998f)); 

   m_RightView.setViewport( 
      FloatRect(0.5f, 0.001f, 0.499f, 0.998f)); 

   m_BGLeftView.setViewport( 
      FloatRect(0.001f, 0.001f, 0.498f, 0.998f)); 

   m_BGRightView.setViewport( 
      FloatRect(0.5f, 0.001f, 0.499f, 0.998f)); 

   // Can this graphics card use shaders? 
   if (!sf::Shader::isAvailable()) 
   { 
      // Time to get a new PC 
      m_Window.close(); 
   } 

   m_BackgroundTexture = TextureHolder::GetTexture( 
      "graphics/background.png"); 

   // Associate the sprite with the texture 
   m_BackgroundSprite.setTexture(m_BackgroundTexture); 

 // Load the texture for the background vertex array
   m_TextureTiles = TextureHolder::GetTexture("graphics/tiles_sheet.png"); 
} 

```

在前面的代码中，我们只是将精灵表加载到`m_TextureTiles`中。

打开`Update.cpp`文件并进行以下突出显示的更改和添加：

```cpp
void Engine::update(float dtAsSeconds) 
{ 
   if (m_NewLevelRequired) 
   { 
      // These calls to spawn will be moved to a new 
      // LoadLevel function soon 
      // Spawn Thomas and Bob 
 //m_Thomas.spawn(Vector2f(0,0), GRAVITY);
      //m_Bob.spawn(Vector2f(100, 0), GRAVITY); 

      // Make sure spawn is called only once 
 //m_TimeRemaining = 10;
      //m_NewLevelRequired = false;

      // Load a level
      loadLevel();        
   } 

```

实际上，我们应该删除而不是注释掉我们不再使用的行。我只是以这种方式向你展示，以便更清楚地看到更改。在前面的`if`语句中，应该只有对`loadLevel`的调用。

最后，在我们可以看到本章迄今为止的工作结果之前，打开`Draw.cpp`文件并进行以下突出显示的添加以绘制表示关卡的顶点数组：

```cpp
void Engine::draw() 
{ 
   // Rub out the last frame 
   m_Window.clear(Color::White); 

   if (!m_SplitScreen) 
   { 
      // Switch to background view 
      m_Window.setView(m_BGMainView); 
      // Draw the background 
      m_Window.draw(m_BackgroundSprite); 
      // Switch to m_MainView 
      m_Window.setView(m_MainView);     

 // Draw the Level
      m_Window.draw(m_VALevel, &m_TextureTiles); 

      // Draw thomas 
      m_Window.draw(m_Thomas.getSprite()); 

      // Draw thomas 
      m_Window.draw(m_Bob.getSprite()); 
   } 
   else 
   { 
      // Split-screen view is active 

      // First draw Thomas' side of the screen 

      // Switch to background view 
      m_Window.setView(m_BGLeftView); 
      // Draw the background 
      m_Window.draw(m_BackgroundSprite); 
      // Switch to m_LeftView 
      m_Window.setView(m_LeftView); 

 // Draw the Level
      m_Window.draw(m_VALevel, &m_TextureTiles); 

      // Draw thomas 
      m_Window.draw(m_Bob.getSprite()); 

      // Draw thomas 
      m_Window.draw(m_Thomas.getSprite()); 

      // Now draw Bob's side of the screen 

      // Switch to background view 
      m_Window.setView(m_BGRightView); 
      // Draw the background 
      m_Window.draw(m_BackgroundSprite); 
      // Switch to m_RightView 
      m_Window.setView(m_RightView); 

 // Draw the Level
     m_Window.draw(m_VALevel, &m_TextureTiles); 

      // Draw thomas 
      m_Window.draw(m_Thomas.getSprite()); 

      // Draw bob 
      m_Window.draw(m_Bob.getSprite()); 

   } 

   // Draw the HUD 
   // Switch to m_HudView 
   m_Window.setView(m_HudView); 

   // Show everything we have just drawn 
   m_Window.display(); 
} 

```

请注意，我们需要为所有屏幕选项（全屏，左侧和右侧）绘制`VertexArray`。

现在你可以运行游戏了。不幸的是，Thomas 和 Bob 直接穿过了我们精心设计的所有平台。因此，我们无法尝试通过关卡并打败时间。

# 碰撞检测

我们将使用矩形相交和 SFML 相交函数来处理碰撞检测。在这个项目中的不同之处在于，我们将把碰撞检测代码抽象成自己的函数，而 Thomas 和 Bob，正如我们已经看到的，有多个矩形（`m_Head`，`m_Feet`，`m_Left`，`m_Right`）需要检查碰撞。

## 编写 detectCollisions 函数

要清楚，这个函数是 Engine 类的一部分。打开`Engine.h`文件，并添加一个名为`detectCollisions`的函数声明。这在以下代码片段中突出显示：

```cpp
   // Private functions for internal use only 
   void input(); 
   void update(float dtAsSeconds); 
   void draw(); 

   // Load a new level 
   void loadLevel(); 

 // Run will call all the private functions
   bool detectCollisions(PlayableCharacter& character); 

public: 
   // The Engine constructor 
   Engine(); 

```

从签名中可以看出，`detectCollision`函数接受一个多态参数，即`PlayerCharacter`对象。正如我们所知，`PlayerCharacter`是抽象的，永远不能被实例化。但是，我们可以通过`Thomas`和`Bob`类继承它。我们将能够将`m_Thomas`或`m_Bob`传递给`detectCollisions`。

在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，通过左键单击突出显示（高亮）**C++文件（** `.cpp` **）**，然后在**名称**字段中键入`DetectCollisions.cpp`。最后，单击**添加**按钮。我们现在准备编写`detectCollisions`函数。

将以下代码添加到`DetectCollisions.cpp`。请注意，这只是该函数的第一部分：

```cpp
#include "stdafx.h" 
#include "Engine.h" 

bool Engine::detectCollisions(PlayableCharacter& character) 
{ 
   bool reachedGoal = false; 
   // Make a rect for all his parts 
   FloatRect detectionZone = character.getPosition(); 

   // Make a FloatRect to test each block 
   FloatRect block; 

   block.width = TILE_SIZE; 
   block.height = TILE_SIZE; 

   // Build a zone around thomas to detect collisions 
   int startX = (int)(detectionZone.left / TILE_SIZE) - 1; 
   int startY = (int)(detectionZone.top / TILE_SIZE) - 1; 
   int endX = (int)(detectionZone.left / TILE_SIZE) + 2; 

   // Thomas is quite tall so check a few tiles vertically 
   int endY = (int)(detectionZone.top / TILE_SIZE) + 3; 

   // Make sure we don't test positions lower than zero 
   // Or higher than the end of the array 
   if (startX < 0)startX = 0; 
   if (startY < 0)startY = 0; 
   if (endX >= m_LM.getLevelSize().x) 
      endX = m_LM.getLevelSize().x; 
   if (endY >= m_LM.getLevelSize().y) 
      endY = m_LM.getLevelSize().y; 

```

首先，我们声明一个名为`reachedGoal`的布尔值。这是`detectCollisions`函数返回给调用代码的值。它被初始化为`false`。

接下来，我们声明一个名为`detectionZone`的`FloatRect`，并用表示角色精灵整个矩形的相同矩形对其进行初始化。请注意，我们实际上不会使用这个矩形进行交集测试。之后，我们声明另一个名为`block`的`FloatRect`。我们将`block`初始化为一个 50x50 的矩形。我们很快就会看到`block`的使用。

接下来，我们将看到如何使用`detectionZone`。我们通过扩展`detectionZone`周围的区域几个方块来初始化四个`int`变量`startX`、`startY`、`endX`和`endY`。在接下来的四个`if`语句中，我们检查不可能尝试在不存在的瓦片上进行碰撞检测。我们通过确保我们永远不会检查小于零或大于`getLevelSize().x`或`.y`返回的值来实现这一点。

之前的所有代码所做的是创建一个用于碰撞检测的区域。在角色远离数百或数千像素的方块上进行碰撞检测是没有意义的。此外，如果我们尝试在数组位置不存在的地方进行碰撞检测（小于零或大于`getLevelSize()...`），游戏将崩溃。

接下来，添加处理玩家掉出地图的代码：

```cpp
   // Has the character fallen out of the map? 
   FloatRect level(0, 0,  
      m_LM.getLevelSize().x * TILE_SIZE,  
      m_LM.getLevelSize().y * TILE_SIZE); 

   if (!character.getPosition().intersects(level)) 
   { 
      // respawn the character 
      character.spawn(m_LM.getStartPosition(), GRAVITY); 
   } 

```

角色要停止下落，必须与平台发生碰撞。因此，如果玩家移出地图（没有平台的地方），它将不断下落。之前的代码检查角色是否*不*与`FloatRect`、`level`相交。如果不是，则它已经掉出地图，`spawn`函数将其发送回起点。

添加以下相当大的代码，然后我们将逐步解释它的作用：

```cpp
   // Loop through all the local blocks 
   for (int x = startX; x < endX; x++) 
   { 
      for (int y = startY; y < endY; y++) 
      { 
         // Initialize the starting position of the current block 
         block.left = x * TILE_SIZE; 
         block.top = y * TILE_SIZE; 

         // Has character been burnt or drowned? 
         // Use head as this allows him to sink a bit 
         if (m_ArrayLevel[y][x] == 2 || m_ArrayLevel[y][x] == 3) 
         { 
            if (character.getHead().intersects(block)) 
            { 
               character.spawn(m_LM.getStartPosition(), GRAVITY); 
               // Which sound should be played? 
               if (m_ArrayLevel[y][x] == 2)// Fire, ouch! 
               { 
                  // Play a sound 

               } 
               else // Water 
               { 
                  // Play a sound 
               } 
            } 
         } 

         // Is character colliding with a regular block 
         if (m_ArrayLevel[y][x] == 1) 
         { 

            if (character.getRight().intersects(block)) 
            { 
               character.stopRight(block.left); 
            } 
            else if (character.getLeft().intersects(block)) 
            { 
               character.stopLeft(block.left); 
            } 

            if (character.getFeet().intersects(block)) 
            { 
               character.stopFalling(block.top); 
            } 
            else if (character.getHead().intersects(block)) 
            { 
               character.stopJump(); 
            } 
         } 

         // More collision detection here once we have  
         // learned about particle effects 

         // Has the character reached the goal? 
         if (m_ArrayLevel[y][x] == 4) 
         { 
            // Character has reached the goal 
            reachedGoal = true; 
         } 

      } 

   } 

```

之前的代码使用相同的技术做了三件事。它循环遍历`startX`、`endX`和`startY`、`endY`之间包含的所有值。对于每次循环，它检查并执行以下操作：

+   角色是否被烧伤或淹死？代码`if (m_ArrayLevel[y][x] == 2 || m_ArrayLevel[y][x] == 3)`确定当前被检查的位置是否是火瓦或水瓦。如果角色的头与这些瓦片之一相交，玩家将重新生成。我们还在准备在下一章节中添加声音的空的`if…else`块。

+   角色是否触碰到普通瓦片？代码`if (m_ArrayLevel[y][x] == 1)`确定当前被检查的位置是否持有普通瓦片。如果它与表示角色各个身体部位的任何矩形相交，相关的函数将被调用（`stopRight`、`stopLeft`、`stopFalling`和`stopJump`）。传递给这些函数的值以及函数如何使用这些值重新定位角色是非常微妙的。虽然不需要仔细检查这些值来理解代码，但您可能希望查看传递的值，然后参考上一章节`PlayableCharacter`类的适当函数。这将帮助您准确理解发生了什么。

+   角色是否触碰到目标瓦片？这是通过代码`if (m_ArrayLevel[y][x] == 4)`来确定的。我们只需要将`reachedGoal`设置为`true`。`Engine`类的`update`函数将跟踪托马斯和鲍勃是否同时达到目标。我们将在`update`中编写这段代码，就在一分钟内。

将最后一行代码添加到`detectCollisions`函数中：

```cpp
   // All done, return, whether or not a new level might be required 
   return reachedGoal; 
} 

```

前面的代码返回`reachedGoal`，以便调用代码可以跟踪并适当地响应如果两个角色同时达到目标。

现在我们所需要做的就是每帧每个角色调用一次`detectCollision`函数。在`Update.cpp`文件的`if(m_Playing)`代码块中添加以下突出显示的代码：

```cpp
if (m_Playing) 
{ 
   // Update Thomas 
   m_Thomas.update(dtAsSeconds); 

   // Update Bob 
   m_Bob.update(dtAsSeconds); 

 // Detect collisions and see if characters
   // have reached the goal tile
   // The second part of the if condition is only executed
   // when thomas is touching the home tile
   if (detectCollisions(m_Thomas) && detectCollisions(m_Bob))
   {
     // New level required
     m_NewLevelRequired = true;
     // Play the reach goal sound
   }
   else
   {
     // Run bobs collision detection
     detectCollisions(m_Bob);
   } 

   // Count down the time the player has left 
   m_TimeRemaining -= dtAsSeconds; 

   // Have Thomas and Bob run out of time? 
   if (m_TimeRemaining <= 0) 
   { 
      m_NewLevelRequired = true; 
   } 

}// End if playing 

```

前面的代码调用`detectCollision`函数并检查鲍勃和托马斯是否同时达到目标。如果是，下一关将通过将`m_NewLevelRequired`设置为`true`来准备好。

你可以运行游戏并走在平台上。你可以达到目标并开始新的关卡。此外，第一次，跳跃按钮（*W*或箭头上）将起作用。

如果你达到目标，下一关将加载。如果你达到最后一关的目标，那么第一关将以减少 10%的时间限制加载。当然，由于我们还没有构建 HUD，所以没有时间或当前关卡的视觉反馈。我们将在下一章中完成。

然而，许多关卡需要托马斯和鲍勃作为一个团队合作。更具体地说，托马斯和鲍勃需要能够爬到彼此的头上。

## 更多碰撞检测

在`Update.cpp`文件中添加前面添加的代码后面，`if (m_Playing)`部分内添加以下代码：

```cpp
if (m_Playing) 
{ 
   // Update Thomas 
   m_Thomas.update(dtAsSeconds); 

   // Update Bob 
   m_Bob.update(dtAsSeconds); 

   // Detect collisions and see if characters
   // have reached the goal tile 
   // The second part of the if condition is only executed 
   // when thomas is touching the home tile 
   if (detectCollisions(m_Thomas) && detectCollisions(m_Bob)) 
   { 
      // New level required 
      m_NewLevelRequired = true; 

      // Play the reach goal sound 

   } 
   else 
   { 
      // Run bobs collision detection 
      detectCollisions(m_Bob); 
   } 

 // Let bob and thomas jump on each others heads
   if (m_Bob.getFeet().intersects(m_Thomas.getHead()))
   {
     m_Bob.stopFalling(m_Thomas.getHead().top);
   }
   else if (m_Thomas.getFeet().intersects(m_Bob.getHead()))
   {
     m_Thomas.stopFalling(m_Bob.getHead().top);
   } 

   // Count down the time the player has left 
   m_TimeRemaining -= dtAsSeconds; 

   // Have Thomas and Bob run out of time? 
   if (m_TimeRemaining <= 0) 
   { 
      m_NewLevelRequired = true; 
   } 

}// End if playing 

```

你可以再次运行游戏并站在托马斯和鲍勃的头上，以到达以前无法到达的难以到达的地方：

![更多碰撞检测](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_14_009.jpg)

# 摘要

本章中有相当多的代码。我们学会了如何从文件中读取并将文本字符串转换为 char，然后转换为`int`。一旦我们有了一个二维数组的`int`，我们就能够填充一个`VertexArray`来实际显示屏幕上的关卡。然后我们使用完全相同的二维数组 int 来实现碰撞检测。我们使用矩形交集，就像我们在僵尸竞技场项目中所做的那样，尽管这次，为了更精确，我们给每个角色四个碰撞区域，分别代表他们的头部、脚部和左右两侧。

现在游戏完全可玩，我们需要在屏幕上表示游戏的状态（得分和时间）。在下一章中，我们将实现 HUD，以及比我们目前使用的更高级的音效。


# 第十五章：声音空间化和 HUD

在本章中，我们将添加所有的音效和 HUD。我们在之前的两个项目中都做过这个，但这次我们会以稍微不同的方式来做。我们将探讨声音空间化的概念以及 SFML 如何使这个本来复杂的概念变得简单易行；此外，我们将构建一个 HUD 类来封装将信息绘制到屏幕上的代码。

我们将按照以下顺序完成这些任务：

+   什么是空间化？

+   SFML 如何处理空间化

+   构建一个`SoundManager`类

+   部署发射器

+   使用`SoundManager`类

+   构建一个`HUD`类

+   使用`HUD`类

# 什么是空间化？

空间化是使某物相对于其所在的空间或内部的行为。在我们的日常生活中，自然界中的一切默认都是空间化的。如果一辆摩托车从左到右呼啸而过，我们会听到声音从一侧变得微弱到响亮，当它经过时，它会在另一只耳朵中变得更加显著，然后再次消失在远处。如果有一天早上醒来，世界不再是空间化的，那将是异常奇怪的。

如果我们能让我们的视频游戏更像现实世界，我们的玩家就能更加沉浸其中。如果玩家能在远处微弱地听到僵尸的声音，而当它们靠近时，它们的不人道的哀嚎声会从一个方向或另一个方向变得更响亮，我们的僵尸游戏会更有趣。

很明显，空间化的数学将会很复杂。我们如何计算特定扬声器中的声音有多大声，基于声音来自的方向以及听者（声音的听者）到发出声音的物体（发射器）的距离？

幸运的是，SFML 为我们处理了所有复杂的事情。我们只需要熟悉一些技术术语，然后就可以开始使用 SFML 来对我们的音效进行空间化。

## 发射器、衰减和听众

为了让 SFML 能够正常工作，我们需要了解一些信息。我们需要知道声音在我们的游戏世界中来自哪里。这个声音的来源被称为**发射器**。在游戏中，发射器可以是僵尸、车辆，或者在我们当前的项目中，是一个火焰图块。我们已经在游戏中跟踪了物体的位置，所以给 SFML 发射器位置将会非常简单。

我们需要意识到的下一个因素是**衰减**。衰减是波动恶化的速率。你可以简化这个说法，并将其具体化为声音，即衰减是声音减小的速度。这在技术上并不准确，但对于本章的目的来说，这已经足够好了。

我们需要考虑的最后一个因素是**听众**。当 SFML 对声音进行空间化时，它是相对于什么进行空间化的？在大多数游戏中，合理的做法是使用玩家角色。在我们的游戏中，我们将使用 Thomas。

# SFML 如何处理空间化

SFML 有许多函数可以让我们处理发射器、衰减和听众。让我们先假设一下，然后我们将编写一些代码，真正为我们的项目添加空间化声音。

我们可以设置一个准备播放的音效，就像我们经常做的那样，如下所示：

```cpp
// Declare SoundBuffer in the usual way 
SoundBuffer zombieBuffer; 
// Declare a Sound object as-per-usual 
Sound zombieSound; 
// Load the sound from a file like we have done so often 
zombieBuffer.loadFromFile("sound/zombie_growl.wav"); 
// Associate the Sound object with the Buffer 
zombieSound.setBuffer(zombieBuffer); 

```

我们可以使用`setPosition`函数来设置发射器的位置，如下面的代码所示：

```cpp
// Set the horizontal and vertical positions of the emitter 
// In this case the emitter is a zombie 
// In the Zombie Arena project we could have used  
// getPosition().x and getPosition().y 
// These values are arbitrary 
float x = 500; 
float y = 500; 
zombieSound.setPosition(x, y, 0.0f); 

```

如前面的代码注释中建议的，你如何获取发射器的坐标可能取决于游戏的类型。就像在 Zombie Arena 项目中所示的那样，这将是非常简单的。当我们在这个项目中设置位置时，我们将面临一些挑战。

我们可以使用以下代码设置衰减级别：

```cpp
zombieSound.setAttenuation(15); 

```

实际的衰减级别可能有些模糊。您希望玩家得到的效果可能与基于衰减的距离减小音量的准确科学公式不同。获得正确的衰减级别通常是通过实验来实现的。一般来说，衰减级别越高，声音级别降至静音的速度就越快。

此外，您可能希望在发射器周围设置一个音量完全不衰减的区域。如果该功能在一定范围之外不合适，或者您有大量的声源并且不想过度使用该功能，您可以这样做。为此，我们可以使用`setMinimumDistance`函数，如下所示：

```cpp
zombieSound.setMinDistance(150); 

```

通过上一行代码，衰减直到听众离发射器`150`像素/单位远才开始计算。

SFML 库中的一些其他有用函数包括`setLoop`函数。当传入 true 作为参数时，此函数将告诉 SFML 在循环播放声音时保持播放，如下面的代码所示：

```cpp
zombieSound.setLoop(true); 

```

声音将继续播放，直到我们使用以下代码结束它：

```cpp
zombieSound.stop(); 

```

不时地，我们会想要知道声音的状态（正在播放或已停止）。我们可以使用`getStatus`函数来实现这一点，如下面的代码所示：

```cpp
if (zombieSound.getStatus() == Sound::Status::Stopped) 
{ 
   // The sound is NOT playing 
   // Take whatever action here 
} 

if (zombieSound.getStatus() == Sound::Status::Playing) 
{ 
   // The sound IS playing 
   // Take whatever action here 
} 

```

在使用 SFML 进行声音空间化的最后一个方面我们需要涵盖的是听众在哪里？我们可以使用以下代码设置听众的位置：

```cpp
// Where is the listener?  
// How we get the values of x and y varies depending upon the game 
// In the Zombie Arena game or the Thomas Was Late game 
// We can use getPosition() 
Listener::setPosition(m_Thomas.getPosition().x,  
   m_Thomas.getPosition().y, 0.0f); 

```

上述代码将使所有声音相对于该位置播放。这正是我们需要的远处火瓦或迫近的僵尸的咆哮声，但对于像跳跃这样的常规音效来说，这是一个问题。我们可以开始处理一个发射器来定位玩家的位置，但 SFML 为我们简化了事情。每当我们想播放*正常*声音时，我们只需调用`setRelativeToListener`，如下面的代码所示，然后以与迄今为止完全相同的方式播放声音。以下是我们可能播放*正常*、非空间化跳跃音效的方式：

```cpp
jumpSound.setRelativeToListener(true); 
jumpSound.play(); 

```

我们只需要在播放任何空间化声音之前再次调用`Listener::setPosition`。

现在我们有了广泛的 SFML 声音函数，我们准备制作一些真正的空间化噪音。

# 构建 SoundManager 类

您可能还记得在上一个项目中，所有的声音代码占用了相当多的行数。现在考虑到空间化，它将变得更长。为了使我们的代码易于管理，我们将编写一个类来管理所有声音效果的播放。此外，为了帮助我们进行空间化，我们还将向 Engine 类添加一个函数，但我们将在后面的章节讨论。

## 编写 SoundManager.h

让我们开始编写和检查头文件。

在**解决方案资源管理器**中右键单击**标头文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，通过左键单击**标头文件（** `.h` **）**，然后在**名称**字段中键入`SoundManager.h`。最后，单击**添加**按钮。现在我们准备为`SoundManager`类编写头文件。

添加并检查以下代码：

```cpp
#pragma once 
#include <SFML/Audio.hpp> 

using namespace sf; 

class SoundManager 
{ 
   private: 
      // The buffers 
      SoundBuffer m_FireBuffer; 
      SoundBuffer m_FallInFireBuffer; 
      SoundBuffer m_FallInWaterBuffer; 
      SoundBuffer m_JumpBuffer; 
      SoundBuffer m_ReachGoalBuffer; 

      // The Sounds 
      Sound m_Fire1Sound; 
      Sound m_Fire2Sound; 
      Sound m_Fire3Sound; 
      Sound m_FallInFireSound; 
      Sound m_FallInWaterSound; 
      Sound m_JumpSound; 
      Sound m_ReachGoalSound; 

      // Which sound should we use next, fire 1, 2 or 3 
      int m_NextSound = 1; 

   public: 

      SoundManager(); 

      void playFire(Vector2f emitterLocation,  
         Vector2f listenerLocation); 

      void playFallInFire(); 
      void playFallInWater(); 
      void playJump(); 
      void playReachGoal(); 
}; 

```

在我们刚刚添加的代码中没有什么棘手的地方。有五个`SoundBuffer`对象和八个`Sound`对象。其中三个`Sound`对象将播放相同的`SoundBuffer`。这解释了不同数量的`Sound`/`SoundBuffer`对象的原因。我们这样做是为了能够同时播放多个咆哮声效，并具有不同的空间化参数。

请注意，有一个`m_NextSound`变量，将帮助我们跟踪这些潜在同时发生的声音中我们应该下一个使用哪一个。

有一个构造函数`SoundManager`，在那里我们将设置所有的音效，还有五个函数将播放音效。其中四个函数只是简单地播放*普通*音效，它们的代码将非常简单。

其中一个函数`playFire`将处理空间化的音效，并且会更加深入。注意`playFire`函数的参数。它接收一个`Vector2f`，这是发射器的位置，和第二个`Vector2f`，这是听众的位置。

## 编写 SoundManager.cpp 文件

现在我们可以编写函数定义了。构造函数和`playFire`函数有相当多的代码，所以我们将分别查看它们。其他函数都很简短，所以我们将一次处理它们。

在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，通过左键单击**C++文件（**`.cpp`**）**，然后在**名称**字段中键入`SoundManager.cpp`。最后，单击**添加**按钮。现在我们准备好为`SoundManager`类编写`.cpp`文件了。

### 编写构造函数

为`SoundManager.cpp`添加以下包含指令和构造函数的代码：

```cpp
#include "stdafx.h" 
#include "SoundManager.h" 
#include <SFML/Audio.hpp> 

using namespace sf; 

SoundManager::SoundManager() 
{ 
   // Load the sound in to the buffers 
   m_FireBuffer.loadFromFile("sound/fire1.wav"); 
   m_FallInFireBuffer.loadFromFile("sound/fallinfire.wav"); 
   m_FallInWaterBuffer.loadFromFile("sound/fallinwater.wav"); 
   m_JumpBuffer.loadFromFile("sound/jump.wav"); 
   m_ReachGoalBuffer.loadFromFile("sound/reachgoal.wav"); 

   // Associate the sounds with the buffers 
   m_Fire1Sound.setBuffer(m_FireBuffer); 
   m_Fire2Sound.setBuffer(m_FireBuffer); 
   m_Fire3Sound.setBuffer(m_FireBuffer); 
   m_FallInFireSound.setBuffer(m_FallInFireBuffer); 
   m_FallInWaterSound.setBuffer(m_FallInWaterBuffer); 
   m_JumpSound.setBuffer(m_JumpBuffer); 
   m_ReachGoalSound.setBuffer(m_ReachGoalBuffer); 

   // When the player is 50 pixels away sound is full volume 
   float minDistance = 150; 
   // The sound reduces steadily as the player moves further away 
   float attenuation = 15; 

   // Set all the attenuation levels 
   m_Fire1Sound.setAttenuation(attenuation); 
   m_Fire2Sound.setAttenuation(attenuation); 
   m_Fire3Sound.setAttenuation(attenuation); 

   // Set all the minimum distance levels 
   m_Fire1Sound.setMinDistance(minDistance); 
   m_Fire2Sound.setMinDistance(minDistance); 
   m_Fire3Sound.setMinDistance(minDistance); 

   // Loop all the fire sounds 
   // when they are played 
   m_Fire1Sound.setLoop(true); 
   m_Fire2Sound.setLoop(true); 
   m_Fire3Sound.setLoop(true); 
} 

```

在前面的代码中，我们将五个声音文件加载到五个`SoundBuffer`对象中。接下来，我们将八个`Sound`对象与其中一个`SoundBuffer`对象关联起来。请注意，`m_Fire1Sound`、`m_Fire2Sound`和`m_Fire3Sound`都将从同一个`SoundBuffer`，`m_FireBuffer`中播放。

接下来，我们设置了三个火焰声音的衰减和最小距离。

### 提示

通过实验得出了分别为`150`和`15`的值。一旦游戏运行起来，我鼓励你通过改变这些值来进行实验，看（或者说听）听到的差异。

最后，对于构造函数，我们在每个与火相关的`Sound`对象上使用了`setLoop`函数。现在当我们调用`play`时，它们将持续播放。

### 编写 playFire 函数

添加下面代码中显示的`playFire`函数，然后我们可以讨论它：

```cpp
void SoundManager::playFire( 
   Vector2f emitterLocation, Vector2f listenerLocation) 
{ 
   // Where is the listener? Thomas. 
   Listener::setPosition(listenerLocation.x,  
      listenerLocation.y, 0.0f); 

   switch(m_NextSound) 
   { 

   case 1: 
      // Locate/move the source of the sound 
      m_Fire1Sound.setPosition(emitterLocation.x,  
         emitterLocation.y, 0.0f); 

      if (m_Fire1Sound.getStatus() == Sound::Status::Stopped) 
      { 
         // Play the sound, if its not already 
         m_Fire1Sound.play(); 
      } 
      break; 

   case 2: 
      // Do the same as previous for the second sound 
      m_Fire2Sound.setPosition(emitterLocation.x,  
         emitterLocation.y, 0.0f); 

      if (m_Fire2Sound.getStatus() == Sound::Status::Stopped) 
      { 
         m_Fire2Sound.play(); 
      } 
      break; 

   case 3: 
      // Do the same as previous for the third sound 
      m_Fire3Sound.setPosition(emitterLocation.x,  
         emitterLocation.y, 0.0f); 

      if (m_Fire3Sound.getStatus() == Sound::Status::Stopped) 
      { 
         m_Fire3Sound.play(); 
      } 
      break; 
   } 

   // Increment to the next fire sound 
   m_NextSound++; 

   // Go back to 1 when the third sound has been started 
   if (m_NextSound > 3) 
   { 
      m_NextSound = 1; 
   } 
} 

```

我们要做的第一件事是调用`Listener::setPosition`，并根据作为参数传入的`Vector2f`设置听众的位置。

接下来，代码根据`m_NextSound`的值进入了一个`switch`块。每个`case`语句都做了完全相同的事情，但是针对`m_Fire1Sound`、`m_Fire2Sound`或`m_Fire3Sound`。

在每个`case`块中，我们使用传入的参数调用`setPosition`函数来设置发射器的位置。每个`case`块中代码的下一部分检查音效当前是否已停止，如果是，则播放音效。我们很快就会看到如何得到传递到这个函数中的发射器和听众的位置。

`playFire`函数的最后部分增加了`m_NextSound`，并确保它只能等于 1、2 或 3，这是`switch`块所需的。

### 编写其余的 SoundManager 函数

添加这四个简单的函数：

```cpp
void SoundManager::playFallInFire() 
{ 
   m_FallInFireSound.setRelativeToListener(true); 
   m_FallInFireSound.play(); 
} 

void SoundManager::playFallInWater() 
{ 
   m_FallInWaterSound.setRelativeToListener(true); 
   m_FallInWaterSound.play(); 
} 

void SoundManager::playJump() 
{ 
   m_JumpSound.setRelativeToListener(true); 
   m_JumpSound.play(); 
} 

void SoundManager::playReachGoal() 
{ 
   m_ReachGoalSound.setRelativeToListener(true); 
   m_ReachGoalSound.play(); 
} 

```

`playFallInFire`、`playFallInWater`和`playReachGoal`函数只做两件事。首先，它们各自调用`setRelativeToListener`，所以音效不是空间化的，使音效变得*普通*，而不是定向的，然后它们调用适当的`Sound`对象上的`play`。

这就结束了`SoundManager`类。现在我们可以在`Engine`类中使用它。

# 将 SoundManager 添加到游戏引擎

打开`Engine.h`文件，并添加一个新的`SoundManager`类的实例，如下面突出显示的代码所示：

```cpp
#pragma once 
#include <SFML/Graphics.hpp> 
#include "TextureHolder.h" 
#include "Thomas.h" 
#include "Bob.h" 
#include "LevelManager.h" 
#include "SoundManager.h" 

using namespace sf; 

class Engine 
{ 
private: 
   // The texture holder 
   TextureHolder th; 

   // Thomas and his friend, Bob 
   Thomas m_Thomas; 
   Bob m_Bob; 

   // A class to manage all the levels 
   LevelManager m_LM; 

 // Create a SoundManager
   SoundManager m_SM; 

   const int TILE_SIZE = 50; 
   const int VERTS_IN_QUAD = 4; 

```

在这一点上，我们可以使用`m_SM`来调用各种`play...`函数。不幸的是，仍然有一些工作要做，以便管理发射器（火砖）的位置。

# 填充声音发射器

打开`Engine.h`文件，并为`populateEmitters`函数添加一个新的原型和一个新的 STL`vector`的`Vector2f`对象：

```cpp
   ... 
   ... 
   ... 
   // Run will call all the private functions 
   bool detectCollisions(PlayableCharacter& character); 

 // Make a vector of the best places to emit sounds from
   void populateEmitters(vector <Vector2f>& vSoundEmitters,
     int** arrayLevel);

   // A vector of Vector2f for the fire emitter locations
   vector <Vector2f> m_FireEmitters; 

public: 
   ... 
   ... 
   ... 

```

`populateEmitters`函数以`Vector2f`对象的`vector`和指向`int`的指针作为参数。这个`vector`将保存每个发射器在一个级别中的位置，而数组是我们的二维数组，它保存了一个级别的布局。

## 编写 populateEmitters 函数

`populateEmitters`函数的工作是扫描`arrayLevel`的所有元素，并决定在哪里放置发射器。它将其结果存储在`m_FireEmitters`中。

在“解决方案资源管理器”中右键单击“源文件”，然后选择“添加”|“新项目”。在“添加新项目”窗口中，选择（通过左键单击）“C++文件”（.cpp），然后在“名称”字段中输入`PopulateEmitters.cpp`。最后，单击“添加”按钮。现在我们可以编写新函数`populateEmitters`。

添加完整的代码；确保在编写代码时仔细研究代码，然后我们可以讨论它。

```cpp
#include "stdafx.h" 
#include "Engine.h" 

using namespace sf; 
using namespace std; 

void Engine::populateEmitters( 
   vector <Vector2f>& vSoundEmitters, int** arrayLevel) 
{ 

   // Make sure the vector is empty 
   vSoundEmitters.empty(); 

   // Keep track of the previous emitter 
   // so we don't make too many 
   FloatRect previousEmitter; 

   // Search for fire in the level 
   for (int x = 0; x < (int)m_LM.getLevelSize().x; x++) 
   { 
      for (int y = 0; y < (int)m_LM.getLevelSize().y; y++) 
      { 
         if (arrayLevel[y][x] == 2)// fire is present 
         { 
            // Skip over any fire tiles too  
            // near a previous emitter 
            if (!FloatRect(x * TILE_SIZE, 
               y * TILE_SIZE, 
               TILE_SIZE, 
               TILE_SIZE).intersects(previousEmitter)) 
            { 
               // Add the coordiantes of this water block 
               vSoundEmitters.push_back( 
                  Vector2f(x * TILE_SIZE, y * TILE_SIZE)); 

               // Make a rectangle 6 blocks x 6 blocks, 
               // so we don't make any more emitters  
               // too close to this one 
               previousEmitter.left = x * TILE_SIZE; 
               previousEmitter.top = y * TILE_SIZE; 
               previousEmitter.width = TILE_SIZE * 6; 
               previousEmitter.height = TILE_SIZE * 6; 
            } 

         } 

      } 

   } 
   return; 

} 

```

一些代码乍一看可能会很复杂。理解我们用来选择发射器位置的技术将使其变得更简单。在我们的级别中，通常会有大块的火砖。在我设计的一个级别中，有超过 30 个火砖。代码确保在给定的矩形内只有一个发射器。这个矩形存储在`previousEmitter`中，大小为 300 像素乘以 300 像素（TILE_SIZE * 6）。

该代码设置了一个嵌套的`for`循环，循环遍历`arrayLevel`以寻找火砖。当找到一个时，它确保它不与`previousEmitter`相交。只有在这种情况下，它才使用`pushBack`函数向`vSoundEmitters`添加另一个发射器。在这样做之后，它还更新`previousEmitter`以避免得到大量的声音发射器。

让我们制造一些噪音。

# 播放声音

打开`LoadLevel.cpp`文件，并在以下代码中添加对新的`populateEmitters`函数的调用：

```cpp
void Engine::loadLevel() 
{ 
   m_Playing = false; 

   // Delete the previously allocated memory 
   for (int i = 0; i < m_LM.getLevelSize().y; ++i) 
   { 
      delete[] m_ArrayLevel[i]; 

   } 
   delete[] m_ArrayLevel; 

   // Load the next 2d array with the map for the level 
   // And repopulate the vertex array as well 
   m_ArrayLevel = m_LM.nextLevel(m_VALevel); 

 // Prepare the sound emitters
   populateEmitters(m_FireEmitters, m_ArrayLevel); 

   // How long is this new time limit 
   m_TimeRemaining = m_LM.getTimeLimit(); 

   // Spawn Thomas and Bob 
   m_Thomas.spawn(m_LM.getStartPosition(), GRAVITY); 
   m_Bob.spawn(m_LM.getStartPosition(), GRAVITY); 

   // Make sure this code isn't run again 
   m_NewLevelRequired = false; 
} 

```

要添加的第一个声音是跳跃声音。您可能记得键盘处理代码在`Bob`和`Thomas`类的纯虚函数中，而`handleInput`函数在成功启动跳跃时返回`true`。

打开`Input.cpp`文件，并添加高亮代码行，以在 Thomas 或 Bob 成功开始跳跃时播放跳跃声音。

```cpp
// Handle input specific to Thomas 
if (m_Thomas.handleInput()) 
{ 
   // Play a jump sound 
 m_SM.playJump(); 
} 

// Handle input specific to Bob 
if (m_Bob.handleInput()) 
{ 
   // Play a jump sound 
 m_SM.playJump(); 
} 

```

打开`Update.cpp`文件，并添加高亮代码行，以在 Thomas 和 Bob 同时到达当前级别的目标时播放成功的声音。

```cpp
// Detect collisions and see if characters have reached the goal tile 
// The second part of the if condition is only executed 
// when thomas is touching the home tile 
if (detectCollisions(m_Thomas) && detectCollisions(m_Bob)) 
{ 
   // New level required 
   m_NewLevelRequired = true; 

   // Play the reach goal sound 
 m_SM.playReachGoal(); 

} 
else 
{ 
   // Run bobs collision detection 
   detectCollisions(m_Bob); 
} 

```

同样在`Update.cpp`文件中，我们将添加代码来循环遍历`m_FireEmitters`向量，并决定何时需要调用`SoundManager`类的`playFire`函数。

仔细观察新的高亮代码周围的一小部分上下文。在恰当的位置添加这段代码是至关重要的。

```cpp
}// End if playing 

// Check if a fire sound needs to be played
vector<Vector2f>::iterator it;

// Iterate through the vector of Vector2f objects
for (it = m_FireEmitters.begin();it != m_FireEmitters.end(); it++)
{
   // Where is this emitter?
   // Store the location in pos
   float posX = (*it).x;
   float posY = (*it).y;
   // is the emiter near the player?
   // Make a 500 pixel rectangle around the emitter
   FloatRect localRect(posX - 250, posY - 250, 500, 500);

   // Is the player inside localRect?
   if (m_Thomas.getPosition().intersects(localRect))
   {
     // Play the sound and pass in the location as well
     m_SM.playFire(Vector2f(posX, posY), m_Thomas.getCenter());
   }
} 

// Set the appropriate view around the appropriate character 

```

前面的代码有点像声音的碰撞检测。每当 Thomas 停留在围绕火砖发射器的 500x500 像素矩形内时，`playFire`函数就会被调用，传入发射器和 Thomas 的坐标。然后`playFire`函数会完成其余的工作，并触发一个空间化的循环声音效果。

打开`DetectCollisions.cpp`文件，找到适当的位置，并按照以下所示添加高亮代码。两行高亮代码触发了当角色掉入水或火砖时播放声音效果。

```cpp
// Has character been burnt or drowned? 
// Use head as this allows him to sink a bit 
if (m_ArrayLevel[y][x] == 2 || m_ArrayLevel[y][x] == 3) 
{ 
   if (character.getHead().intersects(block)) 
   { 
      character.spawn(m_LM.getStartPosition(), GRAVITY); 
      // Which sound should be played? 
      if (m_ArrayLevel[y][x] == 2)// Fire, ouch! 
      { 
        // Play a sound 
 m_SM.playFallInFire(); 

      } 
      else // Water 
      { 
        // Play a sound 
 m_SM.playFallInWater(); 
      } 
   } 
} 

```

玩游戏将允许您听到所有的声音，包括在靠近火砖时的很酷的空间化。

# HUD 类

HUD 是超级简单的，与书中的其他两个项目没有什么不同。我们要做的不同之处在于将所有代码封装在一个新的 HUD 类中。如果我们将所有的字体、文本和其他变量声明为这个新类的成员，然后在构造函数中初始化它们，并为它们提供 getter 函数，这将使得`Engine`类清除了大量的声明和初始化。

## 编写 HUD.h

首先，我们将编写`HUD.h`文件，其中包含所有成员变量和函数声明。在**解决方案资源管理器**中右键单击**头文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，通过左键单击**头文件**（`.h`）并在**名称**字段中键入`HUD.h`。最后，单击**添加**按钮。现在我们准备为`HUD`类编写头文件。

将以下代码添加到`HUD.h`中：

```cpp
#pragma once 
#include <SFML/Graphics.hpp> 

using namespace sf; 

class Hud 
{ 
private: 
   Font m_Font; 
   Text m_StartText; 
   Text m_TimeText; 
   Text m_LevelText; 

public: 
   Hud(); 
   Text getMessage(); 
   Text getLevel(); 
   Text getTime(); 

   void setLevel(String text); 
   void setTime(String text); 
}; 

```

在先前的代码中，我们添加了一个`Font`实例和三个`Text`实例。`Text`对象将用于显示提示用户开始、剩余时间和当前级别编号的消息。

公共函数更有趣。首先是构造函数，大部分代码将在其中。构造函数将初始化`Font`和`Text`对象，并将它们相对于当前屏幕分辨率定位在屏幕上。

三个 getter 函数，`getMessage`、`getLevel`和`getTime`将返回一个`Text`对象给调用代码，以便能够将它们绘制到屏幕上。

`setLevel`和`setTime`函数将用于更新显示在`m_LevelText`和`m_TimeText`中的文本。

现在我们可以编写刚刚概述的所有函数的定义。

## 编写 HUD.cpp 文件

在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，通过左键单击**C++文件（** `.cpp` **）**并在**名称**字段中键入`HUD.cpp`。最后，单击**添加**按钮。现在我们准备为`HUD`类编写`.cpp`文件。

添加包含指令和以下代码，然后我们将讨论它：

```cpp
#include "stdafx.h" 
#include "Hud.h" 

Hud::Hud() 
{ 
   Vector2u resolution; 
   resolution.x = VideoMode::getDesktopMode().width; 
   resolution.y = VideoMode::getDesktopMode().height; 

   // Load the font 
   m_Font.loadFromFile("fonts/Roboto-Light.ttf"); 

   // when Paused 
   m_StartText.setFont(m_Font); 
   m_StartText.setCharacterSize(100); 
   m_StartText.setFillColor(Color::White); 
   m_StartText.setString("Press Enter when ready!"); 

   // Position the text 
   FloatRect textRect = m_StartText.getLocalBounds(); 

   m_StartText.setOrigin(textRect.left + 
      textRect.width / 2.0f, 
      textRect.top + 
      textRect.height / 2.0f); 

   m_StartText.setPosition( 
      resolution.x / 2.0f, resolution.y / 2.0f); 

   // Time 
   m_TimeText.setFont(m_Font); 
   m_TimeText.setCharacterSize(75); 
   m_TimeText.setFillColor(Color::White); 
   m_TimeText.setPosition(resolution.x - 150, 0); 
   m_TimeText.setString("------"); 

   // Level 
   m_LevelText.setFont(m_Font); 
   m_LevelText.setCharacterSize(75); 
   m_LevelText.setFillColor(Color::White); 
   m_LevelText.setPosition(25, 0); 
   m_LevelText.setString("1"); 
} 

```

首先，我们将水平和垂直分辨率存储在名为`resolution`的`Vector2u`中。接下来，我们从我们在第十二章中添加的`fonts`目录中加载字体。*抽象和代码管理 - 更好地利用面向对象编程*。

接下来的四行代码设置了`m_StartText`的字体、颜色、大小和文本。此后的代码块捕获了包裹`m_StartText`的矩形的大小，并进行计算以确定如何将其居中放置在屏幕上。如果您想对代码的这部分进行更详细的解释，请参考第三章：*C++字符串、SFML 时间 - 玩家输入和 HUD*。

构造函数中的最后两个代码块设置了`m_TimeText`和`m_LevelText`的字体、文本大小、颜色、位置和实际文本。然而，我们很快会看到，这两个`Text`对象将通过两个 setter 函数进行更新，每当需要时。

在我们刚刚添加的代码之后立即添加以下 getter 和 setter 函数：

```cpp
Text Hud::getMessage() 
{ 
   return m_StartText; 
} 

Text Hud::getLevel() 
{ 
   return m_LevelText; 
} 

Text Hud::getTime() 
{ 
   return m_TimeText; 
} 

void Hud::setLevel(String text) 
{ 
   m_LevelText.setString(text); 
} 

void Hud::setTime(String text) 
{ 
   m_TimeText.setString(text); 
} 

```

先前代码中的前三个函数只是返回适当的`Text`对象，`m_StartText`、`m_LevelText`和`m_TimeText`。我们将很快使用这些函数，在屏幕上绘制 HUD 时。最后两个函数，`setLevel`和`setTime`，使用`setString`函数来更新适当的`Text`对象，该值将从`Engine`类的`update`函数中每 500 帧传入。

完成所有这些后，我们可以在游戏引擎中使用 HUD 类。

# 使用 HUD 类

打开`Engine.h`，添加一个包含我们新类的声明，声明一个新的`HUD`类的实例，并声明并初始化两个新的成员变量，用于跟踪我们更新 HUD 的频率。正如我们在之前的两个项目中学到的，我们不需要为每一帧都这样做。

将突出显示的代码添加到`Engine.h`中：

```cpp
#pragma once 
#include <SFML/Graphics.hpp> 
#include "TextureHolder.h" 
#include "Thomas.h" 
#include "Bob.h" 
#include "LevelManager.h" 
#include "SoundManager.h" 
#include "HUD.h" 

using namespace sf; 

class Engine 
{ 
private: 
   // The texture holder 
   TextureHolder th; 

   // Thomas and his friend, Bob 
   Thomas m_Thomas; 
   Bob m_Bob; 

   // A class to manage all the levels 
   LevelManager m_LM; 

   // Create a SoundManager 
   SoundManager m_SM; 

 // The Hud   Hud m_Hud;
   int m_FramesSinceLastHUDUpdate = 0;
   int m_TargetFramesPerHUDUpdate = 500; 

   const int TILE_SIZE = 50; 

```

接下来，我们需要在`Engine`类的`update`函数中添加一些代码。打开`Update.cpp`并添加突出显示的代码以每 500 帧更新 HUD：

```cpp
   // Set the appropriate view around the appropriate character 
   if (m_SplitScreen) 
   { 
      m_LeftView.setCenter(m_Thomas.getCenter()); 
      m_RightView.setCenter(m_Bob.getCenter()); 
   } 
   else 
   { 
      // Centre full screen around appropriate character 
      if (m_Character1) 
      { 
         m_MainView.setCenter(m_Thomas.getCenter()); 
      } 
      else 
      { 
         m_MainView.setCenter(m_Bob.getCenter()); 
      } 
   } 

 // Time to update the HUD?
   // Increment the number of frames since the last HUD calculation
   m_FramesSinceLastHUDUpdate++;

   // Update the HUD every m_TargetFramesPerHUDUpdate frames
   if (m_FramesSinceLastHUDUpdate > m_TargetFramesPerHUDUpdate)
   {
     // Update game HUD text
     stringstream ssTime;
     stringstream ssLevel; 
     // Update the time text 
     ssTime << (int)m_TimeRemaining;
     m_Hud.setTime(ssTime.str());
     // Update the level text
     ssLevel << "Level:" << m_LM.getCurrentLevel();
     m_Hud.setLevel(ssLevel.str());
     m_FramesSinceLastHUDUpdate = 0;
   } 
}// End of update function 

```

在前面的代码中，`m_FramesSinceLastUpdate`在每帧递增。当`m_FramesSinceLastUpdate`超过`m_TargetFramesPerHUDUpdate`时，执行进入`if`块。在`if`块内部，我们使用`stringstream`对象来更新我们的`Text`，就像在之前的项目中所做的那样。然而，正如你可能期望的那样，在这个项目中我们使用了`HUD`类，所以我们调用`setTime`和`setLevel`函数，传入`Text`对象需要设置的当前值。

`if`块中的最后一步是将`m_FramesSinceLastUpdate`设置回零，这样它就可以开始计算下一个更新。

最后，打开`Draw.cpp`文件，并添加突出显示的代码来每帧绘制 HUD。

```cpp
   else 
   { 
      // Split-screen view is active 

      // First draw Thomas' side of the screen 

      // Switch to background view 
      m_Window.setView(m_BGLeftView); 
      // Draw the background 
      m_Window.draw(m_BackgroundSprite); 
      // Switch to m_LeftView 
      m_Window.setView(m_LeftView); 

      // Draw the Level 
      m_Window.draw(m_VALevel, &m_TextureTiles); 

      // Draw thomas 
      m_Window.draw(m_Bob.getSprite()); 

      // Draw thomas 
      m_Window.draw(m_Thomas.getSprite()); 

      // Now draw Bob's side of the screen 

      // Switch to background view 
      m_Window.setView(m_BGRightView); 
      // Draw the background 
      m_Window.draw(m_BackgroundSprite); 
      // Switch to m_RightView 
      m_Window.setView(m_RightView); 

      // Draw the Level 
      m_Window.draw(m_VALevel, &m_TextureTiles); 

      // Draw thomas 
      m_Window.draw(m_Thomas.getSprite()); 

      // Draw bob 
      m_Window.draw(m_Bob.getSprite()); 

   } 

   // Draw the HUD 
   // Switch to m_HudView 
   m_Window.setView(m_HudView); 
 m_Window.draw(m_Hud.getLevel());
   m_Window.draw(m_Hud.getTime());
   if (!m_Playing)
   {
     m_Window.draw(m_Hud.getMessage());
   } 
   // Show everything we have just drawn 
   m_Window.display(); 
}// End of draw 

```

前面的代码使用 HUD 类的 getter 函数来绘制 HUD。请注意，只有在游戏当前未进行时`(!m_Playing)`才会调用绘制提示玩家开始的消息。

运行游戏并玩几个关卡，看时间倒计时和关卡增加。当你再次回到第一关时，注意你的时间比之前少了 10%。

# 总结

我们的《Thomas Was Late》游戏不仅可以完全玩得了，还有定向音效和简单但信息丰富的 HUD，而且我们还可以轻松添加新的关卡。在这一点上，我们可以说它已经完成了。

增加一些闪光效果会很好。在接下来的章节中，我们将探讨两个游戏概念。首先，我们将研究粒子系统，这是我们如何处理爆炸或其他特殊效果的方法。为了实现这一点，我们需要学习更多的 C++知识，看看我们如何彻底重新思考我们的游戏代码结构。

之后，当我们学习 OpenGL 和可编程图形管线时，我们将为游戏添加最后的点睛之笔。然后，我们将有机会涉足**GLSL**语言，这使我们能够编写直接在 GPU 上执行的代码，以创建一些特殊效果。


# 第十六章：扩展 SFML 类，粒子系统和着色器

在这最后一章中，我们将探讨 C++中扩展他人类的概念。更具体地说，我们将看看 SFML `Drawable`类以及将其用作我们自己类的基类的好处。我们还将浅尝 OpenGL 着色器的主题，并看看如何使用另一种语言**OpenGL 着色语言**（**GLSL**）编写代码，可以直接在图形卡上运行，可以产生可能无法实现的平滑图形效果。像往常一样，我们还将利用我们的新技能和知识来增强当前项目。

以下是我们将按顺序涵盖的主题列表：

+   SFML Drawable 类

+   构建一个粒子系统

+   OpenGL 着色器和 GLSL

+   在 Thomas Was Late 游戏中使用着色器

# SFML Drawable 类

`Drawable`类只有一个函数。它也没有变量。此外，它唯一的功能是纯虚拟的。这意味着如果我们从`Drawable`继承，我们必须实现它唯一的功能。这个目的，你可能还记得来自第十二章的*抽象和代码管理-更好地利用 OOP*，就是我们可以使用继承自`drawable`的类作为多态类型。更简单地说，任何 SFML 允许我们对`Drawable`对象做的事情，我们都可以用继承自它的类来做。唯一的要求是我们必须为纯虚拟函数`draw`提供定义。

一些从`Drawable`继承的类已经包括`Sprite`和`VertexArray`（还有其他）。每当我们使用`Sprite`或`VertexArray`时，我们都将它们传递给`RenderWindow`类的`draw`函数。

我们之所以能够绘制本书中绘制的每个对象，是因为它们都继承自`Drawable`。我们可以利用这个知识。

我们可以用任何我们喜欢的对象从`Drawable`继承，只要我们实现纯虚拟的`draw`函数。这也是一个简单的过程。假设从`Drawable`继承的`SpaceShip`类的头文件（`SpaceShip.h`）将如下所示：

```cpp
class SpaceShip : public Drawable 
{ 
private: 
   Sprite m_Sprite; 
   // More private members 
public: 

   virtual void draw(RenderTarget& target,  
      RenderStates states) const; 

   // More public members 

}; 

```

在前面的代码中，我们可以看到纯虚拟的`draw`函数和一个 Sprite。请注意，没有办法在类的外部访问私有的`Sprite`，甚至没有`getSprite`函数！

然后`SpaceShip.cpp`文件看起来会像下面这样：

```cpp
void SpaceShip::SpaceShip 
{ 
   // Set up the spaceship 
} 

void SpaceShip::draw(RenderTarget& target, RenderStates states) const 
{ 
   target.draw(m_Sprite, states); 
} 

// Any other functions 

```

在前面的代码中，请注意`draw`函数的简单实现。参数超出了本书的范围。只需注意`target`参数用于调用`draw`并传入`m_Sprite`以及`states`，另一个参数。

### 提示

虽然不需要理解参数来充分利用`Drawable`，但在本书的上下文中，你可能会感兴趣。你可以在 SFML 网站上阅读更多关于 SFML `Drawable`类的信息：[`www.sfml-dev.org/tutorials/2.3/graphics-vertex-array.php#creating-an-sfml-like-entity`](http://www.sfml-dev.org/tutorials/2.3/graphics-vertex-array.php#creating-an-sfml-like-entity)

在主游戏循环中，我们现在可以将`SpaceShip`实例视为`Sprite`，或者从`Drawable`继承的任何其他类：

```cpp
SpaceShip m_SpaceShip; 
// create other objects here 
// ... 

// In the draw function 
// Rub out the last frame 
m_Window.clear(Color::Black); 

// Draw the spaceship 
m_Window.draw(m_SpaceShip); 
// More drawing here 
// ... 

// Show everything we have just drawn 
m_Window.display(); 

```

正是因为`SpaceShip`是一个`Drawable`，我们才能将其视为`Sprite`或`VertexArray`，并且因为我们覆盖了纯虚拟的`draw`函数，一切都按我们想要的方式运行。让我们看看另一种将绘图代码封装到游戏对象中的方法。

## 从 Drawable 继承的另一种选择

通过在我们的类内部实现自己的函数，也许像以下代码一样，也可以将所有绘图功能保留在要绘制的对象类中：

```cpp
void drawThisObject(RenderWindow window) 
{ 
   window.draw(m_Sprite) 
} 

```

先前的代码假设`m_Sprite`代表了我们正在绘制的当前类的视觉外观，就像在这个和前一个项目中一直使用的那样。假设包含`drawThisObject`函数的类的实例被称为`playerHero`，并且进一步假设我们有一个名为`m_Window`的`RenderWindow`的实例，我们可以在主游戏循环中使用以下代码绘制对象：

```cpp
 playerHero.draw(m_Window); 

```

在这个解决方案中，我们将`RenderWindow` `m_Window`作为参数传递给`drawThisObject`函数。然后`drawThisObject`函数使用`RenderWindow`来绘制`Sprite` `m_Sprite`。

与扩展`Drawable`相比，这个解决方案似乎更简单。我们之所以按照建议的方式（扩展 Drawable）做事情的原因并不是因为这个项目本身有很大的好处。我们很快将用这种方法绘制一个整洁的爆炸，原因是这是一个很好的学习技巧。

## 为什么最好继承自 Drawable？

通过本书完成的每个项目，我们都学到了更多关于游戏、C++和 SFML。从一个游戏到下一个游戏，我们所做的最大的改进可能是我们的代码结构——我们所使用的编程**模式**。

如果这本书有第四个项目，我们可以进一步发展。不幸的是，没有，但是想一想以下改进我们代码的想法。

想象我们游戏中的每个对象都是从一个简单的抽象基类派生出来的。让我们称之为`GameObject`。游戏对象可能有具体的`getPosition`等函数。它可能有一个纯虚拟的`update`函数（因为每个对象的更新方式都不同）。此外，考虑`GameObject`继承自`Drawable`。

现在看看这个假设的代码：

```cpp
vector<GameObject> m_GameObjects; 
// Code to initialise all game objects 
// Including tiles, characters, enemies, bullets and anything else 

// In the update function 
for (i = m_GameObjects.begin(); i != m_GameObjects.end(); i++) 
{ 
   (*i).update(elapsedTime); 
} 
// That's it! 

// In the draw function 
// Rub out the last frame 
m_Window.clear(Color::Black); 

for (i = m_GameObjects.begin(); i != m_GameObjects.end(); i++) 
{ 
   m_Window.draw(*i); 
} 

// Show everything we have just drawn 
m_Window.display(); 
// That's it! 

```

与甚至最终项目相比，上述代码在封装、代码可管理性和优雅方面有了很大的进步。如果你看一下以前的代码，你会注意到有一些未解答的问题，比如碰撞检测在哪里等等。然而，希望你能看到，进一步的学习（通过构建很多游戏）将是掌握 C++所必需的。

虽然我们不会以这种方式实现整个游戏，但我们将看到如何设计一个类（`ParticleSystem`）并将其直接传递给`m_Window.draw(m_MyParticleSystemInstance)`。

# 构建一个粒子系统

在我们开始编码之前，看一看我们要实现的确切目标将会很有帮助。看一下以下截图：

![构建一个粒子系统](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_16_001.jpg)

这是一个纯背景上粒子效果的截图。我们将在我们的游戏中使用这个效果。

我们实现效果的方式如下：

1.  在选择的像素位置生成 1,000 个点（粒子），一个叠在另一个上面。

1.  在游戏的每一帧中，以预定但随机的速度和角度将 1,000 个粒子向外移动。

1.  重复第二步两秒钟，然后使粒子消失。

我们将使用`VertexArray`来绘制所有的点，使用`Point`的原始类型来直观地表示每个粒子。此外，我们将继承自`Drawable`，以便我们的粒子系统可以自行绘制。

## 编写 Particle 类

`Particle`类将是一个简单的类，代表了 1,000 个粒子中的一个。让我们开始编码。

### 编写 Particle.h

在**解决方案资源管理器**中右键单击**头文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，通过左键单击**头文件**（`.h`）突出显示，然后在**名称**字段中键入`Particle.h`。最后，单击**添加**按钮。我们现在准备为`Particle`类编写头文件。

将以下代码添加到`Particle.h`文件中：

```cpp
#pragma once 
#include <SFML/Graphics.hpp> 

using namespace sf; 

class Particle 
{ 
private: 
   Vector2f m_Position; 
   Vector2f m_Velocity; 

public: 
   Particle(Vector2f direction); 

   void update(float dt); 

   void setPosition(Vector2f position); 

   Vector2f getPosition(); 
}; 

```

在上述代码中，我们有两个`Vector2f`对象。一个代表粒子的水平和垂直坐标，另一个代表水平和垂直速度。

### 注意

当你有一个以上方向的变化率（速度）时，合并的值也定义了一个方向。这就是所谓的**速度**；因此，Vector2f 被称为'm_Velocity'。

我们还有一些公共函数。首先是构造函数。它接受一个'Vector2f'，将用于让它知道这个粒子将具有什么方向/速度。这意味着系统，而不是粒子本身，将选择速度。

接下来是'update'函数，它接受前一帧所花费的时间。我们将使用这个时间精确地移动粒子。

最后两个函数，'setPosition'和'getPosition'，用于将粒子移动到位置并找出其位置。

当我们编写这些函数时，所有这些函数都会变得非常清晰。

### 编写 Particle.cpp 文件

在“解决方案资源管理器”中右键单击“源文件”，然后选择“添加”|“新项目...”。在“添加新项目”窗口中，突出显示（通过左键单击）“C++文件”（.cpp），然后在“名称”字段中键入`Particle.cpp`。最后，单击“添加”按钮。我们现在准备为 Particle 类编写.cpp 文件。

将以下代码添加到'Particle.cpp'中：

```cpp
#include "stdafx.h" 
#include "Particle.h" 

Particle::Particle(Vector2f direction) 
{ 

   // Determine the direction 
   //m_Velocity = direction; 
   m_Velocity.x = direction.x; 
   m_Velocity.y = direction.y; 
} 

void Particle::update(float dtAsSeconds) 
{ 
   // Move the particle 
   m_Position += m_Velocity * dtAsSeconds; 
} 

void Particle::setPosition(Vector2f position) 
{ 
   m_Position = position; 

} 

Vector2f Particle::getPosition() 
{ 
   return m_Position; 
} 

```

所有这些函数都使用了我们之前见过的概念。构造函数使用传入的 Vector2f 对象设置了'm_Velocity.x'和'm_Velocity.y'的值。

'update'函数通过将经过的时间（'dtAsSeconds'）乘以'm_Velocity'来移动粒子的水平和垂直位置。请注意，为了实现这一点，我们只需将两个'Vector2f'对象相加即可。无需分别为'x'和'y'成员执行计算。

如前所述，'setPosition'函数使用传入的值初始化了'm_Position'对象。'getPosition'函数将'm_Position'返回给调用代码。

现在我们有一个完全功能的 Particle 类。接下来，我们将编写一个 ParticleSystem 类来生成和控制粒子。

## 编写 ParticleSystem 类

'ParticleSystem'类为我们的粒子效果做了大部分工作。我们将在'Engine'类中创建这个类的一个实例。

### 编写 ParticleSystem.h

在“解决方案资源管理器”中右键单击“头文件”，然后选择“添加”|“新项目...”。在“添加新项目”窗口中，突出显示（通过左键单击）“头文件”（.h），然后在“名称”字段中键入`ParticleSystem.h`。最后，单击“添加”按钮。我们现在准备为 ParticleSystem 类编写头文件。

将 ParticleSystem 类的代码添加到 ParticleSystem.h 中：

```cpp
#pragma once 
#include <SFML/Graphics.hpp> 
#include "Particle.h" 

using namespace sf; 
using namespace std; 

class ParticleSystem : public Drawable 
{ 
private: 

   vector<Particle> m_Particles; 
   VertexArray m_Vertices; 
   float m_Duration; 
   bool m_IsRunning = false; 

public: 

   virtual void draw(RenderTarget& target, RenderStates states) const; 

   void init(int count); 

   void emitParticles(Vector2f position); 

   void update(float elapsed); 

   bool running(); 

}; 

```

让我们一点点来看这个。首先，注意我们是从'Drawable'继承的。这将使我们能够将我们的'ParticleSystem'实例传递给'm_Window.draw'，因为'ParticleSystem'是一个'Drawable'。

有一个名为'm_Particles'的类型为'Particle'的向量。这个向量将保存每个'Particle'的实例。接下来我们有一个名为'm_Vertices'的'VertexArray'。这将用于以一堆'Point'原语的形式绘制所有的粒子。

'm_Duration'，'float'变量是每个效果持续的时间。我们将在构造函数中初始化它。

布尔值'm_IsRunning'变量将用于指示粒子系统当前是否正在使用。

接下来，在公共部分，我们有一个纯虚函数'draw'，我们将很快实现它来处理当我们将 ParticleSystem 的实例传递给'm_Window.draw'时发生的情况。

'init'函数将准备'VertexArray'和'vector'。它还将使用它们的速度和初始位置初始化所有的'Particle'对象（由'vector'持有）。

'update'函数将循环遍历'vector'中的每个'Particle'实例，并调用它们各自的'update'函数。

`running`函数提供对`m_IsRunning`变量的访问，以便游戏引擎可以查询`ParticleSystem`当前是否正在使用。

让我们编写函数定义，看看`ParticleSystem`内部发生了什么。

### 编写 ParticleSystem.cpp 文件

右键单击**Solution Explorer**中的**Source Files**，然后选择**Add** | **New Item...**。在**Add New Item**窗口中，通过左键单击**C++ File (** `.cpp` **)**突出显示，然后在**Name**字段中键入`ParticleSystem.cpp`。最后，单击**Add**按钮。现在我们准备好为`ParticleSystem`类编写`.cpp`文件了。

我们将把这个文件分成五个部分来编码和讨论。按照这里所示，添加代码的第一部分：

```cpp
#include "stdafx.h" 
#include <SFML/Graphics.hpp> 
#include "ParticleSystem.h" 

using namespace sf; 
using namespace std; 

void ParticleSystem::init(int numParticles) 
{ 
   m_Vertices.setPrimitiveType(Points); 
   m_Vertices.resize(numParticles); 

   // Create the particles 

   for (int i = 0; i < numParticles; i++) 
   { 
      srand(time(0) + i); 
      float angle = (rand() % 360) * 3.14f / 180.f; 
      float speed = (rand() % 600) + 600.f; 

      Vector2f direction; 

      direction = Vector2f(cos(angle) * speed, 
         sin(angle) * speed); 

      m_Particles.push_back(Particle(direction)); 

   } 

} 

```

在必要的`includes`之后，我们有`init`函数的定义。我们调用`setPrimitiveType`，参数为`Points`，以便`m_VertexArray`知道它将处理什么类型的基元。我们使用`numParticles`调整`m_Vertices`的大小，这是在调用`init`函数时传入的。

`for`循环创建速度和角度的随机值。然后使用三角函数将这些值转换为一个向量，存储在`Vector2f` `direction`中。

### 提示

如果您想了解三角函数（`cos`、`sin`和`tan`）如何将角度和速度转换为向量，可以查看这篇文章系列：[`gamecodeschool.com/essentials/calculating-heading-in-2d-games-using-trigonometric-functions-part-1/`](http://gamecodeschool.com/essentials/calculating-heading-in-2d-games-using-trigonometric-functions-part-1/)

`for`循环（和`init`函数）中发生的最后一件事是将向量传递给`Particle`构造函数。新的`Particle`实例使用`push_back`函数存储在`m_Particles`中。因此，使用值`1000`调用`init`将意味着我们有一千个`Particle`实例，具有随机速度，藏在`m_Particles`中等待爆炸！

接下来，在`ParticleSysytem.cpp`中添加`update`函数：

```cpp
void ParticleSystem::update(float dt) 
{ 
   m_Duration -= dt; 
   vector<Particle>::iterator i; 
   int currentVertex = 0; 

   for (i = m_Particles.begin(); i != m_Particles.end(); i++) 
   { 
      // Move the particle 
      (*i).update(dt); 

      // Update the vertex array 
      m_Vertices[currentVertex].position = (*i).getPosition(); 

      // Move to the next vertex 
      currentVertex++; 
   } 

   if (m_Duration < 0) 
   { 
      m_IsRunning = false; 
   } 

} 

```

`update`函数比起初看起来要简单一些。首先，`m_Duration`会减去传入的时间`dt`，这样我们就知道两秒已经过去了。声明一个向量迭代器`i`，用于`m_Particles`。

`for`循环遍历`m_Particles`中的每个`Particle`实例。对于每一个粒子，它都调用其`update`函数并传入`dt`。每个粒子都将更新其位置。粒子更新完毕后，通过使用粒子的`getPosition`函数更新`m_Vertices`中的适当顶点。在每次循环结束时，`for`循环中的`currentVertex`都会递增，准备好下一个顶点。

`for`循环完成后，`if(m_Duration < 0)`检查是否是时候关闭效果了。如果两秒已经过去，`m_IsRunning`将设置为`false`。

接下来，添加`emitParticles`函数：

```cpp
void ParticleSystem::emitParticles(Vector2f startPosition) 
{ 
   m_IsRunning = true; 
   m_Duration = 2; 

   vector<Particle>::iterator i; 
   int currentVertex = 0; 

   for (i = m_Particles.begin(); i != m_Particles.end(); i++) 
   { 
      m_Vertices[currentVertex].color = Color::Yellow; 
      (*i).setPosition(startPosition); 

      currentVertex++; 
   } 

} 

```

这是我们将调用来启动粒子系统运行的函数。因此，可以预料到，我们将`m_IsRunning`设置为`true`，`m_Duration`设置为`2`。我们声明一个`iterator` `i`，用于遍历`m_Particles`中的所有`Particle`对象，然后在`for`循环中这样做。

在`for`循环中，我们将顶点数组中的每个粒子设置为黄色，并将每个位置设置为传入的`startPosition`。请记住，每个粒子的生命都从完全相同的位置开始，但它们各自被分配了不同的速度。

接下来，添加纯虚拟的 draw 函数定义：

```cpp
void ParticleSystem::draw(RenderTarget& target, RenderStates states) const 
{ 
   target.draw(m_Vertices, states); 
} 

```

在之前的代码中，我们简单地使用`target`调用`draw`，传入`m_Vertices`和`states`。这与我们在本章早些时候讨论`Drawable`时讨论的完全一样，只是我们传入了我们的`VertexArray`，其中包含了 1000 个点的基元，而不是假设的太空飞船 Sprite。

最后，添加`running`函数：

```cpp
bool ParticleSystem::running() 
{ 
   return m_IsRunning; 
} 

```

`running`函数是一个简单的 getter 函数，返回`m_IsRunning`的值。我们将看到这在确定粒子系统的当前状态时是有用的。

## 使用 ParticleSystem

让我们的粒子系统工作非常简单，特别是因为我们继承自`Drawable`。

### 向 Engine 类添加一个 ParticleSystem 对象

打开`Engine.h`并添加一个`ParticleSystem`对象，如下所示的高亮代码：

```cpp
#pragma once 
#include <SFML/Graphics.hpp> 
#include "TextureHolder.h" 
#include "Thomas.h" 
#include "Bob.h" 
#include "LevelManager.h" 
#include "SoundManager.h" 
#include "HUD.h" 
#include "ParticleSystem.h" 

using namespace sf; 

class Engine 
{ 
private: 
   // The texture holder 
   TextureHolder th; 

 // create a particle system
   ParticleSystem m_PS; 

   // Thomas and his friend, Bob 
   Thomas m_Thomas; 
   Bob m_Bob; 

```

接下来，初始化系统。

### 初始化 ParticleSystem

打开`Engine.cpp`文件，并在`Engine`构造函数的最后添加短暗示代码：

```cpp
Engine::Engine() 
{ 
   // Get the screen resolution and create an SFML window and View 
   Vector2f resolution; 
   resolution.x = VideoMode::getDesktopMode().width; 
   resolution.y = VideoMode::getDesktopMode().height; 

   m_Window.create(VideoMode(resolution.x, resolution.y), 
      "Thomas was late", 
      Style::Fullscreen); 

   // Initialize the full screen view 
   m_MainView.setSize(resolution); 
   m_HudView.reset( 
      FloatRect(0, 0, resolution.x, resolution.y)); 

   // Inititialize the split-screen Views 
   m_LeftView.setViewport( 
      FloatRect(0.001f, 0.001f, 0.498f, 0.998f)); 

   m_RightView.setViewport( 
      FloatRect(0.5f, 0.001f, 0.499f, 0.998f)); 

   m_BGLeftView.setViewport( 
      FloatRect(0.001f, 0.001f, 0.498f, 0.998f)); 

   m_BGRightView.setViewport( 
      FloatRect(0.5f, 0.001f, 0.499f, 0.998f)); 

   // Can this graphics card use shaders? 
   if (!sf::Shader::isAvailable()) 
   { 
      // Time to get a new PC 
      m_Window.close(); 
   } 

   m_BackgroundTexture = TextureHolder::GetTexture( 
      "graphics/background.png"); 

   // Associate the sprite with the texture 
   m_BackgroundSprite.setTexture(m_BackgroundTexture); 

   // Load the texture for the background vertex array 
   m_TextureTiles = TextureHolder::GetTexture( 
      "graphics/tiles_sheet.png"); 

 // Initialize the particle system
   m_PS.init(1000); 

}// End Engine constructor 

```

`VertexArray`和`Particle`实例的`vector`已经准备就绪。

### 在每一帧更新粒子系统

打开`Update.cpp`文件，并在`update`函数的最后添加以下高亮代码：

```cpp
   // Update the HUD every m_TargetFramesPerHUDUpdate frames 
   if (m_FramesSinceLastHUDUpdate > m_TargetFramesPerHUDUpdate) 
   { 
      // Update game HUD text 
      stringstream ssTime; 
      stringstream ssLevel; 

      // Update the time text 
      ssTime << (int)m_TimeRemaining; 
      m_Hud.setTime(ssTime.str()); 

      // Update the level text 
      ssLevel << "Level:" << m_LM.getCurrentLevel(); 
      m_Hud.setLevel(ssLevel.str()); 

      m_FramesSinceLastHUDUpdate = 0; 
   } 

 // Update the particles
   if (m_PS.running())
   {
     m_PS.update(dtAsSeconds);
   } 

}// End of update function 

```

在上一个代码中，只需要调用`update`。请注意，它被包裹在一个检查中，以确保系统当前正在运行。如果它没有运行，更新它就没有意义。

### 启动粒子系统

打开`DetectCollisions.cpp`文件，其中包含`detectCollisions`函数。当我们最初编写它时，我们在第十五章中留下了一个注释，*构建可玩级别和碰撞检测*。

从上下文中找到正确的位置并添加高亮代码，如下所示：

```cpp
// Is character colliding with a regular block 
if (m_ArrayLevel[y][x] == 1) 
{ 

   if (character.getRight().intersects(block)) 
   { 
      character.stopRight(block.left); 
   } 
   else if (character.getLeft().intersects(block)) 
   { 
      character.stopLeft(block.left); 
   } 

   if (character.getFeet().intersects(block)) 
   { 
      character.stopFalling(block.top); 
   } 
   else if (character.getHead().intersects(block)) 
   { 
      character.stopJump(); 
   } 
} 

// More collision detection here once  
// we have learned about particle effects 

// Has the character's feet touched fire or water?
// If so, start a particle effect
// Make sure this is the first time we have detected this
// by seeing if an effect is already running
if (!m_PS.running())
{
   if (m_ArrayLevel[y][x] == 2 || m_ArrayLevel[y][x] == 3)
   {
     if (character.getFeet().intersects(block))
     {
        // position and start the particle system
        m_PS.emitParticles(character.getCenter());
     }
   }
} 

// Has the character reached the goal? 
if (m_ArrayLevel[y][x] == 4) 
{ 
   // Character has reached the goal 
   reachedGoal = true; 
}  

```

首先，代码检查粒子系统是否已经运行。如果没有运行，它会检查当前正在检查的瓦片是否是水瓦片或火瓦片。如果是这种情况，它会检查角色的脚是否接触。当这些`if`语句中的每一个为`true`时，通过调用`emitParticles`函数并传入角色中心的位置作为开始效果的坐标来启动粒子系统。

### 绘制粒子系统

这是最好的部分。看看绘制`ParticleSystem`有多容易。在检查粒子系统实际运行后，我们直接将实例传递给`m_Window.draw`函数。

打开`Draw.cpp`文件，并在以下代码中显示的所有位置添加高亮代码：

```cpp
void Engine::draw() 
{ 
   // Rub out the last frame 
   m_Window.clear(Color::White); 

   if (!m_SplitScreen) 
   { 
      // Switch to background view 
      m_Window.setView(m_BGMainView); 
      // Draw the background 
      m_Window.draw(m_BackgroundSprite); 
      // Switch to m_MainView 
      m_Window.setView(m_MainView);     

      // Draw the Level 
      m_Window.draw(m_VALevel, &m_TextureTiles); 

      // Draw thomas 
      m_Window.draw(m_Thomas.getSprite()); 

      // Draw thomas 
      m_Window.draw(m_Bob.getSprite()); 

 // Draw the particle system
      if (m_PS.running())
      {
         m_Window.draw(m_PS);
      } 
   } 
   else 
   { 
      // Split-screen view is active 

      // First draw Thomas' side of the screen 

      // Switch to background view 
      m_Window.setView(m_BGLeftView); 
      // Draw the background 
      m_Window.draw(m_BackgroundSprite); 
      // Switch to m_LeftView 
      m_Window.setView(m_LeftView); 

      // Draw the Level 
      m_Window.draw(m_VALevel, &m_TextureTiles); 

      // Draw thomas 
      m_Window.draw(m_Bob.getSprite()); 

      // Draw thomas 
      m_Window.draw(m_Thomas.getSprite()); 

 // Draw the particle system
      if (m_PS.running())
      {
         m_Window.draw(m_PS);
      } 

      // Now draw Bob's side of the screen 

      // Switch to background view 
      m_Window.setView(m_BGRightView); 
      // Draw the background 
      m_Window.draw(m_BackgroundSprite); 
      // Switch to m_RightView 
      m_Window.setView(m_RightView); 

      // Draw the Level 
      m_Window.draw(m_VALevel, &m_TextureTiles); 

      // Draw thomas 
      m_Window.draw(m_Thomas.getSprite()); 

      // Draw bob 
      m_Window.draw(m_Bob.getSprite()); 

 // Draw the particle system
      if (m_PS.running())
      {
         m_Window.draw(m_PS);
      }           
   } 

   // Draw the HUD 
   // Switch to m_HudView 
   m_Window.setView(m_HudView); 
   m_Window.draw(m_Hud.getLevel()); 
   m_Window.draw(m_Hud.getTime()); 
   if (!m_Playing) 
   { 
      m_Window.draw(m_Hud.getMessage()); 
   } 

   // Show everything we have just drawn 
   m_Window.display(); 
} 

```

请注意，在上一个代码中，我们必须在所有的左侧、右侧和全屏代码块中绘制粒子系统。

运行游戏，并将角色的一只脚移动到火瓦片的边缘。注意粒子系统会突然活跃起来：

![绘制粒子系统](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_16_002.jpg)

现在是另一件新事物。

# OpenGL、着色器和 GLSL

**OpenGL**（**Open Graphics Library**）是一个处理 2D 和 3D 图形的编程库。OpenGL 适用于所有主要桌面操作系统，还有一个适用于移动设备的版本 OpenGL ES。

OpenGL 最初是在 1992 年发布的。它在二十多年的时间里得到了改进和提高。此外，图形卡制造商设计他们的硬件使其与 OpenGL 良好地配合工作。告诉你这一点的目的不是为了历史课，而是为了解释如果你想让游戏在桌面上的 2D（和 3D）上运行，并且希望你的游戏不仅仅在 Windows 上运行，那么使用 OpenGL 是一个明显的选择。我们已经在使用 OpenGL，因为 SFML 使用 OpenGL。着色器是在 GPU 上运行的程序，所以让我们更多地了解它们。

## 可编程管线和着色器

通过 OpenGL，我们可以访问所谓的**可编程管线**。我们可以发送我们的图形进行绘制，每一帧都可以使用`RenderWindow`的`draw`函数。我们还可以编写在调用`draw`后在 GPU 上运行的代码，它能够独立地操纵每一个像素。这是一个非常强大的功能。

在 GPU 上运行的这些额外代码称为**着色器程序**。我们可以编写代码来操纵我们图形的几何（位置），这称为**顶点着色器**。我们还可以编写代码，以在称为**片段着色器**的代码中单独操纵每个像素的外观。

尽管我们不会深入探讨着色器，但我们将使用 GLSL 编写一些着色器代码，并且将一窥所提供的可能性。

在 OpenGL 中，一切都是点、线或三角形。此外，我们可以将颜色和纹理附加到这些基本几何图形，并且我们还可以将这些元素组合在一起，以制作我们在今天的现代游戏中看到的复杂图形。这些统称为**基元**。我们可以通过 SFML 基元和`VertexArray`以及我们所见过的`Sprite`和`Shape`类来访问 OpenGL 基元。

除了基元，OpenGL 还使用矩阵。矩阵是一种执行算术的方法和结构。这种算术可以从非常简单的高中水平计算移动（平移）坐标，或者可以非常复杂，执行更高级的数学；例如，将我们的游戏世界坐标转换为 OpenGL 屏幕坐标，GPU 可以使用。幸运的是，正是这种复杂性在幕后由 SFML 为我们处理。

SFML 还允许我们直接处理 OpenGL。如果您想了解更多关于 OpenGL 的信息，可以从这里开始：[`learnopengl.com/#!Introduction`](http://learnopengl.com/#!Introduction)。如果您想直接在 SFML 旁边使用 OpenGL，可以阅读以下文章：[`www.sfml-dev.org/tutorials/2.3/window-opengl.php`](http://www.sfml-dev.org/tutorials/2.3/window-opengl.php)。

一个应用程序可以有许多着色器。然后我们可以*附加*不同的着色器到不同的游戏对象上，以创建所需的效果。在这个游戏中，我们只会有一个顶点着色器和一个片段着色器。我们将在每一帧将其应用到背景上。

但是，当您了解如何将着色器附加到`draw`调用时，就会明显地知道可以轻松添加更多着色器。

我们将按照以下步骤进行：

1.  首先，我们需要在 GPU 上执行的着色器代码。

1.  然后我们需要编译该代码。

1.  最后，我们需要将着色器附加到游戏引擎的绘图函数中的适当绘图调用。

GLSL 是一种独立的语言，它也有自己的类型，可以声明和使用这些类型的变量。此外，我们可以从我们的 C++代码与着色器程序的变量进行交互。

### 提示

如果对可编程图形管线和着色器的强大功能有进一步了解的话，那么我强烈推荐 Jacobo RodrÃ­guez 的《GLSL Essentials》：[`www.packtpub.com/hardware-and-creative/glsl-essentials`](https://www.packtpub.com/hardware-and-creative/glsl-essentials)。该书探讨了桌面上的 OpenGL 着色器，并且对于具有良好的 C++编程知识并且愿意学习不同语言的任何读者来说都非常易于理解。

正如我们将看到的，GLSL 与 C++有一些语法相似之处。

## 编写片段着色器

这是`shaders`文件夹中`rippleShader.frag`文件中的代码。您不需要编写此代码，因为它在我们在第十二章中添加的资产中已经存在，*抽象和代码管理-更好地利用 OOP*：

```cpp
// attributes from vertShader.vert 
varying vec4 vColor; 
varying vec2 vTexCoord; 

// uniforms 
uniform sampler2D uTexture; 
uniform float uTime; 

void main() { 
   float coef = sin(gl_FragCoord.y * 0.1 + 1 * uTime); 
   vTexCoord.y +=  coef * 0.03; 
   gl_FragColor = vColor * texture2D(uTexture, vTexCoord); 
} 

```

前四行（不包括注释）是片段着色器将使用的变量。但它们不是普通的变量。我们看到的第一种类型是`varying`。这些是在两个`shaders`之间范围内的变量。接下来，我们有`uniform`变量。这些变量可以直接从我们的 C++代码中操作。我们很快将看到我们如何做到这一点。

除了`varying`和`uniform`类型之外，每个变量还有一个更常规的类型，用于定义实际数据：

+   `vec4`是一个具有四个值的向量

+   `vec2`是一个具有两个值的向量

+   `sampler2d`将保存一个纹理

+   `float`就像 C++中的`float`

`main`函数内部的代码才是实际执行的。如果你仔细看`main`中的代码，你会看到每个变量的使用。这段代码实际上做了什么超出了本书的范围。然而，总的来说，纹理坐标(`vTexCoord`)和像素/片段的颜色(`glFragColor`)被一系列数学函数和操作所操纵。请记住，这对我们游戏中每一帧的每一个像素都会执行，而且要知道`uTime`每一帧都会传入不同的值。结果，正如我们很快会看到的，将会产生一种波纹效果。

## 编写顶点着色器

这是`vertShader.vert`文件中的代码。你不需要编写这个，因为它在我们在第十二章中添加的资产中已经有了，*抽象和代码管理-更好地利用 OOP*：

```cpp
//varying "out" variables to be used in the fragment shader 
varying vec4 vColor; 
varying vec2 vTexCoord; 

void main() { 
    vColor = gl_Color; 
    vTexCoord = (gl_TextureMatrix[0] * gl_MultiTexCoord0).xy; 
    gl_Position = gl_ModelViewProjectionMatrix * gl_Vertex; 
} 

```

首先，注意两个`varying`变量。这些正是我们在片段着色器中操作的变量。在`main`函数中，代码操纵了每个顶点的位置。代码的工作原理超出了本书的范围，但在幕后进行了一些相当深入的数学运算，如果你对此感兴趣，那么探索 GLSL 将会是很有趣的（参见前面的提示）。

现在我们有了两个着色器（一个片段着色器和一个顶点着色器）。我们可以在我们的游戏中使用它们。

## 将着色器添加到 Engine 类

打开`Engine.h`文件。添加突出显示的代码行，将一个名为`m_RippleShader`的 SFML `Shader`实例添加到`Engine`类中：

```cpp
// Three views for the background 
View m_BGMainView; 
View m_BGLeftView; 
View m_BGRightView; 

View m_HudView; 

// Declare a sprite and a Texture for the background 
Sprite m_BackgroundSprite; 
Texture m_BackgroundTexture; 

// Declare a shader for the background
Shader m_RippleShader; 

// Is the game currently playing? 
bool m_Playing = false; 

// Is character 1 or 2 the current focus? 
bool m_Character1 = true; 

```

引擎对象及其所有函数现在都可以访问`m_RippleShadder`。请注意，一个 SFML `Shader`对象将由两个着色器代码文件组成。

## 加载着色器

添加以下代码，检查玩家的 GPU 是否能够处理着色器。如果不能，游戏将退出。

### 提示

你的电脑必须非常老旧才不能运行。如果你的 GPU 无法处理着色器，请接受我的道歉。

接下来，我们将添加一个 else 子句，如果系统能够处理它们，它将实际加载着色器。打开`Engine.cpp`文件，并将以下代码添加到构造函数中：

```cpp
// Can this graphics card use shaders?
if (!sf::Shader::isAvailable())
{
   // Time to get a new PC
   m_Window.close();
}
else
{
   // Load two shaders (1 vertex, 1 fragment)
   m_RippleShader.loadFromFile("shaders/vertShader.vert",
     "shaders/rippleShader.frag");} 

m_BackgroundTexture = TextureHolder::GetTexture( 
   "graphics/background.png"); 

```

现在我们几乎准备好看到我们的波纹效果了。

## 在每一帧更新和绘制着色器

打开`Draw.cpp`文件。正如我们在编写着色器时讨论的那样，我们将在每一帧直接从我们的 C++代码中更新`uTime`变量。我们使用`Uniform`函数来实现这一点。

添加突出显示的代码以更新着色器的`uTime`变量，并在每种可能的绘制场景中为`m_BackgroundSprite`的`draw`调用更改：

```cpp
void Engine::draw() 
{ 
   // Rub out the last frame 
   m_Window.clear(Color::White); 

 // Update the shader parameters
   m_RippleShader.setUniform("uTime", m_GameTimeTotal.asSeconds()); 

   if (!m_SplitScreen) 
   { 
      // Switch to background view 
      m_Window.setView(m_BGMainView); 
      // Draw the background 
 //m_Window.draw(m_BackgroundSprite);

     // Draw the background, complete with shader effect
     m_Window.draw(m_BackgroundSprite, &m_RippleShader); 

      // Switch to m_MainView 
      m_Window.setView(m_MainView);     

      // Draw the Level 
      m_Window.draw(m_VALevel, &m_TextureTiles); 

      // Draw thomas 
      m_Window.draw(m_Thomas.getSprite()); 

      // Draw thomas 
      m_Window.draw(m_Bob.getSprite()); 

      // Draw the particle system 
      if (m_PS.running()) 
      { 
         m_Window.draw(m_PS); 
      } 
   } 
   else 
   { 
      // Split-screen view is active 

      // First draw Thomas' side of the screen 

      // Switch to background view 
      m_Window.setView(m_BGLeftView); 
      // Draw the background 
 //m_Window.draw(m_BackgroundSprite);

      // Draw the background, complete with shader effect
      m_Window.draw(m_BackgroundSprite, &m_RippleShader); 

      // Switch to m_LeftView 
      m_Window.setView(m_LeftView); 

      // Draw the Level 
      m_Window.draw(m_VALevel, &m_TextureTiles); 

      // Draw thomas 
      m_Window.draw(m_Bob.getSprite()); 

      // Draw thomas 
      m_Window.draw(m_Thomas.getSprite()); 

      // Draw the particle system 
      if (m_PS.running()) 
      { 
         m_Window.draw(m_PS); 
      } 

      // Now draw Bob's side of the screen 

      // Switch to background view 
      m_Window.setView(m_BGRightView); 
      // Draw the background 
 //m_Window.draw(m_BackgroundSprite);
      // Draw the background, complete with shader effect
      m_Window.draw(m_BackgroundSprite, &m_RippleShader); 

      // Switch to m_RightView 
      m_Window.setView(m_RightView); 

      // Draw the Level 
      m_Window.draw(m_VALevel, &m_TextureTiles); 

      // Draw thomas 
      m_Window.draw(m_Thomas.getSprite()); 

      // Draw bob 
      m_Window.draw(m_Bob.getSprite()); 

      // Draw the particle system 
      if (m_PS.running()) 
      { 
         m_Window.draw(m_PS); 
      } 

   } 

   // Draw the HUD 
   // Switch to m_HudView 
   m_Window.setView(m_HudView); 
   m_Window.draw(m_Hud.getLevel()); 
   m_Window.draw(m_Hud.getTime()); 
   if (!m_Playing) 
   { 
      m_Window.draw(m_Hud.getMessage()); 
   } 

   // Show everything we have just drawn 
   m_Window.display(); 
} 

```

最好实际上删除我所展示的注释掉的代码行。我只是这样做是为了清楚地表明哪些代码行正在被替换。

运行游戏，你会得到一种怪异的熔岩效果。如果你想玩得开心，可以尝试更改背景图像：

![在每一帧更新和绘制着色器](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_16_003.jpg)

就是这样！我们的第三个也是最后一个游戏完成了。

# 摘要

在大结局中，我们探讨了粒子系统和着色器的概念。虽然我们可能只看到了每种情况的最简单的情况，但我们仍然成功地创建了一个简单的爆炸和一种怪异的熔岩效果。

请看一下最后的简短章节，讨论接下来要做什么。
