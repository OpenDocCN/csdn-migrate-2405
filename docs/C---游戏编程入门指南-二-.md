# C++ 游戏编程入门指南（二）

> 原文：[`annas-archive.org/md5/8b22c2649bdec9fa4ee716ae82ae0bb1`](https://annas-archive.org/md5/8b22c2649bdec9fa4ee716ae82ae0bb1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：C++字符串，SFML 时间，玩家输入和 HUD

在本章中，我们将花大约一半的时间学习如何操作文本并在屏幕上显示它，另一半时间将用于研究时间和视觉时间条如何在游戏中制造紧迫感。

我们将涵盖以下主题：

+   暂停和重新开始游戏

+   C++字符串

+   SFML 文本和 SFML 字体类

+   为 Timber!!!添加 HUD

+   为 Timber!!!添加时间条

# 暂停和重新开始游戏

随着接下来三章的游戏进展，代码显然会变得越来越长。因此，现在似乎是一个很好的时机，考虑未来并在我们的代码中添加更多结构。我们将添加这种结构以使我们能够暂停和重新开始游戏。

我们将添加代码，以便在游戏首次运行时暂停。玩家将能够按下***Enter***键来启动游戏。然后游戏将运行，直到玩家被压扁或时间用尽。此时游戏将暂停并等待玩家按下***Enter***键，以重新开始。

让我们一步一步地设置这个。首先，在主游戏循环之外声明一个新的名为`paused`的`bool`变量，并将其初始化为`true`：

```cpp
// Variables to control time itself 
Clock clock; 

// Track whether the game is running
bool paused = true; 

while (window.isOpen()) 
{ 

   /* 
   **************************************** 
   Handle the players input 
   **************************************** 
   */ 

```

现在，每当游戏运行时，我们都有一个名为`paused`的变量，它将是`true`。

接下来，我们将添加另一个`if`语句，其中表达式将检查***Enter***键当前是否被按下。如果被按下，它将将`paused`设置为`false`。在我们其他处理键盘的代码之后添加突出显示的代码：

```cpp
/* 
**************************************** 
Handle the players input 
**************************************** 
*/ 

if (Keyboard::isKeyPressed(Keyboard::Escape)) 
{ 
   window.close(); 
} 

// Start the game
if (Keyboard::isKeyPressed(Keyboard::Return))
{   
  paused = false; 
} 

/* 
**************************************** 
Update the scene 
**************************************** 
*/ 

```

现在我们有一个名为`paused`的`bool`，它起初是`true`，但当玩家按下***Enter***键时会变为`false`。此时，我们必须使我们的游戏循环根据`paused`的当前值做出适当的响应。

这就是我们将要进行的步骤。我们将使用`if`语句包装整个更新部分的代码，包括我们在上一章中编写的用于移动蜜蜂和云的代码。

请注意，在下一段代码中，只有当`paused`不等于`true`时，`if`块才会执行。换句话说，游戏在暂停时不会移动/更新。

这正是我们想要的。仔细看看添加新的`if`语句以及相应的左花括号和右花括号`{...}`的确切位置。如果它们放错地方，事情将不会按预期工作。

添加突出显示的代码以包装代码的更新部分，密切关注下面显示的上下文。我在一些行上添加了`...`来表示隐藏的代码。显然，`...`不是真正的代码，不应该添加到游戏中。您可以通过周围未突出显示的代码来确定要放置新代码（突出显示）的位置，即开头和结尾：

```cpp
/* 
**************************************** 
Update the scene 
**************************************** 
*/ 

if (!paused)
{ 

   // Measure time 

      ... 
      ... 
      ... 

      // Has the cloud reached the right hand edge of the screen? 
      if (spriteCloud3.getPosition().x > 1920) 
      { 
         // Set it up ready to be a whole new cloud next frame 
         cloud3Active = false; 
      } 
   } 

} // End if(!paused) 

/* 
**************************************** 
Draw the scene 
**************************************** 
*/ 

```

请注意，当您放置新的`if`块的右花括号时，Visual Studio 会自动调整所有缩进，以保持代码整洁。

现在您可以运行游戏，直到按下***Enter***键之前一切都是静态的。现在可以开始为我们的游戏添加功能，只需记住当玩家死亡或时间用尽时，我们需要将`paused`设置为`true`。

在上一章中，我们初步了解了 C++字符串。我们需要更多地了解它们，以便实现玩家的 HUD。

# C++字符串

在上一章中，我们简要提到了字符串，并且了解到字符串可以包含从单个字符到整本书的字母数字数据。我们没有研究声明、初始化或操作字符串。所以现在让我们来做。

## 声明字符串

声明字符串变量很简单。我们声明类型，然后是名称：

```cpp
String levelName; 
String playerName; 

```

一旦我们声明了一个字符串，我们就可以为它赋值。

## 为字符串赋值

与常规变量一样，要为字符串赋值，我们只需放置名称，然后是赋值运算符，然后是值：

```cpp
levelName = "Dastardly Cave"; 
playerName = "John Carmack"; 

```

注意，值需要用引号括起来。与常规变量一样，我们也可以在一行中声明和赋值：

```cpp
String score = "Score = 0"; 
String message = "GAME OVER!!"; 

```

这就是我们如何改变我们的字符串变量。

## 操作字符串

我们可以使用`#include <sstream>`指令为我们的字符串提供一些额外的功能。`sstream`类使我们能够将一些字符串连接在一起。当我们这样做时，它被称为**连接**：

```cpp
String part1 = "Hello "; 
String part2 = "World"; 

sstream ss; 
ss << part1 << part2; 

// ss now holds "Hello World" 

```

除了使用`sstream`对象外，字符串变量甚至可以与不同类型的变量连接在一起。下面的代码开始揭示了字符串对我们可能非常有用：

```cpp
String scoreText = "Score = "; 
int score = 0; 

// Later in the code 
score ++; 

sstream ss; 
ss << scoreText << score; 
// ss now holds "Score = 1" 

```

### 提示

`<<`运算符是一个位运算符。然而，C++允许您编写自己的类，并在类的上下文中重写特定运算符的功能。`sstream`类已经这样做了，使`<<`运算符按照它的方式工作。复杂性被隐藏在类中。我们可以使用它的功能而不必担心它是如何工作的。如果你感到有冒险精神，你可以阅读关于运算符重载的内容：[`www.tutorialspoint.com/cplusplus/cpp_overloading.htm`](http://www.tutorialspoint.com/cplusplus/cpp_overloading.htm)。为了继续项目，你不需要更多的信息。

现在我们知道了 C++字符串的基础知识，以及我们如何使用`sstream`，我们可以看到如何使用一些 SFML 类来在屏幕上显示它们。

# SFML Text 和 Font

在我们实际添加代码到我们的游戏之前，让我们简要讨论一下`Text`和`Font`类以及一些假设的代码。

在屏幕上绘制文本的第一步是拥有一个字体。在第一章中，我们将一个字体文件添加到了项目文件夹中。现在我们可以将字体加载到 SFML `Font`对象中，准备使用。

要这样做的代码看起来像这样：

```cpp
Font font; 
font.loadFromFile("myfont.ttf"); 

```

在前面的代码中，我们首先声明了`Font`对象，然后加载了一个实际的字体文件。请注意，`myfont.ttf`是一个假设的字体，我们可以使用项目文件夹中的任何字体。

一旦我们加载了一个字体，我们就需要一个 SFML `Text`对象：

```cpp
Text myText; 

```

现在我们可以配置我们的`Text`对象。这包括大小、颜色、屏幕上的位置、包含消息的字符串，当然，将其与我们的`font`对象关联起来：

```cpp
// Assign the actual message 
myText.setString("Press Enter to start!"); 

// assign a size 
myText.setCharacterSize(75); 

// Choose a color 
myText.setFillColor(Color::White); 

// Set the font to our Text object 
myText.setFont(font); 

```

让我们给 Timber 添加一个 HUD！！！

# 添加分数和消息

现在我们已经了解了足够关于字符串、SFML `Text`和 SFML `Font`，可以开始实现 HUD 了。

我们需要做的下一件事是在代码文件的顶部添加另一个`#include`指令。正如我们所学到的，`sstream`类为将字符串和其他变量类型组合成一个字符串提供了一些非常有用的功能。

添加下面高亮代码的一行：

```cpp
#include "stdafx.h" 
#include <sstream> 
#include <SFML/Graphics.hpp> 

using namespace sf; 

int main() 
{ 

```

接下来我们将设置我们的 SFML `Text`对象。一个将包含一条消息，我们将根据游戏状态进行变化，另一个将包含分数，并且需要定期更新。

声明`Text`和`Font`对象的下一个代码加载字体，将字体分配给`Text`对象，然后添加字符串消息、颜色和大小。这应该从我们在上一节讨论中看起来很熟悉。此外，我们添加了一个名为`score`的新`int`变量，我们可以操纵它来保存玩家的分数。

### 提示

请记住，如果你在第一章中选择了不同的字体，你需要更改代码的部分以匹配你在`Visual Studio Stuff/Projects/Timber/Timber/fonts`文件夹中拥有的`.ttf`文件。

添加高亮代码，我们就可以准备好继续更新 HUD 了：

```cpp
// Track whether the game is running 
bool paused = true; 

// Draw some text
int score = 0;

sf::Text messageText;
sf::Text scoreText;

// We need to choose a font
Font font;
font.loadFromFile("fonts/KOMIKAP_.ttf");

// Set the font to our message
messageText.setFont(font);
scoreText.setFont(font);

// Assign the actual message
messageText.setString("Press Enter to start!");
scoreText.setString("Score = 0");

// Make it really big
messageText.setCharacterSize(75);
scoreText.setCharacterSize(100);

// Choose a color
messageText.setFillColor(Color::White);
scoreText.setFillColor(Color::White); 

while (window.isOpen()) 
{ 

   /* 
   **************************************** 
   Handle the players input 
   **************************************** 
   */ 

```

下面的代码可能看起来有点复杂，甚至复杂。然而，当你稍微分解一下时，它实际上非常简单。检查并添加新代码，然后我们将一起讨论：

```cpp
// Choose a color 
messageText.setFillColor(Color::White); 
scoreText.setFillColor(Color::White); 

// Position the text
FloatRect textRect = messageText.getLocalBounds();

messageText.setOrigin(textRect.left +
  textRect.width / 2.0f,
  textRect.top +
  textRect.height / 2.0f);

messageText.setPosition(1920 / 2.0f, 1080 / 2.0f);

scoreText.setPosition(20, 20); 

while (window.isOpen()) 
{ 

   /* 
   **************************************** 
   Handle the players input 
   **************************************** 
   */ 

```

我们有两个`Text`类型的对象将显示在屏幕上。我们希望将`scoreText`定位在左上角并留有一点填充。这并不困难；我们只需使用`scoreText.setPosition(20, 20)`，它就会在左上角定位，并留有 20 像素的水平和垂直填充。

然而，定位`messageText`并不那么容易。我们希望将其定位在屏幕的正中间。最初这可能看起来不是问题，但我们记得我们绘制的一切的原点都是左上角。因此，如果我们简单地将屏幕的宽度和高度除以二，并在`mesageText.setPosition...`中使用结果，那么文本的左上角将位于屏幕的中心，并且会不整齐地向右边展开。

我们需要一种方法来将`messageText`的中心设置为屏幕的中心。您刚刚添加的看起来相当恶劣的代码重新定位了`messageText`的原点到其自身的中心。为了方便起见，这里是当前讨论的代码：

```cpp
// Position the text 
FloatRect textRect = messageText.getLocalBounds(); 

messageText.setOrigin(textRect.left + 
   textRect.width / 2.0f, 
   textRect.top + 
   textRect.height / 2.0f); 

```

首先，在这段代码中，我们声明了一个名为`textRect`的新的`FloatRect`类型的对象。正如其名称所示，`FloatRect`对象保存了一个带有浮点坐标的矩形。

然后，代码使用`messageText.getLocalBounds`函数来使用`messageText`包装的矩形的坐标来初始化`textRect`。

接下来的代码行，由于它相当长，分成了四行，使用`messageText.setOrigin`函数将原点（我们绘制的点）更改为`textRect`的中心。当然，`textRect`保存了一个矩形，它完全匹配包装`messageText`的坐标。然后，执行下一行代码：

```cpp
messageText.setPosition(1920 / 2.0f,   1080 / 2.0f); 

```

现在，`messageText`将被整齐地定位在屏幕的正中间。每次更改`messageText`的文本时，我们将使用完全相同的代码，因为更改消息会改变`messageText`的大小，因此其原点需要重新计算。

接下来，我们声明了一个名为`ss`的`stringstream`类型的对象。请注意，我们使用了完整的名称，包括命名空间`std::stringstream`。我们可以通过在代码文件顶部添加`using namespace std`来避免这种语法。然而，我们没有这样做，因为我们很少使用它。看一下代码，将其添加到游戏中，然后我们可以更详细地讨论一下。由于我们只希望在游戏暂停时执行此代码，请确保将其与其他代码一起添加到`if(!paused)`块中，如下所示：

```cpp
else 
   { 

      spriteCloud3.setPosition( 
         spriteCloud3.getPosition().x + 
         (cloud3Speed * dt.asSeconds()), 
         spriteCloud3.getPosition().y); 

      // Has the cloud reached the right hand edge of the screen? 
      if (spriteCloud3.getPosition().x > 1920) 
      { 
         // Set it up ready to be a whole new cloud next frame 
         cloud3Active = false; 
      } 
   } 

 // Update the score text   
   std::stringstream ss;   
   ss << "Score = " << score;   
   scoreText.setString(ss.str()); 

}// End if(!paused) 

/* 
**************************************** 
Draw the scene 
**************************************** 
*/ 

```

我们使用`ss`和`<<`运算符提供的特殊功能，它将变量连接到`stringstream`中。因此，代码`ss << "Score = " << score`的效果是创建一个包含`"Score = "`和`score`值的字符串，它们被连接在一起。例如，当游戏刚开始时，`score`等于零，所以`ss`将保存值`"Score = 0"`。如果`score`发生变化，`ss`将在每一帧适应。

接下来的代码简单地显示/设置了`ss`中包含的字符串到`scoreText`。

```cpp
scoreText.setString(ss.str());
```

现在可以绘制到屏幕上了。

接下来的代码绘制了两个`Text`对象（`scoreText`和`messageText`），但请注意，绘制`messageText`的代码包含在一个`if`语句中。这个`if`语句导致只有在游戏暂停时才绘制`messageText`。

添加下面显示的突出代码：

```cpp
// Now draw the insect 
window.draw(spriteBee); 

// Draw the score
window.draw(scoreText);
if (paused)
{   
  // Draw our message   
  window.draw(messageText);
} 

// Show everything we just drew 
window.display(); 

```

现在我们可以运行游戏，看到我们的 HUD 绘制在屏幕上。您将看到**SCORE = 0**和 PRESS ENTER TO START!消息。当您按下***Enter***时，后者将消失。

![添加得分和消息](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_03_001.jpg)

如果您想要看到分数更新，请在`while(window.isOpen)`循环中的任何位置添加临时代码`score ++;`。如果您添加了这行临时代码，您将看到分数迅速上升，非常快！

![添加得分和消息](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_03_002.jpg)

如果您添加了临时代码`score ++;`，请务必在继续之前将其删除。

# 添加时间条

由于时间是游戏中的一个关键机制，必须让玩家意识到它。他需要知道自己被分配的六秒即将用完。这将在游戏接近结束时给他一种紧迫感，并且如果他表现得足够好以保持或增加剩余时间，他会有一种成就感。

在屏幕上绘制剩余秒数并不容易阅读（当专注于分支时），也不是实现目标的特别有趣的方式。

我们需要的是一个时间条。我们的时间条将是一个简单的红色矩形，在屏幕上显眼地展示。它将从宽度开始，但随着时间的流逝迅速缩小。当玩家剩余时间达到零时，时间条将完全消失。

同时添加时间条的同时，我们将添加必要的代码来跟踪玩家剩余的时间，并在他用完时间时做出响应。让我们一步一步地进行。

从前面的`Clock clock;`声明中添加突出显示的代码：

```cpp
// Variables to control time itself 
Clock clock; 

// Time bar
RectangleShape timeBar;
float timeBarStartWidth = 400;
float timeBarHeight = 80;
timeBar.setSize(Vector2f(timeBarStartWidth, timeBarHeight));
timeBar.setFillColor(Color::Red);
timeBar.setPosition((1920 / 2) - timeBarStartWidth / 2, 980);

Time gameTimeTotal;
float timeRemaining = 6.0f;
float timeBarWidthPerSecond = timeBarStartWidth / timeRemaining; 

// Track whether the game is running 
bool paused = true; 

```

首先，我们声明了一个`RectangleShape`类型的对象，并将其命名为`timeBar`。`RectangleShape`是一个适合绘制简单矩形的 SFML 类。

接下来，我们添加了一些`float`变量，`timeBarStartWidth`和`timeBarHeight`。我们分别将它们初始化为`400`和`80`。这些变量将帮助我们跟踪每一帧需要绘制`timeBar`的大小。

接下来，我们使用`timeBar.setSize`函数设置`timeBar`的大小。我们不只是传入我们的两个新的`float`变量。首先，我们创建一个`Vector2f`类型的新对象。然而，这里的不同之处在于，我们没有给新对象命名。我们只是用我们的两个浮点变量初始化它，并直接传递给`setSize`函数。

### 提示

`Vector2f`是一个持有两个`float`变量的类。它还有一些其他功能，将在整本书中介绍。

之后，我们使用`setFillColor`函数将`timeBar`颜色设置为红色。

我们在前面的代码中对`timeBar`做的最后一件事是设置它的位置。y 坐标非常直接，但我们设置 x 坐标的方式略微复杂。这里是计算：

```cpp
(1920 / 2) - timeBarStartWidth / 2
```

代码首先将`1920`除以`2`。然后将`timeBarStartWidth`除以`2`。最后从前者中减去后者。

结果使`timeBar`在屏幕上漂亮地水平居中。

我们要讨论的代码的最后三行声明了一个名为`gameTimeTotal`的新`Time`对象，一个名为`timeRemaining`的新`float`，它初始化为`6`，以及一个听起来奇怪的名为`timeBarWidthPerSecond`的`float`，我们将进一步讨论。

`timeBarWidthPerSecond`变量是用`timeBarStartWidth`除以`timeRemaining`初始化的。结果恰好是`timeBar`每秒需要缩小的像素数量。这在我们每一帧调整`timeBar`的大小时会很有用。

显然，我们需要在玩家开始新游戏时重置剩余时间。这样做的逻辑位置是***Enter***键按下。我们也可以同时将`score`重置为零。现在让我们通过添加这些突出显示的代码来做到这一点：

```cpp
// Start the game 
if (Keyboard::isKeyPressed(Keyboard::Return)) 
{ 
   paused = false; 

 // Reset the time and the score   
   score = 0;   
   timeRemaining = 5; 
 } 

```

现在，每一帧我们都必须减少剩余时间的数量，并相应地调整`timeBar`的大小。在更新部分添加以下突出显示的代码，如下所示：

```cpp
/* 
**************************************** 
Update the scene 
**************************************** 
*/ 
if (!paused) 
{ 
   // Measure time 
   Time dt = clock.restart(); 

 // Subtract from the amount of time remaining   
   timeRemaining -= dt.asSeconds();
   // size up the time bar
   timeBar.setSize(Vector2f(timeBarWidthPerSecond *
     timeRemaining, timeBarHeight)); 

   // Set up the bee 
   if (!beeActive) 
   { 

      // How fast is the bee 
      srand((int)time(0) * 10); 
      beeSpeed = (rand() % 200) + 200; 

      // How high is the bee 
      srand((int)time(0) * 10); 
      float height = (rand() % 1350) + 500; 
      spriteBee.setPosition(2000, height); 
      beeActive = true; 

   } 
   else 
      // Move the bee 

```

首先，我们用这段代码减去了玩家剩余的时间与上一帧执行所花费的时间：

```cpp
timeRemaining -= dt.asSeconds(); 

```

然后，我们用以下代码调整了`timeBar`的大小：

```cpp
timeBar.setSize(Vector2f(timeBarWidthPerSecond * 
      timeRemaining, timeBarHeight)); 

```

`Vector2F`的 x 值是用`timebarWidthPerSecond`乘以`timeRemaining`初始化的。这产生了与玩家剩余时间相关的正确宽度。高度保持不变，`timeBarHeight`在没有任何操作的情况下使用。

当然，我们必须检测时间是否已经用完。现在，我们将简单地检测时间是否已经用完，暂停游戏，并更改`messageText`的文本。稍后我们会在这里做更多的工作。在我们添加的先前代码之后添加突出显示的代码，我们将更详细地查看它：

```cpp
// Measure time 
Time dt = clock.restart(); 

// Subtract from the amount of time remaining 
timeRemaining -= dt.asSeconds(); 

// resize up the time bar 
timeBar.setSize(Vector2f(timeBarWidthPerSecond * 
   timeRemaining, timeBarHeight)); 

if (timeRemaining <= 0.0f) 
{   
  // Pause the game   
  paused = true;   

  // Change the message shown to the player   
  messageText.setString("Out of time!!");   

  //Reposition the text based on its new size   
  FloatRect textRect = messageText.getLocalBounds();
  messageText.setOrigin(textRect.left +     
    textRect.width / 2.0f,     
    textRect.top +     
    textRect.height / 2.0f);   

  messageText.setPosition(1920 / 2.0f, 1080 / 2.0f);
} 

// Set up the bee 
if (!beeActive) 
{ 

   // How fast is the bee 
   srand((int)time(0) * 10); 
   beeSpeed = (rand() % 200) + 200; 

   // How high is the bee 
   srand((int)time(0) * 10); 
   float height = (rand() % 1350) + 500; 
   spriteBee.setPosition(2000, height); 
   beeActive = true; 

} 
else 
   // Move the bee 

```

逐步执行先前的代码：

+   首先，我们用`if(timeRemaining <= 0.0f)`测试时间是否已经用完

+   然后我们将`paused`设置为`true`，这样我们的代码的更新部分将被执行的最后一次（直到玩家再次按***Enter***）。

+   然后我们更改`messageText`的消息，计算其新的中心以设置为其原点，并将其定位在屏幕中心。

最后，在代码的这一部分，我们需要绘制`timeBar`。在这段代码中，没有任何新的东西，我们以前见过很多次。只需注意我们在树之后绘制`timeBar`，这样它就可见。添加突出显示的代码来绘制时间条：

```cpp
// Draw the score 
window.draw(scoreText); 

// Draw the timebar
window.draw(timeBar); 

if (paused) 
{ 
   // Draw our message 
   window.draw(messageText); 
} 

// Show everything we just drew 
window.display(); 

```

现在您可以运行游戏。按***Enter***开始，并观察时间条平稳地消失到无。

![添加时间条](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_03_003.jpg)

游戏暂停，**时间用完了！！**消息将出现。

![添加时间条](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_03_004.jpg)

当然，您可以再次按***Enter***从头开始运行整个游戏。

# 常见问题解答

Q) 我可以预见，通过精灵的左上角定位有时可能会不方便。

A) 幸运的是，您可以选择使用精灵的哪个点作为定位/原点像素，就像我们使用`setOrigin`函数设置`messageText`一样。

Q) 代码变得相当长，我很难跟踪一切的位置。

A) 是的，我同意。在下一章中，我们将看到我们可以组织我们的代码的第一种方式，使其更易读。当我们学习编写 C++函数时，我们将看到这一点。此外，当我们学习关于 C++数组时，我们将学习一种处理相同类型的多个对象/变量（如云）的新方法。

# 总结

在本章中，我们学习了关于字符串、SFML `Text`和 SFML `Font`。它们使我们能够在屏幕上绘制文本，为玩家提供了 HUD。我们还使用了`sstream`，它允许我们连接字符串和其他变量来显示分数。

我们探索了 SFML `RectangleShape`类，它正是其名称所暗示的。我们使用了`RectangleShape`类型的对象和一些精心计划的变量来绘制一个时间条，直观地显示玩家剩余的时间。一旦我们实现了砍树和移动的树枝可以压扁玩家，时间条将产生紧张感和紧迫感。

接下来，我们将学习一系列新的 C++特性，包括循环、数组、切换、枚举和函数。这将使我们能够移动树枝，跟踪它们的位置，并压扁玩家。


# 第四章：循环，数组，开关，枚举和函数-实现游戏机制

本章可能包含的 C++信息比书中的任何其他章节都要多。它充满了将极大地推动我们的理解的基本概念。它还将开始阐明我们一直略微忽略的一些模糊领域，例如函数和游戏循环。

一旦我们探索了整个 C++语言必需品清单，然后我们将利用我们所知道的一切来使主要游戏机制-树枝移动。在本章结束时，我们将准备进入最后阶段并完成《伐木者》。

我们将研究以下主题：

+   循环

+   数组

+   使用开关进行决策

+   枚举

+   开始使用函数

+   创建和移动树枝

# 循环

在编程中，我们经常需要做同样的事情超过一次。到目前为止，我们看到的明显例子是我们的游戏循环。在剥离所有代码的情况下，我们的游戏循环看起来像这样：

```cpp
while (window.isOpen()) 
{      

} 

```

有几种不同类型的循环，我们将看看最常用的。这种类型的循环的正确术语是`while`循环。

## while 循环

`while`循环非常简单。回想一下`if`语句及其表达式，这些表达式评估为`true`或`false`。我们可以在`while`循环的条件表达式中使用相同的运算符和变量的组合。

与`if`语句一样，如果表达式为`true`，则代码执行。然而，与`while`循环相比，C++代码将继续执行，直到条件为`false`。看看这段代码：

```cpp
int numberOfZombies = 100; 

while(numberOfZombies > 0) 
{ 
   // Player kills a zombie 
   numberOfZombies--; 

   // numberOfZombies decreases each pass through the loop 
} 

// numberOfZOmbies is no longer greater than 0 

```

这是以前的代码中发生的事情。在`while`循环之外，声明并初始化`int numberOfZombies`为`100`。然后`while`循环开始。它的条件表达式是`numberOfZombies > 0`。因此，`while`循环将继续循环执行其主体中的代码，直到条件评估为`false`。这意味着上面的代码将执行 100 次。

在循环的第一次通过中，`numberOfZombies`等于 100，然后等于 99，然后等于 98，依此类推。但一旦`numberOfZOmbies`等于零，当然不再大于零。然后代码将跳出`while`循环并继续运行，在闭合大括号之后。

就像`if`语句一样，`while`循环可能不会执行一次。看看这个：

```cpp
int availableCoins = 10; 

while(availableCoins > 10) 
{ 
   // more code here. 
   // Won't run unless availableCoins is greater than 10 
} 

```

此外，表达式的复杂性或可以放入循环主体的代码量没有限制。考虑游戏循环的这种假设变体：

```cpp
int playerLives = 3; 
int alienShips = 10; 

while(playerLives !=0 && alienShips !=0 ) 
{ 
   // Handle input 
   // Update the scene 
   // Draw the scene 
} 

// continue here when either playerLives or alienShips equals 0 

```

以前的`while`循环将继续执行，直到`playerLives`或`alienShips`之一等于零。一旦发生其中一个条件，表达式将评估为`false`，程序将从`while`循环之后的第一行代码继续执行。

值得注意的是，一旦进入循环的主体，即使表达式在中途评估为`false`，它也将至少完成一次，因为在代码尝试开始另一个传递之前不会再次测试。例如：

```cpp
int x = 1; 

while(x > 0) 
{ 
   x--; 
   // x is now 0 so the condition is false 
   // But this line still runs 
   // and this one 
   // and me! 
} 

// Now I'm done! 

```

以前的循环体将执行一次。我们还可以设置一个永远运行的`while`循环，毫不奇怪地称为**无限循环**。这是一个例子：

```cpp
int y = 0; 

while(true) 
{ 
   y++; // Bigger... Bigger... 
} 

```

如果您觉得上面的循环令人困惑，只需字面理解。当条件为`true`时，循环执行。嗯，`true`总是`true`，因此将继续执行。

### 跳出 while 循环

我们可能会使用无限循环，以便我们可以决定何时从循环中退出，而不是在表达式中。当我们准备离开循环主体时，我们将使用`break`关键字来做到这一点。也许会像这样：

```cpp
int z = 0; 

while(true) 
{ 
   z++; // Bigger... Bigger... 
 break; // No you're not 

   // Code doesn't reach here 
} 

```

你可能也能猜到，我们可以在 `while` 循环和其他循环类型中结合使用任何 C++ 决策工具，比如 `if`、`else`，以及我们即将学习的 `switch`。考虑这个例子：

```cpp
int x = 0; 
int max = 10; 

while(true) 
{ 
   x++; // Bigger... Bigger... 

 if(x == max)
   {     
     break;   
   } // No you're not 

   // code reaches here only until x = 10 
} 

```

我们可以花很长时间来研究 C++ `while` 循环的各种排列，但在某个时候我们想要回到制作游戏。所以让我们继续前进，看看另一种类型的循环。

## for 循环

`for` 循环的语法比 `while` 循环稍微复杂一些，因为它需要三个部分来设置。先看看代码，然后我们将把它分解开来：

```cpp
for(int x = 0; x < 100; x ++) 
{ 
   // Something that needs to happen 100 times goes here 
} 

```

这是 `for` 循环条件的所有部分的作用。

`for(`声明和初始化`;` 条件`;` 每次迭代前更改`)`

为了进一步澄清，这里有一个表格来解释前面 `for` 循环例子中的所有三个关键部分。

| **部分** | **描述** |
| --- | --- |
| 声明和初始化 | 我们创建一个新的 `int` 变量 `i`，并将其初始化为 0 |
| 条件 | 就像其他循环一样，它指的是必须为循环执行的条件 |
| 循环通过每次迭代后更改 | 在这个例子中，`x ++` 表示每次迭代时 `x` 增加/递增 1 |

我们可以改变 `for` 循环来做更多的事情。下面是另一个简单的例子，从 10 开始倒数：

```cpp
for(int i = 10; i > 0; i--) 
{ 
   // countdown 
} 

// blast off 

```

`for` 循环控制初始化、条件评估和控制变量。我们将在本章后面在我们的游戏中使用 `for` 循环。

# 数组

如果一个变量是一个可以存储特定类型值的盒子，比如 `int`、`float` 或 `char`，那么我们可以把数组看作是一整行盒子。盒子的行可以是几乎任何大小和类型，包括类的对象。然而，所有的盒子必须是相同的类型。

### 提示

在最终项目中，一旦我们学习了更高级的 C++，就可以规避在每个盒子中使用相同类型的限制。

这个数组听起来可能对我们在第二章中的云有用：*变量、运算符和决策 - 动画精灵*。那么我们如何创建和使用数组呢？

## 声明一个数组

我们可以这样声明一个 `int` 类型变量的数组：

```cpp
int someInts[10]; 

```

现在我们有一个名为 `someInts` 的数组，可以存储十个 `int` 值。然而，目前它是空的。

## 初始化数组的元素

为了向数组的元素添加值，我们可以使用我们已经熟悉的类型的语法，结合一些新的语法，称为**数组表示法**。在下面的代码中，我们将值 `99` 存储到数组的第一个元素中：

```cpp
someInts[0] = 99; 

```

要在第二个元素中存储值 `999`，我们写下这段代码：

```cpp
someInts[1] = 999; 

```

我们可以将值 `3` 存储在最后一个元素中，如下所示：

```cpp
someInts[9] = 3; 

```

请注意，数组的元素始终从零开始，直到数组大小减 1。与普通变量类似，我们可以操作数组中存储的值。唯一的区别是我们会使用数组表示法来做到这一点，因为虽然我们的数组有一个名字 `someInts`，但是单独的元素没有名字。

在下面的代码中，我们将第一个和第二个元素相加，并将答案存储在第三个元素中：

```cpp
someInts[2] = someInts[0] + someInts[1]; 

```

数组也可以与常规变量无缝交互，比如下面的例子：

```cpp
int a = 9999; 
someInts[4] = a; 

```

### 快速初始化数组的元素

我们可以快速地向元素添加值，比如这个使用 `float` 数组的例子：

```cpp
float myFloatingPointArray[3] {3.14f, 1.63f, 99.0f}; 

```

现在值 `3.14`，`1.63` 和 `99.0` 分别存储在第一、第二和第三位置。请记住，使用数组表示法访问这些值时，我们将使用 [0]、[1] 和 [2]。

还有其他方法来初始化数组的元素。这个稍微抽象的例子展示了使用 `for` 循环将值 0 到 9 放入 `uselessArray` 数组中：

```cpp
for(int i = 0; i < 10; i++) 
{ 
   uselessArray[i] = i; 
} 

```

该代码假设 `uslessArray` 之前已经被初始化为至少包含 `10` 个 `int` 变量。

## 那么这些数组对我们的游戏到底有什么作用呢？

我们可以在任何常规变量可以使用的地方使用数组。例如，它们可以在表达式中使用，如下所示：

```cpp
// someArray[] is declared and initialized with 9999 values

for(int i = 0; i < 9999; i++) 
{ 
   // Do something with each entry in the array 
} 

```

数组在游戏代码中的最大好处可能是在本节开始时暗示的。数组可以保存对象（类的实例）。假设我们有一个`Zombie`类，并且我们想要存储大量的`Zombie`。我们可以像在这个假设的例子中那样做：

```cpp
Zombie horde [5] {zombie1, zombie2, zombie3}; // etc... 

```

`horde`数组现在保存了大量`Zombie`类的实例。每个实例都是一个独立的、活着的（有点），呼吸着的、自主决定的`Zombie`对象。然后我们可以循环遍历`horde`数组，在游戏循环的每一次通过中，移动僵尸，检查它们的头是否被斧头砍中，或者它们是否设法抓住了玩家。

如果当时我们知道数组，它们将非常适合处理我们的云。我们可以拥有任意数量的云，并且编写的代码比我们为我们的三朵微不足道的云所做的要少。

### 提示

要查看完整的改进的云代码，并且看它实际运行，可以查看下载包中《伐木工》（代码和可玩游戏）的增强版本。或者您可以在查看代码之前尝试使用数组实现云。

了解所有这些数组内容的最佳方法是看它们的实际应用。当我们实现我们的树枝时，我们将会看到它们的应用。

现在我们将保留我们的云代码，以便尽快回到游戏中添加功能。但首先让我们再看一下使用`switch`进行更多 C++决策的内容。

# 使用`switch`做决策

我们已经看到了`if`，它允许我们根据表达式的结果来决定是否执行一段代码块。有时，在 C++中做决定可能有其他更好的方法。

当我们必须基于一系列可能的结果做出决定时，其中不涉及复杂的组合或广泛的数值范围，通常情况下会使用`switch`。我们可以在以下代码中看到`switch`决策的开始：

```cpp
switch(expression) 
{ 

   // More code here 
} 

```

在前面的例子中，`expression`可以是一个实际的表达式或一个变量。然后，在花括号内，我们可以根据表达式的结果或变量的值做出决定。我们可以使用`case`和`break`关键字来实现这一点：

```cpp
case x: 
    //code to for x 
    break; 

case y: 
    //code for y 
    break; 

```

在前面的抽象例子中，您可以看到，每个`case`表示一个可能的结果，每个`break`表示该`case`的结束以及执行离开`switch`块的地方。

我们还可以选择使用`default`关键字而不带值，以便在没有任何`case`语句评估为`true`时运行一些代码。以下是一个例子：

```cpp
default: // Look no value 
    // Do something here if no other case statements are true 
    break; 

```

作为`switch`的最后一个不太抽象的例子，考虑一个复古的文本冒险游戏，玩家输入一个字母，比如`'n'`、`'e'`、`'s'`或`'w'`来向北、东、南或西移动。`switch`块可以用来处理玩家的每个可能的输入，就像我们在这个例子中看到的那样：

```cpp
// get input from user in a char called command 

switch(command){ 

   case 'n': 
      // Handle move here 
      break; 

   case 'e': 
      // Handle move here 
      break; 

   case 's': 
      // Handle move here 
      break; 

   case 'w': 
      // Handle move here 
      break;    

   // more possible cases 

   default: 
      // Ask the player to try again 
      break; 

} 

```

了解我们学到的关于`switch`的一切最好的方法是将它与我们正在学习的所有其他新概念一起应用。

# 类枚举

枚举是逻辑集合中所有可能值的列表。C++枚举是列举事物的好方法。例如，如果我们的游戏使用的变量只能在特定范围的值中，而且这些值在逻辑上可以形成一个集合或一组，那么枚举可能是合适的。它们将使您的代码更清晰，更不容易出错。

在 C++中声明类枚举，我们使用两个关键字`enum`和`class`，然后是枚举的名称，然后是枚举可以包含的值，用一对花括号`{...}`括起来。

例如，检查这个枚举声明。请注意，按照惯例，将枚举的可能值全部大写声明是常见的。

```cpp
enum class zombieTypes {REGULAR, RUNNER, CRAWLER, SPITTER, BLOATER }; 

```

注意，此时我们还没有声明任何`zombieType`的实例，只是类型本身。如果这听起来有点奇怪，可以这样想：SFML 创建了`Sprite`、`RectangleShape`和`RenderWindow`类，但要使用这些类中的任何一个，我们必须声明一个对象/实例。

此时我们已经创建了一个名为`zombieTypes`的新类型，但我们还没有它的实例。所以现在让我们创建它们：

```cpp
zombieType dave = zombieTypes::CRAWLER; 
zombieType angela = zombieTypes::SPITTER 
zombieType jose = zombieTypes::BLOATER 

/* 
   Zombies are fictional creatures and any resemblance 
   to real people is entirely coincidental 
*/ 

```

接下来是对我们即将添加到 Timber!!!中的代码类型的 sneak preview。我们将想要跟踪树的哪一侧有分支或玩家，因此我们将声明一个名为`side`的枚举，如以下示例所示：

```cpp
enum class side { LEFT, RIGHT, NONE }; 

```

我们可以将玩家定位在左侧，如下所示：

```cpp
// The player starts on the left 
side playerSide = side::LEFT; 

```

我们可以使分支位置数组的第四级（数组从零开始）根本没有分支，如下所示：

```cpp
branchPositions[3] = side::NONE; 

```

我们也可以在表达式中使用枚举：

```cpp
if(branchPositions[5] == playerSide) 
{ 
   // The lowest branch is the same side as the player 
   // SQUISHED!! 
} 

```

我们将再看一个重要的 C++主题，然后我们将回到编写游戏的代码。

# 开始使用函数

那么 C++函数到底是什么？函数是一组变量、表达式和**控制流语句**（循环和分支）。事实上，我们迄今为止在书中学到的任何代码都可以在函数中使用。我们编写的函数的第一部分称为**签名**。以下是一个示例函数签名：

```cpp
public void bombPlayer(int power, int direction) 

```

如果我们添加一对大括号`{...}`，里面包含一些函数实际执行的代码，那么我们就有了一个完整的函数，一个定义：

```cpp
void shootLazers(int power, int direction) 
{ 
    // ZAPP! 
} 

```

然后我们可以在代码的其他部分使用我们的新函数，如下所示：

```cpp
// Attack the player 
bombPlayer(50, 180) // Run the code in the function 
//  I'm back again - code continues here after the function ends 

```

当我们使用一个函数时，我们说我们**调用**它。在我们调用`bombPlayer`的地方，我们的程序的执行分支到该函数中包含的代码。函数将运行直到达到结尾或被告知`return`。然后代码将从函数调用后的第一行继续运行。我们已经在使用 SFML 提供的函数。这里不同的是，我们将学习编写和调用我们自己的函数。

这是另一个函数的例子，包括使函数返回到调用它的代码的代码：

```cpp
int addAToB(int a, int b) 
{ 
   int answer = a + b; 
   return answer; 
} 

```

调用上述函数的方式可能如下所示：

```cpp
int myAnswer = addAToB(2, 4); 

```

显然，我们不需要编写函数来将两个变量相加，但这个例子帮助我们更深入地了解函数的工作原理。首先我们传入值`2`和`4`。在函数签名中，值`2`被赋给`int a`，值`4`被赋给`int b`。

在函数体内，变量`a`和`b`相加并用于初始化新变量`int answer`。行`return answer;`就是这样。它将存储在`answer`中的值返回给调用代码，导致`myAnswer`被初始化为值`6`。

请注意，上面示例中的每个函数签名都有所不同。之所以如此，是因为 C++函数签名非常灵活，允许我们构建我们需要的函数。

函数签名的确切方式定义了函数必须如何被调用以及函数必须如何返回值，这值得进一步讨论。让我们给该签名的每个部分命名，这样我们就可以将其分解成部分并学习它们。

以下是一个函数签名，其各部分由其正式的技术术语描述：

```cpp
return type | name of function | (parameters)
```

以下是我们可以用于每个部分的一些示例：

+   **返回类型**：`bool`、`float`、`int` 等，或任何 C++类型或表达式

+   **函数名称**：`bombPlayer`, `shootLazers`, `setCoordinates`, `addAToB` 等等

+   **参数**：`(int number, bool hitDetected)`, `(int x, int y)` `(float a, float b)`

现在让我们依次看看每个部分。

## 函数返回类型

返回类型，顾名思义，是从函数返回到调用代码的值的类型：

```cpp
int addAToB(int a, int b)
{
    int answer = a + b; 
    return answer; 
} 

```

在我们稍微沉闷但有用的`addAtoB`示例中，签名中的返回类型是`int`。函数`addAToB`将一个值返回给调用它的代码，这个值将适合在一个`int`变量中。返回类型可以是我们到目前为止看到的任何 C++类型，或者是我们还没有看到的类型之一。

然而，函数不一定要返回一个值。在这种情况下，签名必须使用`void`关键字作为返回类型。当使用`void`关键字时，函数体不得尝试返回一个值，否则将导致错误。但是，它可以使用没有值的`return`关键字。以下是一些返回类型和`return`关键字的组合：

```cpp
void doWhatever()
{ 

    // our code 
    // I'm done going back to calling code here 
    // no return is necessary 

} 

```

另一个可能性如下：

```cpp
void doSomethigCool()
{ 

   // our code 

   // I can do this as long as I don't try and add a value 
   return; 
} 

```

以下代码给出了更多可能的函数示例。一定要阅读注释以及代码：

```cpp
void doYetAnotherThing()
{ 
   // some code 

   if(someCondition)
   { 

      // if someCondition is true returning to calling code 
      // before the end of the function body 
      return; 
   } 

   // More code that might or might not get executed 

   return; 

   // As I'm at the bottom of the function body 
   // and the return type is void, I'm 
   // really not necessary but I suppose I make it 
   // clear that the function is over. 
 } 

bool detectCollision(Ship a, Ship b)
{ 

   // Detect if collision has occurred 
   if(collision) 
   { 
      // Bam!!! 
      return true; 
   } 
   else 
   { 
      // Missed 
      return false; 
   } 

} 

```

上面的最后一个函数示例`detectCollision`是我们 C++代码即将到来的一个预览，并且演示了我们也可以将用户定义的类型，称为**对象**，传递到函数中对它们进行计算。

我们可以像这样依次调用上面的每个函数：

```cpp
// OK time to call some functions 
doWhatever(); 
doSomethingCool(); 
doYetAnotherThing(); 

if (detectCollision(milleniumFalcon, lukesXWing)) 
{ 
   // The jedi are doomed! 
   // But there is always Leia. 
   // Unless she was on the Falcon? 
} 
else 
{ 
   // Live to fight another day 
} 

//continue with code from here 

```

不要担心关于`detectCollision`函数的奇怪语法，我们很快就会看到像这样的真实代码。简单地说，我们将使用返回值（`true`或`false`）作为表达式，直接在`if`语句中。

## 函数名称

函数名称，当我们设计自己的函数时，可以是几乎任何东西。但最好使用单词，通常是动词，来清楚地解释函数将要做什么。例如，看看这个函数：

```cpp
void functionaroonieboonie(int blibbityblob, float floppyfloatything) 
{ 
   //code here 
} 

```

上面的示例是完全合法的，并且可以工作，但是下面的函数名称更加清晰：

```cpp
void doSomeVerySpecificTask() 
{ 
   //code here 
} 

void getMySpaceShipHealth() 
{ 
   //code here 
} 

void startNewGame() 
{ 
   //code here 
} 

```

接下来，让我们更仔细地看一下如何与函数共享一些值。

## 函数参数

我们知道函数可以将结果返回给调用代码。如果我们需要与函数共享一些来自调用代码的数据值呢？**参数**允许我们与函数共享值。实际上，我们在查看返回类型时已经看到了参数的示例。我们将更仔细地看一下相同的示例：

```cpp
int addAToB(int a, int b) 
{ 

   int answer = a + b; 
   return answer; 

} 

```

在上面的示例中，参数是`int a`和`int b`。请注意，在函数主体的第一行中，我们使用`a + b`，就好像它们已经声明和初始化了变量一样。那是因为它们确实是。函数签名中的参数是它们的声明，调用函数的代码初始化它们。

### 提示

**重要的行话说明**

请注意，我们在函数签名括号`(int a, int b)`中引用的变量被称为参数。当我们从调用代码中将值传递到函数中时，这些值被称为参数。当参数到达时，它们被称为参数，并用于初始化真正可用的变量：`int returnedAnswer = addAToB(10,5);`

此外，正如我们在先前的示例中部分看到的，我们不必只在参数中使用`int`。我们可以使用任何 C++类型。我们还可以使用尽可能少的参数列表来解决我们的问题，但是将参数列表保持短并且易于管理是一个很好的做法。

正如我们将在未来的章节中看到的，我们已经在这个入门教程中留下了一些更酷的函数用法，这样我们就可以在进一步学习函数主题之前学习相关的 C++概念。

## 函数主体

主体部分是我们一直在避免的部分，比如：

```cpp
// code here 
// some code 

```

但实际上，我们已经完全知道在这里该做什么！到目前为止，我们学到的任何 C++代码都可以在函数体中工作。

## 函数原型

我们已经看到了如何编写函数，也看到了如何调用函数。然而，我们还需要做一件事才能使它们工作。所有函数都必须有一个**原型**。原型是使编译器意识到我们的函数的东西；没有原型，整个游戏将无法编译。幸运的是，原型很简单。

我们可以简单地重复函数的签名，后面跟一个分号。但是要注意的是，原型必须出现在任何尝试调用或定义函数之前。因此，一个完全可用的函数的最简单示例如下。仔细看看注释以及函数的不同部分在代码中的位置：

```cpp
// The prototype 
// Notice the semicolon 
int addAToB(int a, int b); 

int main() 
{ 

   // Call the function 
   // Store the result in answer 
   int answer = addAToB(2,2); 

   // Called before the definition 
   // but that's OK because of the prototype 

   // Exit main 
   return 0; 

}// End of main 

// The function definition 
int addAToB(int a, int b) 
{ 
    return a + b; 
} 

```

前面的代码演示了以下内容：

+   原型在`main`函数之前

+   使用函数的调用，正如我们可能期望的那样，位于`main`函数内部

+   定义在`main`函数之后/外部

### 注意

请注意，当定义出现在函数使用之前时，我们可以省略函数原型直接进入定义。然而，随着我们的代码变得越来越长并且跨越多个文件，这几乎永远不会发生。我们将一直使用单独的原型和定义。

让我们看看如何保持我们的函数有组织性。

## 组织函数

值得指出的是，如果我们有多个函数，特别是如果它们相当长，我们的`.cpp`文件很快就会变得难以控制。这违背了函数的意图。我们将在下一个项目中看到的解决方案是，我们可以将所有函数原型添加到我们自己的头文件（`.hpp`或`.h`）中。然后我们可以在另一个`.cpp`文件中编写所有函数的代码，然后在我们的主`.cpp`文件中简单地添加另一个`#include...`指令。通过这种方式，我们可以使用任意数量的函数，而不需要将它们的任何代码（原型或定义）添加到我们的主代码文件中。

## 函数陷阱！

我们应该讨论的另一点是**作用域**。如果我们在函数中声明一个变量，无论是直接声明还是作为参数之一，那么该变量在函数外部是不可用/可见的。此外，函数外部声明的任何变量在函数内部也是看不到/使用不了的。

我们应该通过参数/参数和返回值在函数代码和调用代码之间共享值。

当一个变量不可用，因为它来自另一个函数，就说它是不在作用域内。当它可用和可用时，就说它在作用域内。

### 注意

实际上，在 C++中，只有在块内声明的变量才在该块内有效！这包括循环和`if`块。在`main`的顶部声明的变量在`main`中的任何地方都是有效的。在游戏循环中声明的变量只在游戏循环内有效，依此类推。在函数或其他块中声明的变量称为**局部**变量。我们写的代码越多，这一点就越有意义。每当我们在代码中遇到作用域问题时，我都会讨论一下，以澄清事情。在下一节中将会出现这样的问题。还有一些 C++的基本知识，会让这个问题变得更加明显。它们被称为**引用**和**指针**，我们将在第七章中学习：C++ *引用、精灵表和顶点数组*和第八章中学习：*指针、标准模板库和纹理管理*。

## 函数的最终话-暂时

关于函数，我们还有很多东西可以学习，但我们已经了解足够的知识来实现游戏的下一部分。如果所有技术术语，如参数、签名和定义等等，还没有完全理解，不要担心。当我们开始使用它们时，概念会变得更清晰。

## 函数的终极最后一句话-暂时

你可能已经注意到，我们一直在调用函数，特别是 SFML 函数，通过在函数名之前附加对象的名称和一个句号，如下例所示：

```cpp
spriteBee.setPosition... 
window.draw... 
// etc 

```

然而，我们对函数的整个讨论都是在没有任何对象的情况下调用函数。我们可以将函数编写为类的一部分，也可以将其编写为独立的函数。当我们将函数编写为类的一部分时，我们需要该类的对象来调用函数，而当我们有一个独立的函数时，我们不需要。

我们将在一分钟内编写一个独立的函数，并且我们将在第六章中编写以函数开头的类：*面向对象编程、类和 SFML 视图*。到目前为止，我们对函数的所有了解在这两种情况下都是相关的。

# 生长树枝

接下来，正如我在过去大约十七页中一直承诺的那样，我们将使用所有新的 C++技术来绘制和移动树上的一些树枝。

将此代码添加到`main`函数之外。为了绝对清楚，我的意思是在代码`int main()`之前：

```cpp
#include "stdafx.h" 
#include <sstream> 
#include <SFML/Graphics.hpp> 

using namespace sf; 

// Function declaration
void updateBranches(int seed);

const int NUM_BRANCHES = 6;
Sprite branches[NUM_BRANCHES];

// Where is the player/branch?
// Left or Right
enum class side { LEFT, RIGHT, NONE };
side branchPositions[NUM_BRANCHES]; 

int main() 
{ 

```

我们刚刚用新代码实现了很多事情：

+   首先，我们为一个名为`updateBranches`的函数声明了一个函数原型。我们可以看到它不返回值（`void`），并且它接受一个名为`seed`的`int`参数。我们将很快编写函数定义，然后我们将看到它确切地做了什么。

+   接下来，我们声明了一个名为`NUM_BRANCHES`的常量`int`，并将其初始化为`6`。树上将有六个移动的树枝，很快我们将看到`NUM_BRANCHES`对我们有多有用。

+   接下来，我们声明了一个名为`branches`的`Sprite`对象数组，可以容纳六个精灵。

+   之后，我们声明了一个名为`side`的新枚举，有三个可能的值，`LEFT`、`RIGHT`和`NONE`。这将用于描述个别树枝的位置，以及在我们的代码中的一些地方描述玩家的位置。

+   最后，在之前的新代码中，我们初始化了一个`side`类型的数组，大小为`NUM_BRANCHES`（6）。为了清楚地说明这实现了什么；我们将有一个名为`branchPositions`的数组，其中包含六个值。这些值中的每一个都是`side`类型，可以是`LEFT`、`RIGHT`或`NONE`。

### 注意

当然，你真正想知道的是为什么常量、两个数组和枚举被声明在`main`函数之外。通过在`main`之上声明它们，它们现在具有**全局范围**。或者，换句话说，常量、两个数组和枚举在整个游戏中都有范围。这意味着我们可以在`main`函数和`updateBranches`函数中的任何地方访问和使用它们。请注意，将所有变量尽可能地局部化到实际使用它们的地方是一个好的做法。将所有东西都变成全局变量可能看起来很有用，但这会导致难以阅读和容易出错的代码。

## 准备树枝

现在我们将准备好我们的六个`Sprite`对象，并将它们加载到`branches`数组中。在我们的游戏循环之前添加以下突出显示的代码：

```cpp
// Position the text 
FloatRect textRect = messageText.getLocalBounds(); 
messageText.setOrigin(textRect.left + 
   textRect.width / 2.0f, 
   textRect.top + 
   textRect.height / 2.0f); 

messageText.setPosition(1920 / 2.0f, 1080 / 2.0f); 

scoreText.setPosition(20, 20); 

// Prepare 6 branches
Texture textureBranch;
textureBranch.loadFromFile("graphics/branch.png");

// Set the texture for each branch sprite
for (int i = 0; i < NUM_BRANCHES; i++) 
{   
  branches[i].setTexture(textureBranch);   
  branches[i].setPosition(-2000, -2000);   
  // Set the sprite's origin to dead center   
  // We can then spin it round without changing its position 
  branches[i].setOrigin(220, 20);
} 

while (window.isOpen()) 
{ 

```

之前的代码没有使用任何新概念。首先，我们声明了一个 SFML `Texture`对象，并将`branch.png`图形加载到其中。

接下来，我们创建一个`for`循环，将`i`设置为零，并在每次循环通过时递增`i`，直到`i`不再小于`NUM_BRANCHES`。这是完全正确的，因为`NUM_BRANCHES`是 6，而`branches`数组的位置是 0 到 5。

在`for`循环中，我们使用`setTexture`为`branches`数组中的每个`Sprite`设置`Texture`，然后用`setPosition`将其隐藏在屏幕外。

最后，我们使用`setOrigin`将原点（绘制时所在的点）设置为精灵的中心。很快，我们将旋转这些精灵，并且将原点设置在中心意味着它们将很好地围绕旋转，而不会使精灵移出位置。

## 每帧更新树枝精灵

在下面的代码中，我们根据`branchPositions`数组中的位置和相应的`branchPositions`数组中的`side`的值，设置`branches`数组中所有精灵的位置。添加高亮代码并尝试理解它，然后我们可以详细讨论一下：

```cpp
   // Update the score text 
   std::stringstream ss; 
   ss << "Score: " << score; 
   scoreText.setString(ss.str()); 

 // update the branch sprites   
   for (int i = 0; i < NUM_BRANCHES; i++)   
   {     
     float height = i * 150;     
     if (branchPositions[i] == side::LEFT)     
     {        
       // Move the sprite to the left side        
       branches[i].setPosition(610, height);

       // Flip the sprite round the other way        
       branches[i].setRotation(180);     
     }

     else if (branchPositions[i] == side::RIGHT)     
     {        
       // Move the sprite to the right side        
       branches[i].setPosition(1330, height);    

       // Set the sprite rotation to normal        
       branches[i].setRotation(0);     
     }     
     else     
     {        
       // Hide the branch        
       branches[i].setPosition(3000, height);     
     }   
   } 
} // End if(!paused) 

/* 
**************************************** 
Draw the scene 
**************************************** 

```

我们刚刚添加的代码是一个大的`for`循环，将`i`设置为零，每次通过循环递增`i`，并持续进行，直到`i`不再小于 6。

在`for`循环内，设置了一个名为`height`的新的`float`变量，其值为`i * 150`。这意味着第一个树枝的高度为 0，第二个为 150，第六个为 750。

接下来是一系列`if`和`else`块的结构。看一下剥离了代码的结构：

```cpp
if() 
{ 
} 
else if() 
{ 
} 
else 
{ 
} 

```

第一个`if`使用`branchPositions`数组来查看当前树枝是否应该在左边。如果是的话，它会将`branches`数组中的相应`Sprite`设置为屏幕上适合左边（610 像素）和当前`height`的位置。然后它将精灵翻转`180`度，因为`branch.png`图形默认向右悬挂。

`else if`只有在树枝不在左边时才执行。它使用相同的方法来查看它是否在右边。如果是的话，树枝就会被绘制在右边（1330 像素）。然后将精灵旋转为 0 度，以防它之前是 180 度。如果 x 坐标看起来有点奇怪，只需记住我们将树枝精灵的原点设置为它们的中心。

最后的`else`假设，正确地，当前的`branchPosition`必须是`NONE`，并将树枝隐藏在屏幕外的`3000`像素处。

此时，我们的树枝已经就位，准备绘制。

## 绘制树枝

在这里，我们使用另一个`for`循环，从 0 到 5 遍历整个`branches`数组，并绘制每个树枝精灵。添加以下高亮代码：

```cpp
// Draw the clouds 
window.draw(spriteCloud1); 
window.draw(spriteCloud2); 
window.draw(spriteCloud3); 

// Draw the branches
for (int i = 0; i < NUM_BRANCHES; i++) 
{   
  window.draw(branches[i]);
} 

// Draw the tree 
window.draw(spriteTree); 

```

当然，我们还没有编写实际移动所有树枝的函数。一旦我们编写了该函数，我们还需要解决何时以及如何调用它的问题。让我们解决第一个问题并编写该函数。

## 移动树枝

我们已经在`main`函数上面添加了函数原型。现在我们编写实际的函数定义，该函数将在每次调用时将所有树枝向下移动一个位置。我们将这个函数分为两部分编写，以便更容易地检查发生了什么。

在`main`函数的右花括号后添加`updateBranches`函数的第一部分：

```cpp
// Function definition 
void updateBranches(int seed) 
{ 
   // Move all the branches down one place 
   for (int j = NUM_BRANCHES-1; j > 0; j--) 
   {    
      branchPositions[j] = branchPositions[j - 1]; 
   } 
} 

```

在函数的第一部分中，我们只是将所有的树枝向下移动一个位置，一次一个，从第六个树枝开始。这是通过使`for`循环从 5 计数到 0 来实现的。代码`branchPositions[j] = branchPositions[j - 1];`实现了实际的移动。

在前面的代码中，另一件需要注意的事情是，当我们将位置 4 的树枝移动到位置 5，然后将位置 3 的树枝移动到位置 4，依此类推，我们需要在位置 0 添加一个新的树枝，这是树的顶部。

现在我们可以在树的顶部生成一个新的树枝。添加高亮代码，然后我们将讨论它：

```cpp
// Function definition 
void updateBranches(int seed) 
{ 
   // Move all the branches down one place 
   for (int j = NUM_BRANCHES-1; j > 0; j--) 
   {    
      branchPositions[j] = branchPositions[j - 1]; 
   } 

 // Spawn a new branch at position 0   
   // LEFT, RIGHT or NONE   
   srand((int)time(0)+seed);   
   int r = (rand() % 5);   
   switch (r) 
   {   
   case 0:     
     branchPositions[0] = side::LEFT;     
     break;   

   case 1:     
     branchPositions[0] = side::RIGHT;     
     break;   

   default:     
     branchPositions[0] = side::NONE;     
     break;  
    } 
} 

```

在`updateBranches`函数的最后部分，我们使用传入函数调用的整数`seed`变量。我们这样做是为了确保随机数`seed`始终不同，并且我们将在下一章中看到这个值是如何得到的。

接下来，我们生成一个介于零和四之间的随机数，并将结果存储在`int`变量`r`中。现在我们使用`r`作为表达式进行`switch`。

`case`语句意味着，如果`r`等于零，那么我们在树的顶部左侧添加一个新的分支。如果`r`等于 1，那么分支就在右侧。如果`r`是其他任何值（2、3 或 4），那么`default`确保在顶部不会添加任何分支。左、右和无的平衡使得树看起来很真实，游戏运行得相当不错。你可以很容易地改变代码，使分支更频繁或更少。

即使为我们的分支编写了所有这些代码，我们仍然无法在游戏中看到任何一个分支。这是因为在我们实际调用`updateBranches`之前，我们还有更多的工作要做。

如果你现在真的想看到一个分支，你可以添加一些临时代码，并在游戏循环之前调用该函数五次，每次使用一个独特的种子：

```cpp
updateBranches(1);
updateBranches(2);
updateBranches(3);
updateBranches(4);
updateBranches(5); 

while (window.isOpen()) 
{ 

```

现在你可以看到分支在它们的位置上。但是如果分支实际上要移动，我们需要定期调用`updateBranches`。

![移动分支](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_04_001.jpg)

### 提示

在继续之前不要忘记删除临时代码。

现在我们可以把注意力转向玩家，并真正调用`updateBranches`函数。

# FAQ

Q) 你提到了几种类型的 C++循环。

A) 是的，看一下这个`do...while`循环的教程和解释：

[`www.tutorialspoint.com/cplusplus/cpp_do_while_loop.htm`](http://www.tutorialspoint.com/cplusplus/cpp_do_while_loop.htm)

Q) 我可以假设我是数组的专家吗？

A) 就像本书中的许多主题一样，总是有更多的东西可以学习。你已经了解足够的关于数组的知识来继续，但如果你还想了解更多，请查看这个更详细的数组教程：[`www.cplusplus.com/doc/tutorial/arrays/`](http://www.cplusplus.com/doc/tutorial/arrays/)。

Q) 我可以假设我是函数的专家吗？

A) 就像本书中的许多主题一样，总是有更多的东西可以学习。你已经了解足够的关于函数的知识来继续，但如果想了解更多，请查看这个教程：[`www.cplusplus.com/doc/tutorial/functions/`](http://www.cplusplus.com/doc/tutorial/functions/)。

# 总结

虽然这不是最长的一章，但可能是我们涵盖最多 C++知识的一章。我们研究了不同类型的循环，比如`for`和`while`循环。我们学习了处理大量变量和对象的数组，而不费吹灰之力。我们还学习了枚举和`switch`。也许这一章最重要的概念是允许我们组织和抽象游戏代码的函数。随着书的继续，我们将在更多地方深入研究函数。

现在我们有一个完全可用的树，我们可以在这个项目的最后一章中完成游戏。


# 第五章：碰撞、声音和结束条件-使游戏可玩

这是第一个项目的最后阶段。在本章结束时，您将拥有您的第一个完成的游戏。一旦您运行了 Timber！！！，一定要阅读本章的最后一节，因为它将提出改进游戏的建议。我们将讨论以下主题：

+   添加其余的精灵

+   处理玩家输入

+   动画飞行原木

+   处理死亡

+   添加音效

+   添加功能并改进 Timber！！！

# 准备玩家（和其他精灵）

让我们同时为玩家的精灵添加代码，以及一些更多的精灵和纹理。这下面的相当大的代码块还为玩家被压扁时添加了一个墓碑精灵，一个用来砍伐的斧头精灵，以及一个可以在玩家砍伐时飞走的原木精灵。

请注意，在`spritePlayer`对象之后，我们还声明了一个`side`变量`playerSide`，以跟踪玩家当前站立的位置。此外，我们为`spriteLog`对象添加了一些额外的变量，包括`logSpeedX`、`logSpeedY`和`logActive`，用于存储原木的移动速度以及它当前是否在移动。`spriteAxe`还有两个相关的`float`常量变量，用于记住左右两侧的理想像素位置。

像以前那样，在`while(window.isOpen())`代码之前添加下一个代码块。请注意，下一个清单中的所有代码都是新的，而不仅仅是突出显示的代码。我没有为下一个代码块提供任何额外的上下文，因为`while(window.isOpen())`应该很容易识别。突出显示的代码是我们刚刚讨论过的代码。

在`while(window.isOpen())`行之前添加整个代码，并在脑海中记住我们简要讨论过的突出显示的行。这将使本章其余的代码更容易理解：

```cpp
// Prepare the player 
Texture texturePlayer; 
texturePlayer.loadFromFile("graphics/player.png"); 
Sprite spritePlayer; 
spritePlayer.setTexture(texturePlayer); 
spritePlayer.setPosition(580, 720); 

// The player starts on the left 
side playerSide = side::LEFT; 

// Prepare the gravestone 
Texture textureRIP; 
textureRIP.loadFromFile("graphics/rip.png"); 
Sprite spriteRIP; 
spriteRIP.setTexture(textureRIP); 
spriteRIP.setPosition(600, 860); 

// Prepare the axe 
Texture textureAxe; 
textureAxe.loadFromFile("graphics/axe.png"); 
Sprite spriteAxe; 
spriteAxe.setTexture(textureAxe); 
spriteAxe.setPosition(700, 830); 

// Line the axe up with the tree 
const float AXE_POSITION_LEFT = 700; 
const float AXE_POSITION_RIGHT = 1075; 

// Prepare the flying log 
Texture textureLog; 
textureLog.loadFromFile("graphics/log.png"); 
Sprite spriteLog; 
spriteLog.setTexture(textureLog); 
spriteLog.setPosition(810, 720); 

// Some other useful log related variables 
bool logActive = false; 
float logSpeedX = 1000; 
float logSpeedY = -1500; 

```

现在我们可以绘制所有新的精灵。

# 绘制玩家和其他精灵

在我们添加移动玩家和使用所有新精灵的代码之前，让我们先绘制它们。这样，当我们添加代码来更新/改变/移动精灵时，我们将能够看到发生了什么。

添加突出显示的代码以绘制四个新的精灵：

```cpp
// Draw the tree 
window.draw(spriteTree); 

// Draw the player 
window.draw(spritePlayer); 

// Draw the axe 
window.draw(spriteAxe); 

// Draraw the flying log 
window.draw(spriteLog); 

// Draw the gravestone 
window.draw(spriteRIP); 

// Draw the bee 
window.draw(spriteBee); 

```

运行游戏，你会看到我们在场景中的新精灵。

![绘制玩家和其他精灵](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_05_001.jpg)

我们现在离一个可运行的游戏非常接近了。

# 处理玩家的输入

许多不同的事情取决于玩家的移动，比如何时显示斧头，何时开始动画原木，以及何时将所有的树枝移动到一个地方。因此，为玩家砍伐设置键盘处理是有意义的。一旦完成这一点，我们就可以将刚才提到的所有功能放入代码的同一部分。

让我们思考一下我们如何检测键盘按键。在每一帧中，我们测试特定的键盘键当前是否被按下。如果是，我们就采取行动。如果按下***Esc***键，我们退出游戏，或者如果按下***Enter***键，我们重新开始游戏。到目前为止，这对我们的需求已经足够了。

然而，当我们尝试处理砍树时，这种方法存在问题。这个问题一直存在，只是直到现在才变得重要。根据您的 PC 有多强大，游戏循环可能每秒执行数千次。在游戏循环中每次按下键时，都会检测到并执行相关代码。

实际上，每次按下***Enter***重新开始游戏时，您很可能会重新开始游戏超过一百次。这是因为即使是最短暂的按键按下也会持续相当长的时间。您可以通过运行游戏并按住***Enter***键来验证这一点。请注意，时间条不会移动。这是因为游戏一遍又一遍地重新启动，每秒甚至数千次。

如果我们不对玩家的砍伐采取不同的方法，那么只需一次尝试的砍伐就会在短短的时间内将整棵树砍倒。我们需要更加复杂一些。我们将允许玩家进行砍伐，然后在他这样做时禁用检测按键的代码。然后我们将检测玩家何时从按键上移开手指，然后重新启用按键检测。以下是清晰列出的步骤：

1.  等待玩家使用左右箭头键砍伐木头。

1.  当玩家砍伐时，禁用按键检测。

1.  等待玩家从按键上移开手指。

1.  重新启用砍伐检测。

1.  从步骤 1 重复。

这可能听起来很复杂，但借助 SFML 的帮助，这将非常简单。让我们现在一步一步地实现这个。

添加代码中的突出显示行，声明一个`bool`变量和`acceptInput`，用于确定何时监听砍伐动作和何时忽略它们：

```cpp
float logSpeedX = 1000; 
float logSpeedY = -1500; 

// Control the player input 
bool acceptInput = false; 

while (window.isOpen()) 
{ 

```

现在我们已经设置好了布尔值，可以继续下一步了。

## 处理设置新游戏

现在我们准备处理砍伐，将突出显示的代码添加到开始新游戏的`if`块中：

```cpp
/* 
**************************************** 
Handle the players input 
**************************************** 
*/ 

if (Keyboard::isKeyPressed(Keyboard::Escape)) 
{ 
  window.close(); 
} 

// Start the game 
if (Keyboard::isKeyPressed(Keyboard::Return)) 
{ 
  paused = false; 

  // Reset the time and the score 
  score = 0; 
  timeRemaining = 6; 

  // Make all the branches disappear 
  for (int i = 1; i < NUM_BRANCHES; i++) 
  { 
    branchPositions[i] = side::NONE; 
  } 

  // Make sure the gravestone is hidden 
  spriteRIP.setPosition(675, 2000); 

  // Move the player into position 
  spritePlayer.setPosition(580, 720); 

  acceptInput = true;  
} 

/* 
**************************************** 
Update the scene 
**************************************** 
*/ 

```

在之前的代码中，我们使用`for`循环将树设置为没有分支。这对玩家是公平的，因为如果游戏从他的头顶上方开始，那将被认为是不公平的。然后我们简单地将墓碑移出屏幕，玩家移动到左侧的起始位置。这个新代码的最后一件事是将`acceptInput`设置为`true`。我们现在准备好接收砍伐按键了。

## 检测玩家的砍伐

现在我们可以准备处理左右方向键的按下。添加这个简单的`if`块，只有当`acceptInput`为`true`时才执行：

```cpp
// Start the game 
if (Keyboard::isKeyPressed(Keyboard::Return)) 
{ 
  paused = false; 

  // Reset the time and the score 
  score = 0; 
  timeRemaining = 5; 

  // Make all the branches disappear 
  for (int i = 1; i < NUM_BRANCHES; i++) 
  { 
    branchPositions[i] = side::NONE; 
  } 

  // Make sure the gravestone is hidden 
  spriteRIP.setPosition(675, 2000); 

  // Move the player into position 
  spritePlayer.setPosition(675, 660); 

  acceptInput = true; 

} 

// Wrap the player controls to 
// Make sure we are accepting input 
if (acceptInput) 
{ 
  // More code here next... 
} 

/* 
**************************************** 
Update the scene 
**************************************** 
*/ 

```

现在，在我们刚刚编写的`if`块中，添加突出显示的代码来处理玩家在键盘上按下右箭头键（**→**）时发生的情况：

```cpp
// Wrap the player controls to 
// Make sure we are accepting input 
if (acceptInput) 
{ 
  // More code here next... 

  // First handle pressing the right cursor key 
  if (Keyboard::isKeyPressed(Keyboard::Right)) 
  { 
    // Make sure the player is on the right 
    playerSide = side::RIGHT; 

    score ++; 

    // Add to the amount of time remaining 
    timeRemaining += (2 / score) + .15; 

    spriteAxe.setPosition(AXE_POSITION_RIGHT, 
      spriteAxe.getPosition().y); 

    spritePlayer.setPosition(1200, 720); 

    // update the branches 
    updateBranches(score); 

    // set the log flying to the left 
    spriteLog.setPosition(810, 720); 
    logSpeedX = -5000; 
    logActive = true; 

    acceptInput = false; 
  } 

  // Handle the left cursor key 
} 

```

在上面的代码中发生了很多事情，让我们逐步进行。首先，我们检测玩家是否在树的右侧砍伐。如果是，我们将`playerSide`设置为`side::RIGHT`。我们将在代码的后面对`playerSide`的值做出响应。

然后我们用`score ++`将分数加 1。下一行代码有点神秘，但实际上我们只是增加了剩余时间的数量。我们正在奖励玩家采取行动。然而，对于玩家来说，问题在于分数越高，增加的时间就越少。您可以通过调整这个公式来使游戏变得更容易或更难。

然后，斧头移动到右侧位置，使用`spriteAxe.setPosition`，玩家精灵也移动到右侧位置。

接下来，我们调用`updateBranches`将所有的分支向下移动一个位置，并在树的顶部生成一个新的随机分支（或空格）。

然后，`spriteLog`移动到起始位置，伪装成树，它的`speedX`变量设置为负数，这样它就会向左飞去。此外，`logActive`设置为`true`，这样我们即将编写的移动木头的代码就会在每一帧中使木头动起来。

最后，`acceptInput`被设置为`false`。此时，玩家无法再进行砍伐。我们已经解决了按键被频繁检测的问题，很快我们将看到如何重新启用砍伐。

现在，在我们刚刚编写的`if(acceptInput)`块内，添加突出显示的代码来处理玩家在键盘上按下左箭头键（**←**）时发生的情况：

```cpp
  // Handle the left cursor key 

  if (Keyboard::isKeyPressed(Keyboard::Left)) 
  { 
    // Make sure the player is on the left 
    playerSide = side::LEFT; 

    score++; 

    // Add to the amount of time remaining 
    timeRemaining += (2 / score) + .15; 

    spriteAxe.setPosition(AXE_POSITION_LEFT, 
      spriteAxe.getPosition().y); 

    spritePlayer.setPosition(580, 720); 

    // update the branches 
    updateBranches(score); 

    // set the log flying 
    spriteLog.setPosition(810, 720); 
    logSpeedX = 5000; 
    logActive = true; 

    acceptInput = false; 
  } 

} 

```

前面的代码与处理右侧砍伐的代码完全相同，只是精灵的位置不同，并且`logSpeedX`变量设置为正值，使得木头向右飞去。

## 检测按键释放

为了使上述代码在第一次砍伐之后继续工作，我们需要检测玩家何时释放键，并将`acceptInput`设置回`true`。

这与我们迄今为止看到的按键处理略有不同。SFML 有两种不同的方式来检测玩家的键盘输入。我们已经看到了第一种方式。它是动态和瞬时的，正是我们需要立即对按键做出响应的。

下面的代码使用了另一种方法。*输入*下一个突出显示的代码到`处理玩家输入`部分的顶部，然后我们将逐步讲解它：

```cpp
/* 
**************************************** 
Handle the players input 
**************************************** 
*/ 

Event event; 

while (window.pollEvent(event)) 
{ 
  if (event.type == Event::KeyReleased && !paused) 
  { 
    // Listen for key presses again 
    acceptInput = true; 

    // hide the axe 
    spriteAxe.setPosition(2000, 
      spriteAxe.getPosition().y); 
  } 
} 

if (Keyboard::isKeyPressed(Keyboard::Escape)) 
{ 
  window.close(); 
} 

```

首先，我们声明了一个名为`event`的`Event`类型的对象。然后我们调用`window.pollEvent`函数，传入我们的新对象`event`。`pollEvent`函数将数据放入`event`对象中，描述了操作系统事件。这可能是按键、释放键、鼠标移动、鼠标点击、游戏控制器动作或发生在窗口本身的事件（例如调整大小等）。

我们将代码包装在`while`循环中的原因是因为队列中可能存储了许多事件。`window.pollEvent`函数将这些事件一个接一个地加载到`event`中。我们将在循环中的每次通过中看到当前事件，如果我们感兴趣，就会做出响应。当`window.pollEvent`返回`false`时，这意味着队列中没有更多事件，`while`循环将退出。

当释放一个键并且游戏没有暂停时，这个`if`条件（`event.type == Event::KeyReleased && !paused`）为`true`。

在`if`块中，我们将`acceptInput`设置回`true`，并将斧头精灵隐藏在屏幕外。

现在您可以运行游戏，惊叹于移动的树木、摆动的斧头和动画的玩家。然而，它不会压扁玩家，砍伐时木头也需要移动。

## 动画砍伐的木头和斧头

当玩家砍木头时，`logActive`被设置为`true`，因此我们可以将一些代码包装在一个块中，只有当`logActive`为`true`时才执行。此外，每次砍木头都会将`logSpeedX`设置为正数或负数，因此木头准备好朝着正确的方向飞离树。

在我们更新分支精灵之后，添加下面突出显示的代码：

```cpp
  // update the branch sprites 
  for (int i = 0; i < NUM_BRANCHES; i++) 
  { 

    float height = i * 150; 

    if (branchPositions[i] == side::LEFT) 
    { 
      // Move the sprite to the left side 
      branches[i].setPosition(610, height); 

      // Flip the sprite round the other way 
      branches[i].setRotation(180); 
    } 
    else if (branchPositions[i] == side::RIGHT) 
    { 
      // Move the sprite to the right side 
      branches[i].setPosition(1330, height); 

      // Flip the sprite round the other way 
      branches[i].setRotation(0); 

    } 
    else 
    { 
      // Hide the branch 
      branches[i].setPosition(3000, height); 
    } 
  } 

  // Handle a flying log         
  if (logActive) 
  { 

    spriteLog.setPosition( 
      spriteLog.getPosition().x +  
      (logSpeedX * dt.asSeconds()), 

    spriteLog.getPosition().y +  
      (logSpeedY * dt.asSeconds())); 

    // Has the log reached the right hand edge? 
    if (spriteLog.getPosition().x < -100 || 
      spriteLog.getPosition().x > 2000) 
    { 
      // Set it up ready to be a whole new log next frame 
      logActive = false; 
      spriteLog.setPosition(810, 720); 
    } 
  } 

} // End if(!paused) 

/* 
**************************************** 
Draw the scene 
**************************************** 
*/ 

```

代码通过使用`getPosition`获取精灵的当前 x 和 y 位置，然后分别使用`logSpeedX`和`logSpeedY`乘以`dt.asSeconds`加到其上，来设置精灵的位置。

在每一帧中移动木头精灵后，代码使用`if`块来查看精灵是否已经从左侧或右侧消失在视野中。如果是，木头就会移回到起点，准备下一次砍伐。

如果您运行游戏，您将能够看到木头飞向屏幕的适当一侧。

![动画砍伐的木头和斧头](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_05_002.jpg)

现在是一个更敏感的话题。

# 处理死亡

每个游戏都必须以不好的方式结束，要么是玩家时间用完（这已经处理过了），要么是被分支压扁。

检测玩家被压扁非常简单。我们只想知道`branchPositions`数组中的最后一个分支是否等于`playerSide`。如果是，玩家就死了。

添加检测这一点的突出代码，然后我们将讨论玩家被压扁时的所有操作：

```cpp
  // Handle a flying log         
  if (logActive) 
  { 

    spriteLog.setPosition( 
      spriteLog.getPosition().x + (logSpeedX * dt.asSeconds()),
        spriteLog.getPosition().y + (logSpeedY * dt.asSeconds())); 

    // Has the log reached the right hand edge? 
    if (spriteLog.getPosition().x < -100 || 
      spriteLog.getPosition().x > 2000) 
    { 
      // Set it up ready to be a whole new cloud next frame 
      logActive = false; 
      spriteLog.setPosition(800, 600); 
    } 
  } 

  // Has the player been squished by a branch? 
  if (branchPositions[5] == playerSide) 
  { 
    // death 
    paused = true; 
    acceptInput = false; 

    // Draw the gravestone 
    spriteRIP.setPosition(525, 760); 

    // hide the player 
    spritePlayer.setPosition(2000, 660); 

    // Change the text of the message 
    messageText.setString("SQUISHED!!"); 

    // Center it on the screen 
    FloatRect textRect = messageText.getLocalBounds(); 

    messageText.setOrigin(textRect.left + 
      textRect.width / 2.0f, 
      textRect.top + textRect.height / 2.0f); 

    messageText.setPosition(1920 / 2.0f, 
      1080 / 2.0f); 

  } 

} // End if(!paused) 

/* 
**************************************** 
Draw the scene 
**************************************** 
*/ 

```

在玩家死亡后，代码的第一件事是将`paused`设置为`true`。现在循环将完成这一帧，并且在玩家开始新游戏之前不会再次运行循环的更新部分。

然后我们将墓碑移动到靠近玩家站立的位置，并将玩家精灵隐藏在屏幕外。

我们将`messageText`的字符串设置为`"SQUISHED !!"`，然后使用通常的技术将其居中显示在屏幕上。

现在您可以运行游戏并真正玩它。这张图片显示了玩家的最终得分和他的墓碑，以及**SQUISHED**消息。

![处理死亡](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_05_003.jpg)

还有一个问题。只是我吗，还是有点安静？

# 简单的声音效果

我们将添加三种声音。每种声音都将在特定的游戏事件上播放。每当玩家砍伐时播放简单的重击声音，当玩家时间用尽时播放沮丧的失败声音，当玩家被压扁致死时播放复古的压碎声音。

## SFML 声音是如何工作的？

SFML 使用两种不同的类来播放声音效果。第一个类是`SoundBuffer`类。这个类保存了来自声音文件的实际音频数据。它是`SoundBuffer`负责将`.wav`文件加载到 PC 的 RAM 中，以一种无需进一步解码工作即可播放的格式。

一会儿，当我们为声音效果编写代码时，我们将看到，一旦我们有了一个包含我们声音的`SoundBuffer`对象，我们将创建另一个类型为`Sound`的对象。然后，我们可以将这个`Sound`对象与`SoundBuffer`对象关联起来。然后，在我们的代码中适当的时刻，我们将能够调用适当`Sound`对象的`play`函数。

## 何时播放声音

很快我们将看到，加载和播放声音的 C++代码真的很简单。然而，我们需要考虑的是何时调用`play`函数。我们的代码中何处将调用`play`函数？以下是我们想要实现的一些功能：

+   砍伐声音可以从按下左右光标键时调用

+   死亡声音可以从检测到树木将玩家搅碎的`if`块中播放

+   时间用尽的声音可以从检测到`timeRemaining`小于零的`if`块中播放

现在我们可以编写我们的声音代码。

## 添加声音代码

首先，我们添加另一个`#include`指令，以使 SFML 与声音相关的类可用。添加下面突出显示的代码：

```cpp
#include "stdafx.h" 
#include <sstream> 
#include <SFML/Graphics.hpp> 
#include <SFML/Audio.hpp>

using namespace sf; 

```

现在我们声明三个不同的`SoundBuffer`对象，将三个不同的声音文件加载到它们中，并将三个不同的`Sound`对象与相关的`SoundBuffer`对象关联起来。添加下面突出显示的代码：

```cpp
// Control the player input 
bool acceptInput = false; 

// Prepare the sound 
SoundBuffer chopBuffer; 
chopBuffer.loadFromFile("sound/chop.wav"); 
Sound chop; 
chop.setBuffer(chopBuffer); 

SoundBuffer deathBuffer; 
deathBuffer.loadFromFile("sound/death.wav"); 
Sound death; 
death.setBuffer(deathBuffer); 

// Out of time 
SoundBuffer ootBuffer; 
ootBuffer.loadFromFile("sound/out_of_time.wav"); 
Sound outOfTime; 
outOfTime.setBuffer(ootBuffer); 

while (window.isOpen()) 
{ 

```

现在我们可以播放我们的第一个声音效果。在检测到玩家按下左光标键的`if`块旁边添加如下一行代码：

```cpp
// Wrap the player controls to 
// Make sure we are accepting input 
if (acceptInput) 
{ 
  // More code here next... 

  // First handle pressing the right cursor key 
  if (Keyboard::isKeyPressed(Keyboard::Right)) 
  { 
    // Make sure the player is on the right 
    playerSide = side::RIGHT; 

    score++; 

    timeRemaining += (2 / score) + .15; 

    spriteAxe.setPosition(AXE_POSITION_RIGHT, 
      spriteAxe.getPosition().y); 

    spritePlayer.setPosition(1120, 660); 

    // update the branches 
    updateBranches(score); 

    // set the log flying to the left 
    spriteLog.setPosition(800, 600); 
    logSpeedX = -5000; 
    logActive = true; 

    acceptInput = false; 

    // Play a chop sound 
    chop.play(); 
  } 

```

### 提示

在下一个以`if (Keyboard::isKeyPressed(Keyboard::Left))`开头的代码块的末尾添加完全相同的代码，以使玩家在树的左侧砍伐时发出砍伐声音。

找到处理玩家时间用尽的代码，并添加下一个突出显示的代码，以播放与时间相关的音效：

```cpp
if (timeRemaining <= 0.f) { 
  // Pause the game 
  paused = true; 

  // Change the message shown to the player 
  messageText.setString("Out of time!!"); 

  //Reposition the text based on its new size 
  FloatRect textRect = messageText.getLocalBounds(); 
  messageText.setOrigin(textRect.left + 
    textRect.width / 2.0f, 
    textRect.top + 
    textRect.height / 2.0f); 

  messageText.setPosition(1920 / 2.0f, 1080 / 2.0f); 

  // Play the out of time sound 
  outOfTime.play(); 

} 

```

最后，当玩家被压扁时播放死亡声音，将下面突出显示的代码添加到执行当底部树枝与玩家同侧时的`if`块中：

```cpp
// has the player been squished by a branch? 
if (branchPositions[5] == playerSide) 
{ 
  // death 
  paused = true; 
  acceptInput = false; 

  // Draw the gravestone 
  spriteRIP.setPosition(675, 660); 

  // hide the player 
  spritePlayer.setPosition(2000, 660); 

  messageText.setString("SQUISHED!!"); 
  FloatRect textRect = messageText.getLocalBounds(); 

  messageText.setOrigin(textRect.left + 
    textRect.width / 2.0f, 
    textRect.top + textRect.height / 2.0f); 

  messageText.setPosition(1920 / 2.0f, 1080 / 2.0f); 

  // Play the death sound 
  death.play();
} 

```

就是这样！我们已经完成了第一个游戏。在我们继续进行第二个项目之前，让我们讨论一些可能的增强功能。

# 改进游戏和代码

看看 Timber!!!项目的这些建议的增强功能。您可以在下载包的`Runnable`文件夹中看到增强功能的效果：

1.  **加快代码速度**：我们的代码中有一部分正在减慢我们的游戏。对于这个简单的游戏来说无所谓，但我们可以通过将`sstream`代码放在仅偶尔执行的块中来加快速度。毕竟，我们不需要每秒更新得分数百次！

1.  **调试控制台**：让我们添加一些文本，以便我们可以看到当前的帧速率。与得分一样，我们不需要经常更新这个。每一百帧更新一次就足够了。

1.  **在背景中添加更多的树**：只需添加一些更多的树精灵并将它们绘制在看起来不错的位置（你可以在相机附近放一些，远一些）。

1.  **改善 HUD 文本的可见性**：我们可以在分数和 FPS 计数器后面绘制简单的`RectangleShape`对象；黑色并带有一些透明度看起来会很好。

1.  **使云代码更有效率**：正如我们已经提到过几次的，我们可以利用我们对数组的知识使云代码变得更短。

看看游戏中额外的树、云和文本的透明背景。

![改善游戏和代码](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_05_004.jpg)

要查看这些增强的代码，请查看下载包中的“伐木工增强版”文件夹。

# 常见问题

Q）我承认，对于云的数组解决方案更有效率。但是我们真的需要三个单独的数组吗，一个用于活动，一个用于速度，一个用于精灵本身吗？

A）如果我们查看各种对象的属性/变量，例如`Sprite`对象，我们会发现它们很多。精灵有位置、颜色、大小、旋转等等。但如果它们有`active`、`speed`，甚至更多的话就更完美了。问题在于 SFML 的程序员不可能预测我们将如何使用他们的`Sprite`类。幸运的是，我们可以制作自己的类。我们可以制作一个名为`Cloud`的类，其中有一个布尔值用于`active`和一个整数用于速度。我们甚至可以给我们的`Cloud`类一个 SFML 的`Sprite`对象。然后我们甚至可以进一步简化我们的云代码。我们将在下一章中设计我们自己的类。

# 总结

在本章中，我们为《伐木工》游戏添加了最后的修饰和图形。如果在读这本书之前，你从未编写过一行 C++代码，那么你可以为自己鼓掌。在短短的五章中，你已经从零基础到一个可运行的游戏。

然而，我们不会为自己的成就而沾沾自喜太久，因为在下一章中，我们将直接转向一些稍微更复杂和更全面的 C++，这可以用来构建更复杂和更全面的游戏。
