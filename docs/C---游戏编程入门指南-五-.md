# C++ 游戏编程入门指南（五）

> 原文：[`annas-archive.org/md5/8b22c2649bdec9fa4ee716ae82ae0bb1`](https://annas-archive.org/md5/8b22c2649bdec9fa4ee716ae82ae0bb1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：分层视图和实现 HUD

在本章中，我们将看到 SFML **Views**的真正价值。我们将添加大量的 SFML `Text`对象，并像在**Timber!!!**项目中一样操纵它们。新的是，我们将使用第二个视图实例来绘制 HUD。这样，HUD 将始终整齐地定位在主游戏动作的顶部，而不管背景、玩家、僵尸和其他游戏对象在做什么。

这是我们将要做的事情：

+   在主页/游戏结束屏幕上添加文本和背景

+   在升级屏幕上添加文本

+   创建第二个视图

+   添加 HUD

# 添加所有文本和 HUD 对象

在本章中，我们将操纵一些字符串。这样我们就可以格式化 HUD 和升级屏幕。

添加下一个高亮显示的`include`指令，以便我们可以创建一些`sstream`对象来实现这一点：

```cpp
#include "stdafx.h" 
#include <sstream> 
#include <SFML/Graphics.hpp> 
#include "ZombieArena.h" 
#include "Player.h" 
#include "TextureHolder.h" 
#include "Bullet.h" 
#include "Pickup.h" 

using namespace sf; 

```

接下来添加这段相当冗长但易于解释的代码。为了帮助确定应该添加代码的位置，新代码已经高亮显示，而现有代码没有。您可能需要调整一些文本/元素的位置/大小以适应您的屏幕：

```cpp
int score = 0; 
int hiScore = 0; 

// For the home/game over screen
Sprite spriteGameOver;
Texture textureGameOver = 
TextureHolder::GetTexture("graphics/background.png");
spriteGameOver.setTexture(textureGameOver);
spriteGameOver.setPosition(0, 0);

// Create a view for the HUD
View hudView(sf::FloatRect(0, 0, resolution.x, resolution.y));

// Create a sprite for the ammo icon
Sprite spriteAmmoIcon;
Texture textureAmmoIcon = 
TextureHolder::GetTexture("graphics/ammo_icon.png");
spriteAmmoIcon.setTexture(textureAmmoIcon);
spriteAmmoIcon.setPosition(20, 980);

// Load the font
Font font;
font.loadFromFile("fonts/zombiecontrol.ttf");

// Paused
Text pausedText;
pausedText.setFont(font);
pausedText.setCharacterSize(155);
pausedText.setFillColor(Color::White);
pausedText.setPosition(400, 400);
pausedText.setString("Press Enter \n to continue");

// Game Over
Text gameOverText;
gameOverText.setFont(font);
gameOverText.setCharacterSize(125);
gameOverText.setFillColor(Color::White);
gameOverText.setPosition(250, 850);
gameOverText.setString("Press Enter to play");

// LEVELING up
Text levelUpText;
levelUpText.setFont(font);
levelUpText.setCharacterSize(80);
levelUpText.setFillColor(Color::White);
levelUpText.setPosition(150, 250);
std::stringstream levelUpStream;
levelUpStream <<
   "1- Increased rate of fire" <<
   "\n2- Increased clip size(next reload)" <<
   "\n3- Increased max health" <<
   "\n4- Increased run speed" <<
   "\n5- More and better health pickups" <<
   "\n6- More and better ammo pickups";
levelUpText.setString(levelUpStream.str());

// Ammo
Text ammoText;
ammoText.setFont(font);
ammoText.setCharacterSize(55);
ammoText.setColor(Color::White);
ammoText.setPosition(200, 980);

// Score
Text scoreText;
scoreText.setFont(font);
scoreText.setCharacterSize(55);
scoreText.setFillColor(Color::White);
scoreText.setPosition(20, 0);

// Hi Score
Text hiScoreText;
hiScoreText.setFont(font);
hiScoreText.setCharacterSize(55);
hiScoreText.setFillColor(Color::White);
hiScoreText.setPosition(1400, 0);
std::stringstream s;
s << "Hi Score:" << hiScore;
hiScoreText.setString(s.str());

// Zombies remaining
Text zombiesRemainingText;
zombiesRemainingText.setFont(font);
zombiesRemainingText.setCharacterSize(55);
zombiesRemainingText.setFillColor(Color::White);
zombiesRemainingText.setPosition(1500, 980);
zombiesRemainingText.setString("Zombies: 100");

// Wave number
int wave = 0;
Text waveNumberText;
waveNumberText.setFont(font);
waveNumberText.setCharacterSize(55);
waveNumberText.setFillColor(Color::White);
waveNumberText.setPosition(1250, 980);
waveNumberText.setString("Wave: 0");

// Health bar
RectangleShape healthBar;
healthBar.setFillColor(Color::Red);
healthBar.setPosition(450, 980); 
// The main game loop 
while (window.isOpen()) 

```

先前的代码非常简单，没有什么新东西。它基本上创建了一堆 SFML `Text`对象。它分配它们的颜色和大小，然后格式化它们的位置，使用我们之前见过的函数。

最重要的是，我们创建了另一个名为`hudView`的`View`对象，并将其初始化为适应屏幕的分辨率。

正如我们所看到的，主视图对象随着玩家的移动而滚动。相比之下，我们永远不会移动`hudView`。这样做的结果是，只要在绘制 HUD 元素之前切换到这个视图，我们就会产生这样的效果：游戏世界在下方滚动，而玩家的 HUD 保持静止。

### 提示

类比一下，您可以想象在电视屏幕上放置一张带有一些文字的透明塑料片。电视将继续正常播放移动图片，而塑料片上的文字将保持在同一位置，不管下面发生了什么。

然而，下一件要注意的事情是，高分并没有以任何有意义的方式设置。我们需要等到下一章，当我们调查文件 I/O 以保存和检索高分时。

值得注意的另一点是，我们声明并初始化了一个名为`healthBar`的`RectangleShape`，它将是玩家剩余生命的视觉表示。这将几乎与上一个项目中的时间条工作方式完全相同，当然，它代表的是生命而不是时间。

在先前的代码中，有一个名为`ammoIcon`的新精灵，它为我们将在屏幕左下角旁边绘制的子弹和弹夹统计数据提供了上下文。

虽然我们刚刚添加的大量代码没有什么新的或技术性的，但一定要熟悉细节，特别是变量名，以便更容易跟随本章的其余部分。

# 每帧更新 HUD

正如您所期望的，我们将在代码的更新部分更新 HUD 变量。然而，我们不会在每一帧都这样做。原因是这是不必要的，而且还会减慢我们的游戏循环速度。

举个例子，考虑这样一种情况：玩家杀死了一个僵尸并获得了一些额外的分数。无论`Text`对象中的分数是在千分之一秒、百分之一秒，甚至十分之一秒内更新，玩家都不会察觉到任何区别。这意味着没有必要在每一帧重新构建我们设置给`Text`对象的字符串。

因此，我们可以确定何时以及多久更新 HUD，添加以下变量：

```cpp
// When did we last update the HUD?
int framesSinceLastHUDUpdate = 0;

// How often (in frames) should we update the HUD
int fpsMeasurementFrameInterval = 1000; 

// The main game loop 
while (window.isOpen()) 

```

在先前的代码中，我们有变量来跟踪自上次更新 HUD 以来经过了多少帧，以及我们希望在 HUD 更新之间等待的帧数间隔。

现在我们可以使用这些新变量并实际上每帧更新 HUD。然而，直到我们开始操纵最终变量（例如`wave`）在下一章中，我们才会真正看到所有 HUD 元素的变化。

按照以下所示，在游戏循环的更新部分中添加突出显示的代码：

```cpp
   // Has the player touched ammo pickup 
   if (player.getPosition().intersects 
      (ammoPickup.getPosition()) && ammoPickup.isSpawned()) 
   { 
      bulletsSpare += ammoPickup.gotIt(); 

   } 

 // size up the health bar
   healthBar.setSize(Vector2f(player.getHealth() * 3, 50));
   // Increment the number of frames since the previous update
   framesSinceLastHUDUpdate++;

   // re-calculate every fpsMeasurementFrameInterval frames
   if (framesSinceLastHUDUpdate > fpsMeasurementFrameInterval)
   {
     // Update game HUD text
     std::stringstream ssAmmo;
     std::stringstream ssScore;
     std::stringstream ssHiScore;
     std::stringstream ssWave;
     std::stringstream ssZombiesAlive;

     // Update the ammo text
     ssAmmo << bulletsInClip << "/" << bulletsSpare;
     ammoText.setString(ssAmmo.str());

     // Update the score text
     ssScore << "Score:" << score;
     scoreText.setString(ssScore.str());

     // Update the high score text
     ssHiScore << "Hi Score:" << hiScore;
     hiScoreText.setString(ssHiScore.str());

     // Update the wave
     ssWave << "Wave:" << wave;
     waveNumberText.setString(ssWave.str());

     // Update the high score text
     ssZombiesAlive << "Zombies:" << numZombiesAlive;
     zombiesRemainingText.setString(ssZombiesAlive.str());

     framesSinceLastHUDUpdate = 0;

   }// End HUD update 

}// End updating the scene 

```

在新代码中，我们更新了`healthBar`精灵的大小，增加了`timeSinceLastUpdate`对象，然后增加了`framesSinceLastUpdate`变量。

接下来，我们开始一个`if`块，测试`framesSinceLastHUDUpdate`是否大于我们存储在`fpsMeasurementFrameInterval`中的首选间隔。

在这个`if`块中是所有操作发生的地方。首先，我们为需要设置为`Text`对象的每个字符串声明一个字符串流对象。

然后我们依次使用这些字符串流对象，并使用`setString`函数将结果设置为适当的`Text`对象。

最后，在退出`if`块之前，将`framesSinceLastHUDUpdate`设置回零，以便计数可以重新开始。

现在，当我们重新绘制场景时，新值将出现在玩家的 HUD 中。

# 绘制 HUD，主页和升级屏幕

接下来三个代码块中的所有代码都在游戏循环的绘制阶段中。我们只需要在主游戏循环的绘制部分的适当状态下绘制适当的`Text`对象。

在`PLAYING`状态下，添加以下突出显示的代码：

```cpp
   //Draw the crosshair 
   window.draw(spriteCrosshair); 

 // Switch to the HUD view
   window.setView(hudView);

   // Draw all the HUD elements
   window.draw(spriteAmmoIcon);
   window.draw(ammoText);
   window.draw(scoreText);
   window.draw(hiScoreText);
   window.draw(healthBar);
   window.draw(waveNumberText);
   window.draw(zombiesRemainingText); 
} 

if (state == State::LEVELING_UP) 
{ 
} 

```

在上一个代码块中需要注意的重要事情是，我们切换到了 HUD 视图。这会导致所有东西都以我们给 HUD 的每个元素的精确屏幕位置绘制。它们永远不会移动。

在`LEVELING_UP`状态下，添加以下突出显示的代码：

```cpp
if (state == State::LEVELING_UP) 
{ 
 window.draw(spriteGameOver);
   window.draw(levelUpText); 
} 

```

在`PAUSED`状态下，添加以下突出显示的代码：

```cpp
if (state == State::PAUSED) 
{ 
 window.draw(pausedText); 
} 

```

在`GAME_OVER`状态下，添加以下突出显示的代码：

```cpp
if (state == State::GAME_OVER) 
{ 
 window.draw(spriteGameOver);
   window.draw(gameOverText);
   window.draw(scoreText);
   window.draw(hiScoreText); 
} 

```

现在我们可以运行游戏，并在游戏过程中看到我们的 HUD 更新。

![绘制 HUD，主页和升级屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_10_001.jpg)

这显示了主页/游戏结束屏幕上的**HI SCORE**和得分：

![绘制 HUD，主页和升级屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_10_002.jpg)

接下来，我们看到文本显示玩家的升级选项，尽管这些选项目前还没有任何作用。

![绘制 HUD，主页和升级屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_10_003.jpg)

在这里，我们在暂停屏幕上看到了一条有用的消息：

![绘制 HUD，主页和升级屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_10_004.jpg)

### 提示

SFML Views 比这个简单的 HUD 更强大。要了解 SFML Views 的潜力以及它们的易用性，可以查看 SFML 网站关于`View`的教程[`www.sfml-dev.org/tutorials/2.0/graphics-view.php`](http://www.sfml-dev.org/tutorials/2.0/graphics-view.php)。

# FAQ

这里可能会有一个让您在意的问题：

Q）我在哪里可以看到`View`类的更多功能？

A）查看下载包中**Zombie Arena**游戏的增强版。您可以使用键盘光标键旋转和缩放操作。警告！旋转场景会使控制变得笨拙，但您可以看到`View`类可以做的一些事情。

![FAQ](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_10_005.jpg)

缩放和旋转功能是在主游戏循环的输入处理部分中只用了几行代码就实现的。您可以在下载包的`Zombie Arena Enhanced Version`文件夹中查看代码，或者从`Runnable Games/Zombie Arena`文件夹中运行增强版。

# 总结

这是一个快速简单的章节。我们看到了如何使用`sstream`显示不同类型的变量持有的值，然后使用第二个 SFML`View`对象在主游戏动作的顶部绘制它们。

我们现在几乎完成了僵尸竞技场。所有的截图都显示了一个小竞技场，没有充分利用整个显示器。在这个项目的最后阶段，我们将加入一些最后的修饰，比如升级、音效和保存最高分。竞技场可以随后扩大到与显示器相同的大小甚至更大。


# 第十一章：音效，文件 I/O 和完成游戏

我们快要完成了。这一小节将演示如何使用 C++标准库轻松操作存储在硬盘上的文件，我们还将添加音效。当然，我们知道如何添加音效，但我们将讨论在代码中`play`的调用应该放在哪里。我们还将解决一些问题，使游戏完整。

在本章中，我们将学习以下主题：

+   保存和加载最高分

+   添加音效

+   允许玩家升级

+   创建永无止境的多波

# 保存和加载最高分

文件 I/O，或输入/输出，是一个相当技术性的主题。幸运的是，由于它在编程中是一个如此常见的需求，有一个库可以为我们处理所有的复杂性。与我们为 HUD 连接字符串一样，是**标准库**通过`fstream`提供了必要的功能。

首先，我们以与包含`sstream`相同的方式包含`fstream`：

```cpp
#include "stdafx.h" 
#include <sstream> 
#include <fstream> 
#include <SFML/Graphics.hpp> 
#include "ZombieArena.h" 
#include "Player.h" 
#include "TextureHolder.h" 
#include "Bullet.h" 
#include "Pickup.h" 

using namespace sf; 

```

现在，在`ZombieArena/ZombieArena`文件夹中添加一个名为`gamedata`的新文件夹。接下来，在此文件夹中右键单击，创建一个名为`scores.txt`的新文件。我们将保存玩家的最高分数在这个文件中。您可以打开文件并向其中添加分数。如果您这样做，请确保它是一个相当低的分数，这样我们就可以轻松测试是否击败该分数会导致新分数被添加。确保在完成后关闭文件，否则游戏将无法访问它。

在下一段代码中，我们创建了一个名为`InputFile`的`ifstream`对象，并将刚刚创建的文件夹和文件作为参数传递给它的构造函数。

`if(InputFile.is_open())`代码检查文件是否存在并准备好读取。然后我们将文件的内容放入`hiScore`中并关闭文件。添加突出显示的代码：

```cpp
// Score 
Text scoreText; 
scoreText.setFont(font); 
scoreText.setCharacterSize(55); 
scoreText.setFillColor(Color::White); 
scoreText.setPosition(20, 0); 

// Load the high-score from a text file
std::ifstream inputFile("gamedata/scores.txt");
if (inputFile.is_open())
{
   inputFile >> hiScore;
   inputFile.close();
} 

// Hi Score 
Text hiScoreText; 
hiScoreText.setFont(font); 
hiScoreText.setCharacterSize(55); 
hiScoreText.setFillColor(Color::White); 
hiScoreText.setPosition(1400, 0); 
std::stringstream s; 
s << "Hi Score:" << hiScore; 
hiScoreText.setString(s.str()); 

```

现在我们处理保存可能的新最高分。在处理玩家健康小于或等于零的块中，我们创建一个名为`outputFile`的`ofstream`对象，将`hiScore`的值写入文本文件，然后关闭文件：

```cpp
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

 std::ofstream outputFile("gamedata/scores.txt");
        outputFile << hiScore;
        outputFile.close(); 

      } 
   } 
}// End player touched 

```

您可以玩游戏，您的最高分将被保存。退出游戏并注意，如果您再次玩游戏，您的最高分仍然存在。

让我们制造一些噪音。

# 准备音效

在本节中，我们将创建所有我们需要为游戏添加一系列音效的`SoundBuffer`和`Sound`对象。

首先添加所需的 SFML 包含文件：

```cpp
#include "stdafx.h" 
#include <sstream> 
#include <fstream> 
#include <SFML/Graphics.hpp> 
#include <SFML/Audio.hpp> 
#include "ZombieArena.h" 
#include "Player.h" 
#include "TextureHolder.h" 
#include "Bullet.h" 
#include "Pickup.h" 

```

现在继续添加七个`SoundBuffer`和`Sound`对象，它们加载和准备了我们在第六章中准备的七个音频文件：

```cpp
// When did we last update the HUD? 
int framesSinceLastHUDUpdate = 0; 
// What time was the last update 
Time timeSinceLastUpdate; 
// How often (in frames) should we update the HUD 
int fpsMeasurementFrameInterval = 1000; 

// Prepare the hit sound
SoundBuffer hitBuffer;
hitBuffer.loadFromFile("sound/hit.wav");
Sound hit;
hit.setBuffer(hitBuffer);

// Prepare the splat sound
SoundBuffer splatBuffer;
splatBuffer.loadFromFile("sound/splat.wav");
sf::Sound splat;
splat.setBuffer(splatBuffer);

// Prepare the shoot soundSoundBuffer shootBuffer;shootBuffer.loadFromFile("sound/shoot.wav");
Sound shoot;shoot.setBuffer(shootBuffer);

// Prepare the reload sound
SoundBuffer reloadBuffer;
reloadBuffer.loadFromFile("sound/reload.wav");
Sound reload;
reload.setBuffer(reloadBuffer);

// Prepare the failed sound
SoundBuffer reloadFailedBuffer;
reloadFailedBuffer.loadFromFile("sound/reload_failed.wav");
Sound reloadFailed;
reloadFailed.setBuffer(reloadFailedBuffer);

// Prepare the powerup sound
SoundBuffer powerupBuffer;
powerupBuffer.loadFromFile("sound/powerup.wav");
Sound powerup;
powerup.setBuffer(powerupBuffer);

// Prepare the pickup sound
SoundBuffer pickupBuffer;
pickupBuffer.loadFromFile("sound/pickup.wav");
Sound pickup;
pickup.setBuffer(pickupBuffer); 

// The main game loop 
while (window.isOpen()) 

```

现在七个音效已经准备好播放。我们只需要弄清楚在我们的代码中每个`play`函数的调用应该放在哪里。

# 升级

我们将添加的下一段代码使玩家可以在波之间升级。由于我们已经完成的工作，这是很容易实现的。

在我们处理玩家输入的`LEVELING_UP`状态中添加突出显示的代码：

```cpp
// Handle the LEVELING up state 
if (state == State::LEVELING_UP) 
{ 
   // Handle the player LEVELING up 
   if (event.key.code == Keyboard::Num1) 
   { 
 // Increase fire rate
     fireRate++; 
     state = State::PLAYING; 
   } 

   if (event.key.code == Keyboard::Num2) 
   { 
 // Increase clip size
     clipSize += clipSize; 
     state = State::PLAYING; 
   } 

   if (event.key.code == Keyboard::Num3) 
   { 
 // Increase health
     player.upgradeHealth(); 
     state = State::PLAYING; 
   } 

   if (event.key.code == Keyboard::Num4) 
   { 
 // Increase speed
     player.upgradeSpeed(); 
     state = State::PLAYING; 
   } 

   if (event.key.code == Keyboard::Num5) 
   { 
 // Upgrade pickup
     healthPickup.upgrade(); 
     state = State::PLAYING; 
   } 

   if (event.key.code == Keyboard::Num6) 
   { 
 // Upgrade pickup
     ammoPickup.upgrade(); 
     state = State::PLAYING; 
   } 

   if (state == State::PLAYING) 
   { 

```

玩家现在可以在每次清除一波僵尸时升级。然而，我们目前无法增加僵尸的数量或级别的大小。

在`LEVELING_UP`状态的下一部分，在我们刚刚添加的代码之后，修改从`LEVELING_UP`到`PLAYING`状态改变时运行的代码。

以下是完整的代码。我已经突出显示了要么是新的要么已经稍作修改的行。

添加或修改突出显示的代码：

```cpp
   if (event.key.code == Keyboard::Num6) 
   { 
      ammoPickup.upgrade(); 
      state = State::PLAYING; 
   } 

   if (state == State::PLAYING) 
   { 
 // Increase the wave number
     wave++; 

     // Prepare thelevel 
     // We will modify the next two lines later 
 arena.width = 500 * wave;
     arena.height = 500 * wave; 
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
 numZombies = 5 * wave; 

     // Delete the previously allocated memory (if it exists) 
     delete[] zombies; 
     zombies = createHorde(numZombies, arena); 
     numZombiesAlive = numZombies; 

 // Play the powerup sound
     powerup.play(); 

     // Reset the clock so there isn't a frame jump 
     clock.restart(); 
   } 
}// End LEVELING up 

```

前面的代码首先递增`wave`变量。然后修改代码，使僵尸的数量和竞技场的大小与`wave`的新值相关。最后，我们添加了`powerup.play()`的调用来播放升级音效。

# 重新启动游戏

我们已经通过`wave`变量的值确定了竞技场的大小和僵尸的数量。我们还必须在每场新游戏开始时将弹药、枪支、`wave`和`score`重置为零。在游戏循环的事件处理部分找到以下代码，并添加高亮显示的代码：

```cpp
// Start a new game while in GAME_OVER state 
else if (event.key.code == Keyboard::Return && 
   state == State::GAME_OVER) 
{ 
   state = State::LEVELING_UP; 
 wave = 0;
   score = 0;

   // Prepare the gun and ammo for next game
   currentBullet = 0;
   bulletsSpare = 24;
   bulletsInClip = 6;
   clipSize = 6;
   fireRate = 1;

   // Reset the player's stats
   player.resetPlayerStats(); 
} 

```

现在我们可以玩游戏了，玩家可以在不断增大的竞技场中变得更加强大，而僵尸的数量也会不断增加，直到他死亡，然后一切重新开始。

# 播放其余的声音

现在我们将添加对`play`函数的其余调用。我们会逐个处理它们，因为准确确定它们的位置对于在正确时刻播放它们至关重要。

## 添加玩家重新装填时的声音效果

在三个地方添加高亮显示的代码，以在玩家按下***R***键尝试重新装填枪支时播放适当的`reload`或`reloadFailed`声音：

```cpp
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
 reload.play(); 
      } 
      else if (bulletsSpare > 0) 
      { 
         // Only few bullets left 
         bulletsInClip = bulletsSpare; 
         bulletsSpare = 0;           
 reload.play(); 
      } 
      else 
      { 
         // More here soon?! 
 reloadFailed.play(); 
      } 
   } 
} 

```

## 发出射击声音

在处理玩家点击鼠标左键的代码末尾附近添加对`shoot.play()`的高亮调用：

```cpp
// Fire a bullet 
if (sf::Mouse::isButtonPressed(sf::Mouse::Left)) 
{ 

   if (gameTimeTotal.asMilliseconds() 
      - lastPressed.asMilliseconds() 
      > 1000 / fireRate && bulletsInClip > 0) 
   { 

      // Pass the centre of the player and crosshair 
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

 shoot.play(); 

      bulletsInClip--; 
   } 

}// End fire a bullet 

```

## 在玩家被击中时播放声音

在下面的代码中，我们将对`hit.play`的调用包装在一个测试中，以查看`player.hit`函数是否返回`true`。请记住，`player.hit`函数用于测试前 100 毫秒内是否记录了击中。这将导致播放一个快速、重复的、沉闷的声音，但不会太快以至于声音模糊成一个噪音。

在这里添加对`hit.play`的调用：

```cpp
// Have any zombies touched the player        
for (int i = 0; i < numZombies; i++) 
{ 
   if (player.getPosition().intersects 
      (zombies[i].getPosition()) && zombies[i].isAlive()) 
   { 

      if (player.hit(gameTimeTotal)) 
      { 
         // More here later 
 hit.play(); 
      } 

      if (player.getHealth() <= 0) 
      { 
         state = State::GAME_OVER; 

         std::ofstream OutputFile("gamedata/scores.txt"); 
         OutputFile << hiScore; 
         OutputFile.close(); 

      } 
   } 
}// End player touched 

```

## 在拾取时播放声音

当玩家拾取生命值时，我们会播放常规的拾取声音，但当玩家获得弹药时，我们会播放重新装填的声音效果。

在适当的碰撞检测代码中，添加如下高亮显示的两个调用来播放声音：

```cpp
// Has the player touched health pickup 
if (player.getPosition().intersects 
   (healthPickup.getPosition()) && healthPickup.isSpawned()) 
{ 
   player.increaseHealthLevel(healthPickup.gotIt()); 
 // Play a sound
   pickup.play(); 

} 

// Has the player touched ammo pickup 
if (player.getPosition().intersects 
   (ammoPickup.getPosition()) && ammoPickup.isSpawned()) 
{ 
   bulletsSpare += ammoPickup.gotIt(); 
 // Play a sound
   reload.play(); 

} 

```

## 当射中僵尸时发出尖啸声

在检测子弹与僵尸碰撞的代码部分末尾添加对`splat.play`的调用：

```cpp
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
            if (zombies[j].hit()) { 
               // Not just a hit but a kill too 
               score += 10; 
               if (score >= hiScore) 
               { 
                  hiScore = score; 
               } 

               numZombiesAlive--; 

               // When all the zombies are dead (again) 
               if (numZombiesAlive == 0) { 
                  state = State::LEVELING_UP; 
               } 
            }   

 // Make a splat sound
           splat.play(); 

         } 
      } 

   } 
}// End zombie being shot 

```

您现在可以玩完整的游戏，并观看每一波僵尸和竞技场的增加。谨慎选择您的升级：

![当射中僵尸时发出尖啸声](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_11_001.jpg)

恭喜！

# 常见问题解答

以下是您可能会考虑的一些问题：

问：尽管使用了类，我发现代码变得非常冗长和难以管理，再次。

答：最大的问题之一是我们的代码结构。随着我们学习更多的 C++，我们也会学会使代码更易管理，通常更简洁。

问：声音效果似乎有点单调和不真实。如何改进？

答：显著改善玩家从声音中获得的感觉的一种方法是使声音具有方向性，并根据声源到玩家角色的距离改变音量。在下一个项目中，我们将使用 SFML 的高级声音功能。

# 总结

我们已经完成了僵尸竞技场游戏。这是一次相当的旅程。我们学到了很多 C++基础知识，比如引用、指针、面向对象编程和类。此外，我们还使用了 SFML 来管理摄像机、顶点数组和碰撞检测。我们学会了如何使用精灵表来减少对`window.draw`的调用次数，并提高帧率。使用 C++指针、STL 和一点面向对象编程，我们构建了一个单例类来管理我们的纹理，在下一个项目中，我们将扩展这个想法来管理我们游戏的所有资源。

在本书的结束项目中，我们将探索粒子效果、定向声音和分屏多人游戏。在 C++中，我们还将遇到继承、多态和一些新概念。


# 第十二章：抽象和代码管理 - 更好地利用 OOP

在本章中，我们将首次查看本书的最终项目。该项目将具有高级特点，如方向性声音，根据玩家位置从扬声器发出。它还将具有分屏合作游戏。此外，该项目还将引入**着色器**的概念，这是用另一种语言编写的程序，直接在图形卡上运行。到第十六章结束时，您将拥有一个完全功能的多人平台游戏，以命中经典**托马斯独自一人**的风格构建。

本章的主要重点将是启动项目，特别是探索如何构建代码结构以更好地利用 OOP。将涵盖以下主题：

+   最终项目《托马斯迟到》，包括游戏特点和项目资产的介绍

+   详细讨论我们将如何改进代码结构，与之前的项目相比

+   编写《托马斯迟到》游戏引擎

+   实施分屏功能

# 《托马斯迟到的游戏》

此时，如果您还没有，我建议您去观看《托马斯独自一人》的视频[`store.steampowered.com/app/220780/`](http://store.steampowered.com/app/220780/)。请注意其简单但美观的图形。视频还展示了各种游戏挑战，例如使用角色的不同属性（身高，跳跃，力量等）。为了保持我们的游戏简单而不失挑战，我们将比《托马斯独自一人》少一些解谜特点，但将增加需要两名玩家合作玩游戏的挑战。为了确保游戏不会太容易，我们还将让玩家与时间赛跑，这就是我们的游戏名字叫《托马斯迟到》的原因。

## 《托马斯迟到的特点》

我们的游戏不会像我们试图模仿的杰作那样先进，但它将具有一系列令人兴奋的游戏特点：

+   一个从适合关卡挑战的时间开始倒计时的时钟。

+   发射火坑会根据玩家的位置发出咆哮声，并在玩家掉下去时重新生成玩家。水坑也有同样的效果，但没有方向性的声音效果。

+   合作游戏 - 两名玩家必须在规定的时间内将他们的角色带到目标。他们经常需要一起工作，例如，身材较矮，跳跃力较低的鲍勃需要站在他朋友（托马斯）的头上。

+   玩家将有选择在全屏和分屏之间切换，因此他可以尝试自己控制两个角色。

+   每个关卡将设计并从文本文件中加载。这将使设计各种各样的关卡变得非常容易。

看看游戏的注释截图，看看一些特点的实际操作和组件/资产，构成了游戏：

![托马斯迟到的特点](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/B05523_12_01.jpg)

让我们看看这些特点，并描述一些更多的特点：

+   截图显示了一个简单的 HUD，详细说明了关卡编号和剩余秒数，直到玩家失败并不得不重新开始关卡。

+   您还可以清楚地看到分屏合作模式的实际操作。请记住这是可选的。单人玩家可以全屏玩游戏，同时在托马斯和鲍勃之间切换摄像头焦点。

+   在截图中并不是很清楚（尤其是在打印品中），但是当一个角色死亡时，他会爆炸成星花/烟火般的粒子效果。

+   水和火砖可以被策略性地放置，使得关卡更有趣，并迫使角色之间合作。更多内容请参见第十四章，“构建可玩关卡和碰撞检测”。

+   注意 Thomas 和 Bob——它们不仅在高度上不同，而且跳跃能力也有显著不同。这意味着 Bob 依赖于 Thomas 进行大跳跃，可以设计关卡来迫使 Thomas 选择避免碰头的路线。

+   此外，火砖会发出咆哮声。这些声音将与 Thomas 的位置有关。它们不仅是方向性的，可以从左侧或右侧扬声器发出，而且随着 Thomas 离开或接近源头，声音会变得越来越大或越来越小。

+   最后，在带注释的截图中，您可以看到背景。如果您将其与`background.png`文件（本章后面显示）进行比较，您会发现它们是完全不同的。我们将在第十六章，“扩展 SFML 类、粒子系统和着色器”中使用 OpenGL 着色器效果来实现背景中移动的——几乎是冒泡的——效果。

所有这些功能都需要更多的截图，这样我们在编写 C++代码时可以记住最终的产品。

以下截图显示了 Thomas 和 Bob 到达一个火坑，Bob 没有机会跳过去：

![“Thomas Was Late”的特点](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_12_002.jpg)

以下截图显示了 Bob 和 Thomas 合作清除一个危险的跳跃：

![“Thomas Was Late”的特点](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_12_003.jpg)

以下截图显示了我们如何设计需要“信仰之跃”才能达到目标的谜题：

![“Thomas Was Late”的特点](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_12_004.jpg)

以下截图展示了我们如何设计几乎任意大小的压抑洞穴系统。我们还可以设计需要 Bob 和 Thomas 分开并走不同路线的关卡：

![“Thomas Was Late”的特点](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_12_005.jpg)

## 从模板创建项目

创建“Thomas Was Late”项目与其他两个项目相同。只需在 Visual Studio 中按照这些简单的步骤进行操作：

1.  从主菜单中选择**文件** | **新建项目**。

1.  确保在左侧菜单中选择**Visual C++**，然后从所呈现的选项列表中选择**HelloSFML**。以下截图应该可以说明这一点：![从模板创建项目](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_12_006.jpg)

1.  在**名称：**字段中，键入`TWL`，并确保**为解决方案创建目录**选项已被选中。现在点击**确定**。

1.  现在我们需要将 SFML 的`.dll`文件复制到主项目目录中。我的主项目目录是`D:\Visual Studio Stuff\Projects\ TWL\TWL`。这个文件夹是在上一步中由 Visual Studio 创建的。如果您将`Projects`文件夹放在其他地方，请在那里执行此步骤。我们需要复制到`project`文件夹中的文件位于您的`SFML\bin`文件夹中。为每个位置打开一个窗口，并突出显示所需的`.dll`文件。

1.  现在将突出显示的文件复制并粘贴到项目中。

项目现在已经设置好，准备就绪。

## 项目资源

该项目中的资源比僵尸竞技场游戏中的资源更加丰富和多样。通常，资源包括屏幕上的字体、不同动作的声音效果（如跳跃、达到目标或远处火焰的咆哮）以及 Thomas 和 Bob 的图形以及所有背景砖块的精灵表。

游戏所需的所有资源都包含在下载包中。它们分别位于`第十二章/图形`和`第十二章/声音`文件夹中。

所需的字体没有提供。这是因为我想避免任何可能的许可歧义。不过这不会造成问题，因为我会准确地向你展示在哪里以及如何选择和下载字体。

虽然我会提供资产本身或者获取它们的信息，但你可能也想自己创建和获取它们。

除了我们期望的图形、声音和字体之外，这个游戏还有两种新的资产类型。它们是关卡设计文件和 GLSL 着色器程序。让我们接下来了解一下它们各自的情况。

### 游戏关卡设计

所有的关卡都是在一个文本文件中创建的。通过使用 0 到 3 的数字，我们可以构建挑战玩家的关卡设计。所有的关卡设计都在与其他资产相同目录下的 levels 文件夹中。现在可以随意偷看一下，但我们将在第十四章中详细讨论，*构建可玩关卡和碰撞检测*。

除了这些关卡设计资产，我们还有一种特殊类型的图形资产，叫做着色器。

### GLSL 着色器

着色器是用**GLSL**（图形库着色语言）编写的程序。不用担心要学习另一种语言，因为我们不需要深入学习就能利用着色器。着色器很特殊，因为它们是完整的程序，与我们的 C++代码分开，由 GPU 每一帧执行。事实上，一些着色器程序每一帧都会运行，对每一个像素！我们将在第十六章中了解更多细节，*扩展 SFML 类、粒子系统和着色器*。如果你等不及了，可以看一下下载包的`Chapter 12/shaders`文件夹中的文件。

### 图形资产特写

图形资产构成了我们游戏场景的部分。看一下图形资产，就能清楚地知道它们在我们的游戏中将被使用在哪里：

![图形资产特写](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_12_007.jpg)

如果`tiles_sheet`图形上的图块看起来与游戏截图有些不同，那是因为它们部分是透明的，背景透过显示会使它们有些变化。如果背景图与游戏截图中的实际背景完全不同，那是因为我们将编写的着色器程序会每一帧操纵每一个像素，创造一种"熔化"效果。

### 声音资产特写

声音文件都是`.wav`格式。这些文件包含了我们在游戏中的某些事件中播放的音效。它们如下：

+   `fallinfire.wav`：当玩家的头进入火焰并且没有逃脱的机会时会播放这个音效。

+   `fallinwater.wav`：水和火一样会导致死亡。这个音效会通知玩家他们需要从关卡的开始重新开始。

+   `fire1.wav`：这个音效是以单声道录制的。它将根据玩家距离火焰图块的距离以不同的音量播放，并根据玩家相对于火焰图块的左右位置从不同的扬声器播放。显然，我们需要学习一些更多的技巧来实现这个功能。

+   `jump.wav`：当玩家跳跃时会播放一个令人愉悦（稍微可预测）的欢呼声。

+   `reachgoal.wav`：当玩家（或玩家）将 Thomas 和 Bob 两个角色都带到目标方块时，会播放令人愉悦的胜利音效。

这些音效非常简单直接，你可以很容易地创建自己的音效。如果你打算替换`fire1.wav`文件，确保将你的声音保存为单声道（而不是立体声）格式。这其中的原因将在第十五章中解释，*声音空间化和 HUD*。

### 将资产添加到项目中

一旦您决定要使用哪些资产，就是将它们添加到项目的时候了。以下说明将假定您使用了书籍下载包中提供的所有资产。

如果您使用自己的资产，只需用您选择的文件替换相应的声音或图形文件，文件名完全相同：

1.  浏览到 Visual `D:\Visual Studio Stuff\Projects\TWL\TWL`目录。

1.  在此文件夹中创建五个新文件夹，并将它们命名为`graphics`，`sound`，`fonts`，`shaders`和`levels`。

1.  从下载包中，将`Chapter 12/graphics`的全部内容复制到`D:\Visual Studio Stuff\Projects\TWL\TWL\graphics`文件夹中。

1.  从下载包中，将`Chapter 12/sound`的全部内容复制到`D:\Visual Studio Stuff\Projects\TWL\TWL\sound`文件夹中。

1.  现在在您的网络浏览器中访问[`www.dafont.com/roboto.font`](http://www.dafont.com/roboto.font)，并下载**Roboto Light**字体。

1.  提取压缩下载的内容，并将`Roboto-Light.ttf`文件添加到`D:\Visual Studio Stuff\Projects\TWL\TWL\fonts`文件夹中。

1.  从下载包中，将`Chapter 12/levels`的全部内容复制到`D:\Visual Studio Stuff\Projects\TWL\TWL\levels`文件夹中。

1.  从下载包中，将`Chapter 12/shaders`的全部内容复制到`D:\Visual Studio Stuff\Projects\TWL\TWL\shaders`文件夹中。

现在我们有了一个新项目，以及整个项目所需的所有资产，我们可以讨论如何构建游戏引擎代码。

# 构建 Thomas Was Late 代码的结构

到目前为止，在两个项目中都很明显的一个问题是代码变得非常冗长和难以控制。OOP 允许我们将项目分解为称为类的逻辑和可管理的块。

通过引入**Engine 类**，我们将大大改善此项目中代码的可管理性。Engine 类将具有三个私有函数，分别是`input`，`update`和`draw`。这应该听起来非常熟悉。这些函数中的每一个将保存以前全部在`main`函数中的代码的一部分。这些函数将分别在自己的代码文件中，`Input.cpp`，`Update.cpp`和`Draw.cpp`中。

`Engine`类中还将有一个公共函数，可以使用`Engine`的实例调用。这个函数是`run`，将负责调用`input`，`update`和`draw`，每帧游戏调用一次：

![构建 Thomas Was Late 代码的结构](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_12_008.jpg)

此外，由于我们已经将游戏引擎的主要部分抽象为`Engine`类，我们还可以将许多变量从`main`中移动并将它们作为`Engine`的成员。要启动我们的游戏引擎，我们只需要创建一个`Engine`的实例并调用它的`run`函数。这里是一个超级简单的主函数的预览：

```cpp
int main() 
{ 
   // Declare an instance of Engine 
   Engine engine; 

   // Start the engine 
   engine.run(); 

   // Quit in the usual way when the engine is stopped 
   return 0; 
} 

```

### 提示

暂时不要添加上述代码。

为了使我们的代码更加可管理和可读，我们还将抽象出加载关卡和碰撞检测等重要任务的责任，放到单独的函数中（在单独的代码文件中）。这两个函数分别是`loadLevel`和`detectCollisions`。我们还将编写其他函数来处理 Thomas Was Late 项目的一些新功能。随着它们的出现，我们将详细介绍它们。

为了更好地利用 OOP，我们将完全将游戏特定领域的责任委托给新的类。您可能还记得以前项目中的声音和 HUD 代码非常冗长。我们将构建一个`SoundManager`和`HUD`类来以更清晰的方式处理这些方面。当我们实现它们时，它们的工作方式将被深入探讨。

游戏关卡本身比以前的游戏更加深入，因此我们还将编写一个`LevelManager`类。

正如您所期望的，可玩角色也将使用类制作。但是，对于这个项目，我们将学习更多的 C++，并实现一个`PlayableCharacter`类，其中包含 Thomas 和 Bob 的所有常见功能，然后`Thomas`和`Bob`类，它们将继承这些常见功能，并实现自己的独特功能和能力。这，也许并不奇怪，被称为**继承**。我将在接下来的第十三章，“高级面向对象编程，继承和多态”中更详细地介绍继承。

我们还将实现许多其他类来执行特定的职责。例如，我们将使用粒子系统制作一些漂亮的爆炸效果。您可能能够猜到，为了做到这一点，我们将编写一个`Particle`类和一个`ParticleSystem`类。所有这些类都将作为`Engine`类的成员具有实例。以这种方式做事将使游戏的所有功能都可以从游戏引擎中访问，但将细节封装到适当的类中。

在我们继续查看将创建 Engine 类的实际代码之前，要提到的最后一件事是，我们将重用我们为“Zombie Arena”游戏讨论和编写的`TextureHolder`类，而不做任何更改。

# 构建游戏引擎

如前面的讨论所建议的，我们将编写一个名为`Engine`的类，它将控制并绑定 Thomas Was Late 游戏的不同部分。

我们将首先使上一个项目中的`TextureHolder`类在这个项目中可用。

## 重用 TextureHolder 类

我们讨论并编写的`TextureHolder`类对于这个项目也会很有用。虽然可以直接从上一个项目添加文件（`TextureHolder.h`和`TextureHolder.cpp`），而无需重新编码或重新创建文件，但我不想假设您没有直接跳转到这个项目。接下来是非常简要的说明，以及创建`TextureHolder`类的完整代码清单。如果您想要解释该类或代码，请参阅第八章，“指针、标准模板库和纹理管理”。

### 提示

如果您完成了上一个项目，并且*确实*想要从“Zombie Arena”项目中添加该类，只需执行以下操作：在“解决方案资源管理器”窗口中，右键单击“头文件”，然后选择“添加”|“现有项...”。浏览到上一个项目的`TextureHolder.h`并选择它。在“解决方案资源管理器”窗口中，右键单击“源文件”，然后选择“添加”|“现有项...”。浏览到上一个项目的`TextureHolder.cpp`并选择它。现在您可以在这个项目中使用`TextureHolder`类。请注意，文件在项目之间共享，任何更改都将在两个项目中生效。

要从头开始创建`TextureHolder`类，请在“解决方案资源管理器”中右键单击“头文件”，然后选择“添加”|“新项...”。在“添加新项”窗口中，通过左键单击突出显示（高亮）“头文件（.h）”，然后在“名称”字段中输入`TextureHolder.h`。最后，单击“添加”按钮。

将以下代码添加到`TextureHolder.h`中：

```cpp
#pragma once 
#ifndef TEXTURE_HOLDER_H 
#define TEXTURE_HOLDER_H 

#include <SFML/Graphics.hpp> 
#include <map> 

class TextureHolder 
{ 
private: 
   // A map container from the STL, 
   // that holds related pairs of String and Texture 
   std::map<std::string, sf::Texture> m_Textures; 

   // A pointer of the same type as the class itself 
   // the one and only instance 
   static TextureHolder* m_s_Instance; 

public: 
   TextureHolder(); 
   static sf::Texture& GetTexture(std::string const& filename); 

}; 

#endif 

```

在“解决方案资源管理器”中右键单击“源文件”，然后选择“添加”|“新项...”。在“添加新项”窗口中，通过左键单击突出显示（高亮）“C++文件（**.cpp**）”，然后在“名称”字段中输入`TextureHolder.cpp`。最后，单击“添加”按钮。

将以下代码添加到`TextureHolder.cpp`中：

```cpp
#include "stdafx.h" 
#include "TextureHolder.h" 
#include <assert.h> 

using namespace sf; 
using namespace std; 

TextureHolder* TextureHolder::m_s_Instance = nullptr; 

TextureHolder::TextureHolder() 
{ 
   assert(m_s_Instance == nullptr); 
   m_s_Instance = this; 
} 

sf::Texture& TextureHolder::GetTexture(std::string const& filename) 
{ 
   // Get a reference to m_Textures using m_S_Instance 
   auto& m = m_s_Instance->m_Textures; 
   // auto is the equivalent of map<string, Texture> 

   // Create an iterator to hold a key-value-pair (kvp) 
   // and search for the required kvp 
   // using the passed in file name 
   auto keyValuePair = m.find(filename); 
   // auto is equivalent of map<string, Texture>::iterator 

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
      // File name not found 
      // Create a new key value pair using the filename 
      auto& texture = m[filename]; 
      // Load the texture from file in the usual way 
      texture.loadFromFile(filename); 

      // Return the texture to the calling code 
      return texture; 
   } 
} 

```

我们现在可以开始创建我们的新`Engine`类了。

## 编写 Engine.h

和往常一样，我们将从头文件开始，其中包含函数声明和成员变量。请注意，我们将在整个项目中重新访问此文件，以添加更多函数和成员变量。目前，我们将只添加在这个阶段必要的代码。

在 **解决方案资源管理器** 中右键单击 **头文件**，然后选择 **添加** | **新建项...**。在 **添加新项** 窗口中，通过左键单击突出显示（高亮） **头文件（** `.h` **）**，然后在 **名称** 字段中键入 `Engine.h`。最后，单击 **添加** 按钮。现在我们准备好为 `Engine` 类编写头文件了。

添加以下成员变量以及函数声明。其中许多我们在其他项目中已经见过，有些我们在 *Structuring the Thomas Was Late* 代码部分讨论过。注意函数和变量的名称，以及它们是私有的还是公共的。添加以下代码到 `Engine.h` 文件中，然后我们将讨论它：

```cpp
#pragma once 
#include <SFML/Graphics.hpp> 
#include "TextureHolder.h" 

using namespace sf; 

class Engine 
{ 
private: 
   // The texture holder 
   TextureHolder th; 

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

   // Declare a sprite and a Texture  
   // for the background 
   Sprite m_BackgroundSprite; 
   Texture m_BackgroundTexture; 

   // Is the game currently playing? 
   bool m_Playing = false; 

   // Is character 1 or 2 the current focus? 
   bool m_Character1 = true; 

   // Start in fullscreen mode 
   bool m_SplitScreen = false; 

   // How much time is left in the current level 
   float m_TimeRemaining = 10; 
   Time m_GameTimeTotal; 

   // Is it time for a new/first level? 
   bool m_NewLevelRequired = true; 

   // Private functions for internal use only 
   void input(); 
   void update(float dtAsSeconds); 
   void draw(); 

public: 
   // The Engine constructor 
   Engine(); 

   // Run will call all the private functions 
   void run(); 

}; 

```

这是所有私有变量和函数的完整概述。在适当的情况下，我会在解释上花费更多时间：

+   `TextureHolder th`：`TextureHolder` 类的唯一实例。

+   `TILE_SIZE`：一个有用的常量，提醒我们精灵表中的每个瓦片都是五十像素宽和五十像素高。

+   `VERTS_IN_QUAD`：一个有用的常量，使我们对 `VertexArray` 的操作更不容易出错。事实上，一个四边形中有四个顶点。现在我们不会忘记它了。

+   `GRAVITY`：一个表示游戏角色每秒向下推动的像素数的常量 `int` 值。一旦游戏完成，这是一个非常有趣的值。我们将其初始化为 `300`，因为这对我们最初的级别设计效果很好。

+   `m_Window`：像我们在所有项目中看到的那样，通常的 `RenderWindow` 对象。

+   SFML `View` 对象，`m_MainView`，`m_LeftView`，`m_RightView`，`m_BGMainView`，`m_BGLeftView`，`m_BGRightView` 和 `m_HudView`：前三个 `View` 对象用于全屏视图，游戏的左右分屏视图。我们还为这三个分别有一个单独的 SFML `View` 对象，用于绘制背景。最后一个 `View` 对象 `m_HudView`，将在其他六个视图的适当组合上方显示得分、剩余时间和任何玩家的消息。有七个不同的 `View` 对象可能会暗示复杂性，但当你看到本章的进展如何处理它们时，你会发现它们非常简单。我们将在本章结束时解决整个分屏/全屏问题。

+   `Sprite m_BackgroundSprite` 和 `Texture m_BackgroundTexture`：可以预料到，这组 SFML `Sprite` 和 `Texture` 将用于显示和保存来自图形资源文件夹的背景图形。

+   `m_Playing`：这个布尔值将让游戏引擎知道当前级别是否已经开始（通过按下 ***Enter*** 键）。一旦玩家开始游戏，他们就没有暂停游戏的选项。

+   `m_Character1`：当屏幕是全屏时，它应该以 Thomas（m_Character1 = true）还是 Bob（m_Character1 = false）为中心？最初，它被初始化为 true，以便以 Thomas 为中心。

+   `m_SplitScreen`：游戏当前是否以分屏模式进行？我们将使用这个变量来决定如何使用我们之前声明的所有 `View` 对象。

+   `m_TimeRemaining` 变量：这个 `float` 变量保存了当前级别剩余的时间。在之前的代码中，它被设置为 `10` 用于测试目的，直到我们真正为每个级别设置一个特定的时间。

+   `m_GameTimeTotal` 变量：这个变量是一个 SFML 时间对象。它跟踪游戏已经进行了多长时间。

+   `m_NewLevelRequired`布尔变量：这个变量用于检查玩家是否刚刚完成或失败了一个关卡。然后我们可以使用它来触发加载下一个关卡或重新开始当前关卡。

+   `input`函数：这个函数将处理玩家的所有输入，这个游戏中全部来自键盘。乍一看，它似乎直接处理所有的键盘输入。然而，在这个游戏中，我们将直接处理影响 Thomas 或 Bob 的键盘输入，这将直接在`Thomas`和`Bob`类中进行。我们将调用`input`函数，这个函数将直接处理键盘输入，比如退出、切换到分屏等其他键盘输入。

+   `update`函数：这个函数将完成我们之前在`main`函数的更新部分中做的所有工作。我们还将从`update`函数中调用一些其他函数，以保持代码的组织性。如果你回顾代码，你会看到它接收一个`float`参数，这个参数将保存自上一帧以来经过的秒数的分数。当然，这正是我们需要更新所有游戏对象的内容。

+   `draw`函数：这个函数将包含以前项目中主函数绘图部分的所有代码。然而，当我们学习使用 SFML 进行其他绘图方式时，会有一些绘图代码不在这个函数中。当我们学习第十六章中的粒子系统时，我们将看到这些新代码，*扩展 SFML 类、粒子系统和着色器*。

现在让我们来看一下所有的公共函数：

+   `Engine`构造函数：正如我们所期望的那样，当我们首次声明`Engine`的实例时，将调用这个函数。它将进行所有的设置和类的初始化。我们很快将在编写`Engine.cpp`文件时看到具体内容。

+   `run`函数：这是我们需要调用的唯一公共函数。它将触发输入、更新和绘制的执行，完成所有工作。

接下来，我们将看到所有这些函数的定义以及一些变量的作用。

## 编写 Engine.cpp

在我们之前的所有类中，我们将所有的函数定义放在`.cpp`文件中，并以类名为前缀。由于我们这个项目的目标是使代码更易管理，我们正在以稍微不同的方式做事情。

在`Engine.cpp`文件中，我们将放置构造函数（`Engine`）和公共`run`函数。所有其他函数将放在它们自己的`.cpp`文件中，文件名清楚地说明了哪个函数放在哪里。只要我们在包含`Engine`类的所有文件的顶部添加适当的包含指令（`#include "Engine.h"`），这对编译器来说不会是问题。 

让我们开始编写`Engine`并在`Engine.cpp`中运行它。在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，选择（单击左键）**C++文件（.cpp）**，然后在**名称**字段中输入`Engine.cpp`。最后，单击**添加**按钮。现在我们已经准备好为`Engine`类编写`.cpp`文件。

### 编写 Engine 类构造函数定义

这个函数的代码将放在我们最近创建的`Engine.cpp`文件中。

添加以下代码，然后我们可以讨论它：

```cpp
#include "stdafx.h" 
#include "Engine.h" 

Engine::Engine() 
{ 
   // Get the screen resolution  
   // and create an SFML window and View 
   Vector2f resolution; 
   resolution.x = VideoMode::getDesktopMode().width; 
   resolution.y = VideoMode::getDesktopMode().height; 

   m_Window.create(VideoMode(resolution.x, resolution.y), 
      "Thomas was late", 
      Style::Fullscreen); 

   // Initialize the fullscreen view 
   m_MainView.setSize(resolution); 
   m_HudView.reset( 
      FloatRect(0, 0, resolution.x, resolution.y)); 

   // Inititialize the split screen Views 
   m_LeftView.setViewport( 
      FloatRect(0.001f, 0.001f, 0.498f, 0.998f)); 

   m_RightView.setViewport( 
      FloatRect(0.5f, 0.001f, 0.499f, 0.998f)); 

   m_BGLeftView.setViewport( 
      FloatRect(0.001f, 0.001f, 0.498f, 0.998f)); 

   m_BGRightView.setViewport( 
      FloatRect(0.5f, 0.001f, 0.499f, 0.998f)); 

   m_BackgroundTexture = TextureHolder::GetTexture( 
      "graphics/background.png"); 

   // Associate the sprite with the texture 
   m_BackgroundSprite.setTexture(m_BackgroundTexture); 

} 

```

我们之前看到的大部分代码都很熟悉。例如，有通常的代码行来获取屏幕分辨率以及创建一个`RenderWindow`。在前面的代码结束时，我们使用了现在熟悉的代码来加载纹理并将其分配给一个 Sprite。在这种情况下，我们正在加载`background.png`纹理并将其分配给`m_BackgroundSprite`。

需要一些解释的是`setViewport`函数的四次调用之间的代码。`setViewport`函数将屏幕的一部分分配给 SFML 的`View`对象。但它不使用像素坐标。它使用比例。其中“1”是整个屏幕（宽度或高度），每次调用`setViewport`的前两个值是起始位置（水平，然后垂直），最后两个值是结束位置。

注意，`m_LeftView`和`m_BGLeftView`的位置完全相同，从屏幕的几乎最左侧（0.001）开始，结束于距离中心的两千分之一（0.498）。

`m_RightView`和`m_BGRightView`也位于完全相同的位置，从前两个`View`对象的左侧开始（0.5），延伸到屏幕的几乎最右侧（0.998）。

此外，所有视图在屏幕的顶部和底部留下了一小部分空隙。当我们在白色背景上绘制这些`View`对象时，它将产生在屏幕的两侧之间有一条细白线以及屏幕边缘周围有一条细白色边框的效果。

我已经尝试在以下图表中表示这种效果：

![编写引擎类构造函数定义](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_12_009.jpg)

最好的理解方法是完成本章，运行代码，看到它的实际效果。

### 编写 run 函数定义

这个函数的代码将放在我们最近创建的`Engine.cpp`文件中。

在上一个构造函数代码之后立即添加以下代码：

```cpp
void Engine::run() 
{ 
   // Timing    
   Clock clock; 

   while (m_Window.isOpen()) 
   { 
      Time dt = clock.restart(); 
      // Update the total game time 
      m_GameTimeTotal += dt; 
      // Make a decimal fraction from the delta time 
      float dtAsSeconds = dt.asSeconds(); 

      // Call each part of the game loop in turn 
      input(); 
      update(dtAsSeconds); 
      draw(); 
   } 
} 

```

run 函数是我们引擎的中心-它启动所有其他部分。首先，我们声明一个 Clock 对象。接下来，我们有熟悉的`while(window.isOpen())`循环，它创建游戏循环。在这个 while 循环内，我们做以下事情：

1.  重新启动`clock`并将上一个循环所花费的时间保存在`dt`中。

1.  跟踪`m_GameTimeTotal`中经过的总时间。

1.  声明并初始化一个`float`来表示上一帧中经过的秒数的一部分。

1.  调用`input`。

1.  调用`update`并传入经过的时间（`dtAsSeconds`）。

1.  调用`draw`。

所有这些都应该看起来非常熟悉。新的是它包含在`run`函数中。

### 编写 input 函数定义

如前所述，这个函数的代码将放在自己的文件中，因为它比构造函数或`run`函数更复杂。我们将使用`#include "Engine.h"`并在函数签名前加上`Engine::`以确保编译器了解我们的意图。

在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加** | **新项目...**。在**添加新项目**窗口中，突出显示（通过左键单击）**C++文件（**`.cpp`**）**，然后在**名称**字段中输入`Input.cpp`。最后，单击**添加**按钮。我们现在准备编写`input`函数的代码。

添加以下代码：

```cpp
void Engine::input() 
{ 
   Event event; 
   while (m_Window.pollEvent(event)) 
   { 
      if (event.type == Event::KeyPressed) 
      {         
         // Handle the player quitting 
         if (Keyboard::isKeyPressed(Keyboard::Escape)) 
         { 
            m_Window.close(); 
         } 

         // Handle the player starting the game 
         if (Keyboard::isKeyPressed(Keyboard::Return)) 
         { 
            m_Playing = true; 
         } 

         // Switch between Thomas and Bob 
         if (Keyboard::isKeyPressed(Keyboard::Q)) 
         { 
            m_Character1 = !m_Character1; 
         } 

         // Switch between full and split screen 
         if (Keyboard::isKeyPressed(Keyboard::E)) 
         { 
            m_SplitScreen = !m_SplitScreen; 
         } 
      } 
   }   
} 

```

与之前的两个项目一样，我们每帧都会检查`RenderWindow`事件队列。同样，我们像以前一样使用`if (Keyboard::isKeyPressed(Keyboard::E))`来检测特定的键盘键。我们刚刚添加的代码中最重要的是这些键实际上做了什么：

+   像往常一样，***Esc***键关闭窗口，游戏将退出。

+   ***Enter***键将`m_Playing`设置为 true，最终，这将导致关卡开始。

+   ***Q***键在全屏模式下在`true`和`false`之间切换`m_Character1`的值。它将在主`View`的中心之间切换 Thomas 和 Bob。

+   ***E***键在`true`和`false`之间切换`m_SplitScreen`。这将导致在全屏和分屏视图之间切换。

大部分键盘功能将在本章结束时完全可用。我们即将能够运行我们的游戏引擎。接下来，让我们编写`update`函数。

### 编写 update 函数定义

如前所述，这个函数的代码将放在自己的文件中，因为它比构造函数或`run`函数更加广泛。我们将使用`#include "Engine.h"`并在函数签名前加上`Engine::`以确保编译器知道我们的意图。

在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，通过左键单击**C++文件（**`.cpp`**）**，然后在**名称**字段中输入`Update.cpp`。最后，单击**添加**按钮。现在我们准备为`update`函数编写一些代码。

将以下代码添加到`Update.cpp`文件中以实现`update`函数：

```cpp
#include "stdafx.h" 
#include "Engine.h" 
#include <SFML/Graphics.hpp> 
#include <sstream> 

using namespace sf; 

void Engine::update(float dtAsSeconds) 
{ 

   if (m_Playing) 
   { 
      // Count down the time the player has left 
      m_TimeRemaining -= dtAsSeconds; 

      // Have Thomas and Bob run out of time? 
      if (m_TimeRemaining <= 0) 
      { 
         m_NewLevelRequired = true; 
      } 

   }// End if playing 

} 

```

首先注意，`update`函数接收上一帧所用时间作为参数。当然，这对于`update`函数履行其职责至关重要。

在这个阶段，前面的代码并没有实现任何可见的效果。它确立了我们将来需要的结构。它从`m_TimeRemaining`中减去了上一帧所用的时间。它检查时间是否已经用完，如果是，就将`m_NewLevelRequired`设置为`true`。所有这些代码都包裹在一个`if`语句中，只有当`m_Playing`为`true`时才执行。原因是，与以前的项目一样，我们不希望在游戏尚未开始时时间推移和对象更新。

随着项目的继续，我们将在这段代码的基础上构建。

### 编写绘制函数定义

如前所述，这个函数的代码将放在自己的文件中，因为它比构造函数或`run`函数更加广泛。我们将使用`#include "Engine.h"`并在函数签名前加上`Engine::`以确保编译器知道我们的意图。

在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，通过左键单击**C++文件（**`.cpp`**）**，然后在**名称**字段中输入`Draw.cpp`。最后，单击**添加**按钮。现在我们准备为`draw`函数添加一些代码。

将以下代码添加到`Draw.cpp`文件中以实现`draw`函数：

```cpp
#include "stdafx.h" 
#include "Engine.h" 

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
   } 
   else 
   { 
      // Split screen view is active 

      // First draw Thomas' side of the screen 

      // Switch to background view 
      m_Window.setView(m_BGLeftView); 
      // Draw the background 
      m_Window.draw(m_BackgroundSprite); 
      // Switch to m_LeftView 
      m_Window.setView(m_LeftView); 

      // Now draw Bob's side of the screen 

      // Switch to background view 
      m_Window.setView(m_BGRightView); 
      // Draw the background 
      m_Window.draw(m_BackgroundSprite); 
      // Switch to m_RightView 
      m_Window.setView(m_RightView); 

   } 

   // Draw the HUD 
   // Switch to m_HudView 
   m_Window.setView(m_HudView); 

   // Show everything we have just drawn 
   m_Window.display(); 
} 

```

在前面的代码中，我们没有看到任何新东西。代码通常从清除屏幕开始。在这个项目中，我们用白色清除屏幕。新的是不同的绘制选项是如何通过条件分隔的，检查屏幕当前是分割还是全屏。

```cpp
if (!m_SplitScreen) 
{ 
} 
else 
{ 
} 

```

如果屏幕没有分割，我们在背景`View`（`m_BGView`）中绘制背景精灵，然后切换到主全屏`View`（`m_MainView`）。请注意，目前我们实际上并没有在`m_MainView`中进行任何绘制。

另一方面，如果屏幕被分割，`else`块中的代码将被执行，我们将用屏幕左侧的背景精灵绘制`m_BGLeftView`，然后切换到`m_LeftView`。

然后，在`else`块中，我们用屏幕右侧的背景精灵绘制`m_BGRightView`，然后切换到`m_RightView`。

在刚才描述的`if...else`结构之外，我们切换到`m_HUDView`。在这个阶段，我们实际上并没有在`m_HUDView`中绘制任何东西。

与另外两个（`input`、`update`）最重要的函数一样，我们将经常回到`draw`函数。我们将添加需要绘制的游戏新元素。您会注意到，每次我们这样做时，我们都会在主、左和右部分中添加代码。

让我们快速回顾一下`Engine`类，然后我们可以启动它。

## 到目前为止的 Engine 类

我们已经将以前在`main`函数中的所有代码抽象成了`input`、`update`和`draw`函数。这些函数的连续循环以及时间控制都由`run`函数处理。

考虑在 Visual Studio 中保持**Input.cpp**、**Update.cpp**和**Draw.cpp**标签打开，可能按顺序组织，如下面的截图所示：

![到目前为止的引擎类](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_12_010.jpg)

在项目的过程中，我们将重新审视每一个这些函数，以添加更多的代码。现在我们有了`Engine`类的基本结构和功能，我们可以在`main`函数中创建一个实例，并看到它的运行。

# 编写主函数

让我们将`HelloSFML.cpp`文件重命名为`Main.cpp`。右键单击**解决方案资源管理器**中的`HelloSFML`文件，然后选择**重命名**。将名称更改为`Main.cpp`。这将是包含我们的`main`函数和实例化`Engine`类的代码的文件。

将以下代码添加到`Main.cpp`中：

```cpp
#include "stdafx.h" 
#include "Engine.h" 

int main() 
{ 
   // Declare an instance of Engine 
   Engine engine; 

   // Start the engine VRRrrrrmmm 
   engine.run(); 

   // Quit in the usual way when the engine is stopped 
   return 0; 
} 

```

我们所做的就是为`Engine`类添加一个包含指令，声明一个`Engine`的实例，然后调用它的`run`函数。直到玩家退出并且执行返回到`main`和`return 0`语句，一切都将由`Engine`类处理。

这很容易。现在我们可以运行游戏，看到空的背景，无论是全屏还是分屏，最终都将包含所有的动作。

到目前为止，游戏在全屏模式下，只显示了背景：

![编写主函数](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_12_011.jpg)

现在按下***E***键，你将能够看到屏幕被整齐地分成两半，准备好进行分屏合作游戏：

![编写主函数](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_12_012.jpg)

以下是一些可能会让你困惑的问题。

# 常见问题

Q）我不完全理解代码文件的结构。

A）抽象确实可以使我们的代码结构变得不太清晰，但实际的代码本身变得更容易。我们将代码分割成`Input.cpp`、`Update.cpp`和`Draw.cpp`，而不是像以前的项目那样把所有东西塞进主函数中。此外，随着我们的进行，我们将使用更多的类来将相关的代码分组在一起。再次学习《构建 Thomas Was Late 代码》部分，特别是图表。

# 总结

在本章中，我们介绍了 Thomas Was Late 游戏，并为项目的其余部分奠定了理解和代码结构的基础。在解决方案资源管理器中确实有很多文件，但只要我们理解每个文件的目的，我们会发现项目的实现变得更加容易。

在接下来的章节中，我们将学习另外两个基本的 C++主题，继承和多态。我们还将开始利用它们，构建三个类来代表两个可玩角色。


# 第十三章：高级 OOP-继承和多态

在本章中，我们将通过更深入地了解**继承**和**多态**的略微更高级的概念来进一步扩展我们对 OOP 的知识。然后，我们将能够使用这些新知识来实现我们游戏的明星角色 Thomas 和 Bob。在本章中，我们将更详细地介绍以下内容：

+   如何使用继承扩展和修改一个类？

+   通过多态将一个类的对象视为多种类型的类

+   抽象类以及设计从未实例化的类实际上可以很有用

+   构建一个抽象的`PlayableCharacter`类

+   在`Thomas`和`Bob`类中使用继承

+   将 Thomas 和 Bob 添加到游戏项目中

# 继承

我们已经看到了如何通过实例化/创建来使用 SFML 库的类的对象来使用其他人的辛勤工作。但是这整个 OOP 的东西甚至比这更深入。

如果有一个类中有很多有用的功能，但不完全符合我们的要求怎么办？在这种情况下，我们可以从其他类中**继承**。就像它听起来的那样，**继承**意味着我们可以利用其他人的类的所有功能和好处，包括封装，同时进一步完善或扩展代码，使其特别适合我们的情况。在这个项目中，我们将从一些 SFML 类中继承并扩展。我们还将对我们自己的类进行同样的操作。

让我们看一些使用继承的代码，

## 扩展一个类

考虑到所有这些，让我们看一个示例类，并看看我们如何扩展它，只是为了看看语法和作为第一步。

首先，我们定义一个要继承的类。这与我们创建其他任何类的方式没有区别。看一下这个假设的`Soldier`类声明：

```cpp
class Soldier 
{ 
   private: 
      // How much damage can the soldier take 
      int m_Health; 
      int m_Armour; 
      int m_Range; 
      int m_ShotPower; 

   Public: 
      void setHealth(int h); 
      void setArmour(int a);   
      void setRange(int r); 
      void setShotPower(int p); 
}; 

```

在前面的代码中，我们定义了一个`Soldier`类。它有四个私有变量，`m_Health`、`m_Armour`、`m_Range`和`m_ShotPower`。它有四个公共函数`setHealth`、`setArmour`、`setRange`和`setShotPower`。我们不需要看函数的定义，它们只是初始化与它们的名称明显相关的适当变量。

我们还可以想象，一个完全实现的`Soldier`类会比这个更加深入。它可能有`shoot`、`goProne`等函数。如果我们在一个 SFML 项目中实现了`Soldier`类，它可能会有一个`Sprite`对象，以及一个`update`和一个`getPostion`函数。

这里呈现的简单场景适合学习继承。现在让我们看看一些新的东西，实际上是从`Soldier`类继承。看看这段代码，特别是突出显示的部分：

```cpp
class Sniper : public Soldier 
{ 
public: 
   // A constructor specific to Sniper 
   Sniper::Sniper(); 
}; 

```

通过在`Sniper`类声明中添加`: public Soldier`代码，`Sniper`继承自`Soldier`。但这到底意味着什么呢？`Sniper`是一个`Soldier`。它拥有`Soldier`的所有变量和函数。然而，继承不仅仅是这样。

还要注意，在前面的代码中，我们声明了一个`Sniper`构造函数。这个构造函数是`Sniper`独有的。我们不仅继承了`Soldier`，还**扩展了**`Soldier`。`Soldier`类的所有功能（定义）都由`Soldier`类处理，但`Sniper`构造函数的定义必须由`Sniper`类处理。

这是假设的`Sniper`构造函数定义可能是这样的：

```cpp
// In Sniper.cpp 
Sniper::Sniper() 
{ 
   setHealth(10); 
   setArmour(10);  
   setRange(1000); 
   setShotPower(100); 
} 

```

我们可以继续编写一堆其他类，这些类是`Soldier`类的扩展，也许是`Commando`和`Infantryman`。每个类都有完全相同的变量和函数，但每个类也可以有一个独特的构造函数，用于初始化适合`Soldier`类型的变量。`Commando`可能有非常高的`m_Health`和`m_ShotPower`，但是`m_Range`非常小。`Infantryman`可能介于`Commando`和`Sniper`之间，每个变量的值都是中等的。

### 提示

好像面向对象编程还不够有用，我们现在可以对现实世界的对象进行建模，包括它们的层次结构。我们通过子类化、扩展和继承其他类来实现这一点。

我们可能想要学习的术语是，被扩展的类是**超类**，从超类继承的类是**子类**。我们也可以说**父**类和**子**类。

### 提示

你可能会发现自己对继承这个问题感到困惑：为什么？原因大致如下：我们可以一次编写通用代码；在父类中，我们可以更新这些通用代码，所有继承它的类也会被更新。此外，子类只能使用公共和受保护的实例变量和函数。因此，如果设计得当，这也进一步增强了封装的目标。

你说过受保护的吗？是的。类变量和函数有一个叫做**protected**的访问限定符。你可以把受保护的变量看作介于公共和私有之间。这里是访问限定符的快速摘要，以及有关受保护限定符的更多细节：

+   `公共`变量和函数可以被任何人访问和使用。

+   `私有`变量和函数只能被类的内部代码访问/使用。这对封装是有利的，当我们需要访问/更改私有变量时，我们可以提供公共的`getter`和`setter`函数（如`getSprite`等）。如果我们扩展了一个具有`私有`变量和函数的类，那么子类*不能*直接访问其父类的私有数据。

+   `受保护`变量和函数几乎与私有相同。它们不能被类的实例直接访问/使用。但是，它们可以被任何扩展它们所声明的类的类直接使用。因此，它们就像是私有的，除了对子类。

要完全理解受保护的变量和函数是什么以及它们如何有用，让我们先看看另一个主题，然后我们可以看到它们的作用。

# 多态

**多态**允许我们编写的代码不那么依赖于我们要操作的类型。这可以使我们的代码更清晰和更高效。多态意味着不同的形式。如果我们编码的对象可以是多种类型的东西，那么我们就可以利用这一点。

### 注意

对我们来说，多态意味着什么？简化到最简单的定义，多态就是：任何子类都可以作为使用超类的代码的一部分。这意味着我们可以编写更简单、更易于理解的代码，也更容易修改或更改。此外，我们可以为超类编写代码，并依赖于这样一个事实，即在一定的参数范围内，无论它被子类化多少次，代码仍然可以正常工作。

让我们讨论一个例子。

假设我们想要使用多态来帮助编写一个动物园管理游戏，我们需要喂养和照顾动物的需求。我们可能会想要一个名为`feed`的函数。我们可能还想将要喂食的动物的实例传递给`feed`函数。

当然，动物园有很多种类的动物——`狮子`、`大象`和`三趾树懒`。有了我们对 C++继承的新知识，编写一个`Animal`类并让所有不同类型的动物从中继承将是合理的。

如果我们想要编写一个可以将狮子、大象和三趾树懒作为参数传递的函数（`feed`），似乎我们需要为每种类型的`动物`编写一个`feed`函数。然而，我们可以编写多态函数，具有多态返回类型和参数。看看这个假设的`feed`函数的定义：

```cpp
void feed(Animal& a) 
{ 
   a.decreaseHunger(); 
} 

```

前面的函数将`Animal`引用作为参数，这意味着可以将从扩展`Animal`类构建的任何对象传递给它。

因此，即使今天编写代码并在一周、一个月或一年后创建另一个子类，相同的函数和数据结构仍将起作用。此外，我们可以对子类强制执行一组规则，规定它们可以做什么，不能做什么，以及如何做。因此，一个阶段的良好设计可以影响其他阶段。

但我们真的会想要实例化一个真正的动物吗？

# 抽象类-虚函数和纯虚函数

**抽象类**是一种不能被实例化的类，因此不能成为对象。

### 提示

我们可能想在这里学习的一些术语是**具体**类。**具体类**是指任何不是抽象的类。换句话说，到目前为止我们编写的所有类都是具体类，可以实例化为可用的对象。

那么，这段代码永远不会被使用吗？但这就像支付一个建筑师设计你的房子，然后永远不建造它！

如果我们或类的设计者想要强制其用户在使用其类之前继承它，他们可以将一个类设为**抽象**。然后，我们就不能从中创建对象；因此，我们必须首先扩展它，然后从子类创建对象。

为此，我们可以使一个函数**纯虚**，并且不提供任何定义。然后，该函数必须在扩展它的任何类中**重写**（重新编写）。

让我们看一个例子；这会有所帮助。我们通过添加一个纯虚函数来使一个类成为抽象类，比如这个只能执行通用动作 makeNoise 的抽象`Animal`类：

```cpp
Class Animal 
   private: 
      // Private stuff here 

   public: 

      void virtual makeNoise() = 0; 

      // More public stuff here 
}; 

```

如您所见，我们在函数声明之前添加了 C++关键字`virtual`，并在函数声明之后添加了`= 0`。现在，任何扩展/继承自`Animal`的类都必须重写`makeNoise`函数。这可能是有道理的，因为不同类型的动物发出非常不同类型的噪音。我们可能会假设任何扩展`Animal`类的人都足够聪明，以注意到`Animal`类不能发出噪音，并且他们将需要处理它，但如果他们没有注意到呢？关键是通过制作一个纯虚函数，我们保证他们会注意到，因为他们必须。

抽象类也很有用，因为有时我们需要一个可以用作多态类型的类，但我们需要保证它永远不能被用作对象。例如，`Animal`本身并没有太多意义。我们不谈论动物；我们谈论动物的类型。我们不会说，“哦，看那只可爱的、蓬松的、白色的动物！”或者，“昨天我们去宠物店买了一只动物和一个动物床”。这太抽象了。

因此，抽象类有点像一个**模板**，可以被任何继承它的类使用。如果我们正在构建一个类似于“工业帝国”类型的游戏，玩家管理企业及其员工，我们可能需要一个`Worker`类，并将其扩展为`Miner`，`Steelworker`，`OfficeWorker`，当然还有`Programmer`。但是一个普通的`Worker`到底是做什么的？我们为什么要实例化一个？

答案是我们不想实例化一个，但我们可能想要将其用作多态类型，以便在函数之间传递多个`Worker`子类，并且具有可以容纳所有类型的工作者的数据结构。

所有纯虚函数必须被扩展父类的任何类重写。这意味着抽象类可以提供一些在其所有子类中都可用的常见功能。例如，`Worker`类可能有`m_AnnualSalary`，`m_Productivity`和`m_Age`成员变量。它可能还有`getPayCheck`函数，这不是纯虚的，在所有子类中都是相同的，但它可能有一个`doWork`函数，这是纯虚的，必须被重写，因为所有不同类型的`Worker`将以非常不同的方式`doWork`。

### 注意

顺便说一下，**virtual**，与纯虚相反，是一个可以**选择性重写**的函数。你声明一个虚函数的方式与声明纯虚函数相同，但是最后不加上`= 0`。在当前的游戏项目中，我们将使用纯虚函数。

如果这些虚拟、纯虚或抽象的东西有任何不清楚的地方，使用它可能是理解它的最好方法。

# 构建 PlayableCharacter 类

现在我们了解了继承、多态和纯虚函数的基础知识，我们将把它们应用起来。我们将构建一个`PlayableCharacter`类，该类将拥有游戏中任何角色所需的绝大部分功能。它将有一个纯虚函数`handleInput`。`handleInput`函数在子类中需要有很大的不同，所以这是有道理的。

由于`PlayableCharacter`将有一个纯虚函数，它将是一个抽象类，不可能有它的对象。然后我们将构建`Thomas`和`Bob`类，它们将继承自`PlayableCharacter`，实现纯虚函数的定义，并允许我们在游戏中实例化`Bob`和`Thomas`对象。

## 编写 PlayableCharacter.h

通常情况下，创建一个类时，我们将从包含成员变量和函数声明的头文件开始。新的是，在这个类中，我们将声明一些**protected**成员变量。记住，受保护的变量可以被继承自具有受保护变量的类的类使用，就好像它们是`Public`一样。

在**解决方案资源管理器**中右键单击**头文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，通过左键单击**头文件（** `.h` **）**，然后在**名称**字段中输入`PlayableCharacter.h`。最后，单击**添加**按钮。现在我们准备编写`PlayableCharacter`类的头文件。

我们将在三个部分添加和讨论`PlayableCharacter.h`文件的内容。首先是**protected**部分，然后是**private**，最后是**public**。

在`PlayableCharacter.h`文件中添加下面显示的代码：

```cpp
#pragma once 
#include <SFML/Graphics.hpp> 

using namespace sf; 

class PlayableCharacter 
{ 
protected: 
   // Of course we will need a sprite 
   Sprite m_Sprite; 

   // How long does a jump last 
   float m_JumpDuration; 

   // Is character currently jumping or falling 
   bool m_IsJumping; 
   bool m_IsFalling; 

   // Which directions is the character currently moving in 
   bool m_LeftPressed; 
   bool m_RightPressed; 

   // How long has this jump lasted so far 
   float m_TimeThisJump; 

   // Has the player just initialted a jump 
   bool m_JustJumped = false; 

   // Private variables and functions come next 

```

在我们刚刚编写的代码中，要注意的第一件事是所有变量都是`protected`。这意味着当我们扩展这个类时，我们刚刚编写的所有变量将对那些扩展它的类可访问。我们将用`Thomas`和`Bob`类扩展这个类。

除了`protected`访问规范之外，之前的代码没有什么新的或复杂的。然而，值得注意的是一些细节。然后随着我们的进展，理解类的工作原理将会变得容易。所以，让我们逐个运行那些`protected`变量。

我们有一个相当可预测的`Sprite`，`m_Sprite`。我们有一个名为`m_JumpDuration`的浮点数，它将保存代表角色能够跳跃的时间。数值越大，角色跳得越远/高。

接下来，我们有一个布尔值`m_IsJumping`，当角色跳跃时为`true`，否则为`false`。这将有助于确保角色在空中时不能跳跃。

`m_IsFalling`变量与`m_IsJumping`具有类似的用途。知道角色何时下落将是有用的。

接下来，我们有两个布尔值，如果角色的左键或右键当前被按下，将为 true。这些取决于角色（*A*和*D*代表 Thomas，左右箭头键代表 Bob）。我们将在`Thomas`和`Bob`类中看到如何响应这些布尔值。

`m_TimeThisJump`浮点变量在每一帧`m_IsJumping`为`true`时更新。然后我们就知道`m_JumpDuration`已经达到了。

最后一个`protected`变量是布尔值`m_JustJumped`。如果在当前帧中启动了跳跃，它将为`true`。这将有助于知道何时播放跳跃音效。

接下来，在`PlayableCharacter.h`文件中添加以下`private`变量：

```cpp
private: 
   // What is the gravity 
   float m_Gravity; 

   // How fast is the character 
   float m_Speed = 400; 

   // Where is the player 
   Vector2f m_Position; 

   // Where are the characters various body parts? 
   FloatRect m_Feet; 
   FloatRect m_Head; 
   FloatRect m_Right; 
   FloatRect m_Left; 

   // And a texture 
   Texture m_Texture; 

   // All our public functions will come next 

```

在前面的代码中，我们有一些有趣的`private`变量。请记住，这些变量只能被`PlayableCharacter`类中的代码直接访问。`Thomas`和`Bob`类将无法直接访问它们。

`m_Gravity`变量将保存角色下落的每秒像素数。`m_Speed`变量将保存角色每秒左右移动的像素数。

`Vector2f`，`m_Position`变量是角色在世界中（而不是屏幕上）的位置，即角色中心的位置。

接下来的四个`FloatRect`对象很重要。在*Zombie Arena*游戏中进行碰撞检测时，我们只是简单地检查两个`FloatRect`对象是否相交。每个`FloatRect`对象代表整个角色、拾取物或子弹。对于非矩形形状的对象（僵尸和玩家），这有点不准确。

在这个游戏中，我们需要更精确。`m_Feet`，`m_Head`，`m_Right`和`m_Left`的`FloatRect`对象将保存角色身体不同部位的坐标。这些坐标将在每一帧中更新。

通过这些坐标，我们将能够准确地知道角色何时落在平台上，跳跃时碰到头部，或者与侧面的瓷砖擦肩而过。

最后，我们有`Texture`。`Texture`是`private`的，因为它不会被`Thomas`或`Bob`类直接使用，但是，正如我们所看到的，`Sprite`是`protected`的，因为它被直接使用。

现在在`PlayableCharacter.h`文件中添加所有的`public`函数，然后我们将讨论它们：

```cpp
public: 

   void spawn(Vector2f startPosition, float gravity); 

   // This is a pure virtual function 
   bool virtual handleInput() = 0; 
   // This class is now abstract and cannot be instanciated 

   // Where is the player 
   FloatRect getPosition(); 

   // A rectangle representing the position  
   // of different parts of the sprite 
   FloatRect getFeet(); 
   FloatRect getHead(); 
   FloatRect getRight(); 
   FloatRect getLeft(); 

   // Send a copy of the sprite to main 
   Sprite getSprite(); 

   // Make the character stand firm 
   void stopFalling(float position); 
   void stopRight(float position); 
   void stopLeft(float position); 
   void stopJump(); 

   // Where is the center of the character 
   Vector2f getCenter(); 

   // We will call this function once every frame 
   void update(float elapsedTime); 

};// End of the class 

```

让我们谈谈我们刚刚添加的每个函数声明。这将使编写它们的定义更容易跟踪。

+   `spawn`函数接收一个名为`startPosition`的`Vector2f`和一个名为`gravity`的`float`。顾名思义，`startPosition`将是角色开始的关卡坐标，`gravity`将是角色下落的每秒像素数。

+   `bool virtual handleInput() = 0`当然是我们的纯虚函数。由于`PlayableCharacter`有这个函数，任何扩展它的类，如果我们想要实例化它，必须为这个函数提供一个定义。因此，当我们一会儿为`PlayableCharacter`写所有函数定义时，我们不会为`handleInput`提供定义。当然，`Thomas`和`Bob`类中也需要有定义。

+   `getPosition`函数返回一个`FloatRect`，表示整个角色的位置。

+   `getFeet()`函数，以及`getHead`，`getRight`和`getLeft`，每个都返回一个`FloatRect`，表示角色身体特定部位的位置。这正是我们需要进行详细的碰撞检测。

+   `getSprite`函数像往常一样，将`m_Sprite`的副本返回给调用代码。

+   `stopFalling`，`stopRight`，`stopLeft`和`stopJump`函数接收一个`float`值，函数将使用该值重新定位角色，并阻止其通过实心瓷砖行走或跳跃。

+   `getCenter`函数返回一个`Vector2f`给调用代码，让它准确知道角色的中心在哪里。这个值当然保存在`m_Position`中。我们将在后面看到，它被`Engine`类用来围绕适当的角色中心适当地调整`View`。

+   我们以前多次看到的`update`函数，像往常一样，它接受一个`float`参数，表示当前帧所花费的秒数的一部分。然而，这个`update`函数需要做的工作比以前的`update`函数（来自其他项目）更多。它需要处理跳跃，以及更新表示头部、脚部、左侧和右侧的`FloatRect`对象。

现在我们可以为所有函数编写定义，当然，除了`handleInput`。

## 编写 PlayableCharacter.cpp

在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，突出显示（通过左键单击）**C++文件（**`.cpp`**）**，然后在**名称**字段中键入`PlayableCharacter.cpp`。最后，单击**添加**按钮。我们现在准备好为`PlayableCharacter`类编写`.cpp`文件了。

我们将把代码和讨论分成几个部分。首先，添加包含指令和`spawn`函数的定义：

```cpp
#include "stdafx.h" 
#include "PlayableCharacter.h" 

void PlayableCharacter::spawn(Vector2f startPosition, float gravity) 
{ 
   // Place the player at the starting point 
   m_Position.x = startPosition.x; 
   m_Position.y = startPosition.y; 

   // Initialize the gravity 
   m_Gravity = gravity; 

   // Move the sprite in to position 
   m_Sprite.setPosition(m_Position); 

} 

```

`spawn`函数使用传入的位置初始化`m_Position`，并初始化`m_Gravity`。代码的最后一行将`m_Sprite`移动到其起始位置。

接下来，在上述代码之后立即添加`update`函数的定义：

```cpp
void PlayableCharacter::update(float elapsedTime) 
{ 

   if (m_RightPressed) 
   { 
      m_Position.x += m_Speed * elapsedTime; 
   } 

   if (m_LeftPressed) 
   { 
      m_Position.x -= m_Speed * elapsedTime; 
   } 

   // Handle Jumping 
   if (m_IsJumping) 
   { 
      // Update how long the jump has been going 
      m_TimeThisJump += elapsedTime; 

      // Is the jump going upwards 
      if (m_TimeThisJump < m_JumpDuration) 
      { 
         // Move up at twice gravity 
         m_Position.y -= m_Gravity * 2 * elapsedTime; 
      } 
      else 
      { 
         m_IsJumping = false; 
         m_IsFalling = true; 
      } 

   } 

   // Apply gravity 
   if (m_IsFalling) 
   { 
      m_Position.y += m_Gravity * elapsedTime; 
   } 

   // Update the rect for all body parts 
   FloatRect r = getPosition(); 

   // Feet 
   m_Feet.left = r.left + 3; 
   m_Feet.top = r.top + r.height - 1; 
   m_Feet.width = r.width - 6; 
   m_Feet.height = 1; 

   // Head 
   m_Head.left = r.left; 
   m_Head.top = r.top + (r.height * .3); 
   m_Head.width = r.width; 
   m_Head.height = 1; 

   // Right 
   m_Right.left = r.left + r.width - 2; 
   m_Right.top = r.top + r.height * .35; 
   m_Right.width = 1; 
   m_Right.height = r.height * .3; 

   // Left 
   m_Left.left = r.left; 
   m_Left.top = r.top + r.height * .5; 
   m_Left.width = 1; 
   m_Left.height = r.height * .3; 

   // Move the sprite into position 
   m_Sprite.setPosition(m_Position); 

} 

```

代码的前两部分检查`m_RightPressed`或`m_LeftPressed`是否为`true`。如果其中任何一个是，`m_Position`将使用与上一个项目相同的公式（经过的时间乘以速度）进行更改。

接下来，我们看看角色当前是否正在执行跳跃。我们从`if(m_IsJumping)`知道这一点。如果这个`if`语句为`true`，代码将执行以下步骤：

1.  使用`elapsedTime`更新`m_TimeThisJump`。

1.  检查`m_TimeThisJump`是否仍然小于`m_JumpDuration`。如果是，则通过两倍的重力乘以经过的时间更改`m_Position`的 y 坐标。

1.  在`else`子句中，当`m_TimeThisJump`不低于`m_JumpDuration`时，`m_Falling`被设置为`true`。这样做的效果将在下面看到。此外，`m_Jumping`被设置为`false`。这可以防止我们刚刚讨论的代码执行，因为`if(m_IsJumping)`现在为 false。

`if(m_IsFalling)`块在每帧移动`m_Position`向下。它使用当前的`m_Gravity`值和经过的时间进行移动。

以下代码（几乎是剩下的所有代码）更新了角色的身体部位，相对于整个精灵的当前位置。查看以下图表，了解代码如何计算角色的虚拟头部、脚部、左侧和右侧的位置：

![编写 PlayableCharacter.cpp](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_13_001.jpg)

代码的最后一行使用`setPosition`函数将精灵移动到正确的位置，以便在`update`函数的所有可能性之后。

现在立即添加`getPosition`、`getCenter`、`getFeet`、`getHead`、`getLeft`、`getRight`和`getSprite`函数的定义，紧接在上述代码之后：

```cpp
FloatRect PlayableCharacter::getPosition() 
{ 
   return m_Sprite.getGlobalBounds(); 
} 

Vector2f PlayableCharacter::getCenter() 
{ 
   return Vector2f( 
      m_Position.x + m_Sprite.getGlobalBounds().width / 2, 
      m_Position.y + m_Sprite.getGlobalBounds().height / 2 
      ); 
} 

FloatRect PlayableCharacter::getFeet() 
{ 
   return m_Feet; 
} 

FloatRect PlayableCharacter::getHead() 
{ 
   return m_Head; 
} 

FloatRect PlayableCharacter::getLeft() 
{ 
   return m_Left; 
} 

FloatRect PlayableCharacter::getRight() 
{ 
   return m_Right; 
} 

Sprite PlayableCharacter::getSprite() 
{ 
   return m_Sprite; 
} 

```

`getPosition`函数返回包装整个精灵的`FloatRect`，`getCenter`返回一个包含精灵中心的`Vector2f`。请注意，我们将精灵的高度和宽度除以 2，以便动态地得出这个结果。这是因为托马斯和鲍勃的身高不同。

`getFeet`、`getHead`、`getLeft`和`getRight`函数返回代表角色身体部位的`FloatRect`对象，我们在`update`函数中每帧更新。我们将在下一章中编写使用这些函数的**碰撞检测代码**。

`getSprite`函数像往常一样返回`m_Sprite`的副本。

最后，对于`PlayableCharacter`类，添加`stopFalling`、`stopRight`、`stopLeft`和`stopJump`函数的定义。在上一段代码之后立即执行：

```cpp
void PlayableCharacter::stopFalling(float position) 
{ 
   m_Position.y = position - getPosition().height; 
   m_Sprite.setPosition(m_Position); 
   m_IsFalling = false; 
} 

void PlayableCharacter::stopRight(float position) 
{ 

   m_Position.x = position - m_Sprite.getGlobalBounds().width; 
   m_Sprite.setPosition(m_Position); 
} 

void PlayableCharacter::stopLeft(float position) 
{ 
   m_Position.x = position + m_Sprite.getGlobalBounds().width; 
   m_Sprite.setPosition(m_Position); 
} 

void PlayableCharacter::stopJump() 
{ 
   // Stop a jump early  
   m_IsJumping = false; 
   m_IsFalling = true; 
} 

```

每个先前的函数都接收一个值作为参数，用于重新定位精灵的顶部、底部、左侧或右侧。这些值是什么以及如何获得它们将在下一章中看到。每个先前的函数还会重新定位精灵。

最后一个函数是`stopJump`函数，也将用于碰撞检测。它设置了`m_IsJumping`和`m_IsFalling`的必要值来结束跳跃。

# 构建 Thomas 和 Bob 类

现在我们要真正使用继承。我们将为 Thomas 建立一个类，为 Bob 建立一个类。它们都将继承我们刚刚编写的`PlayableCharacter`类。然后它们将拥有`PlayableCharacter`类的所有功能，包括直接访问其`protected`变量。我们还将为纯虚函数`handleInput`添加定义。您将注意到`Thomas`和`Bob`的`handleInput`函数将不同。

## 编写 Thomas.h

在**解决方案资源管理器**中右键单击**头文件**，然后选择**添加** | **新项目...**。在**添加新项目**窗口中，通过左键单击突出显示（高亮）**头文件**（`.h`），然后在**名称**字段中键入`Thomas.h`。最后，单击**添加**按钮。我们现在准备为`Thomas`类编写头文件。

现在将此代码添加到`Thomas.h`类中：

```cpp
#pragma once 
#include "PlayableCharacter.h" 

class Thomas : public PlayableCharacter 
{ 
public: 
   // A constructor specific to Thomas 
   Thomas::Thomas(); 

   // The overridden input handler for Thomas 
   bool virtual handleInput(); 

}; 

```

前面的代码非常简短。我们可以看到我们有一个构造函数，并且我们将要实现纯虚拟的`handleInput`函数，所以现在让我们来做。

## 编写 Thomas.cpp

在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加** | **新项目...**。在**添加新项目**窗口中，通过左键单击突出显示（高亮）**C++文件**（`.cpp`），然后在**名称**字段中键入`Thomas.cpp`。最后，单击**添加**按钮。我们现在准备为`Thomas`类编写`.cpp`文件。

将`Thomas`构造函数添加到`Thomas.cpp`文件中，如下面的片段所示：

```cpp
#include "stdafx.h" 
#include "Thomas.h" 
#include "TextureHolder.h" 

Thomas::Thomas() 
{ 
   // Associate a texture with the sprite 
   m_Sprite = Sprite(TextureHolder::GetTexture( 
      "graphics/thomas.png")); 

   m_JumpDuration = .45; 
} 

```

我们只需要加载`thomas.png`图形并将跳跃的持续时间（`m_JumpDuration`）设置为`.45`（几乎半秒）。

添加`handleInput`函数的定义，如下面的片段所示：

```cpp

// A virtual function 
bool Thomas::handleInput() 
{ 
   m_JustJumped = false; 

   if (Keyboard::isKeyPressed(Keyboard::W)) 
   { 

      // Start a jump if not already jumping 
      // but only if standing on a block (not falling) 
      if (!m_IsJumping && !m_IsFalling) 
      { 
         m_IsJumping = true; 
         m_TimeThisJump = 0; 
         m_JustJumped = true; 
      } 
   } 
   else 
   { 
      m_IsJumping = false; 
      m_IsFalling = true; 

   } 
   if (Keyboard::isKeyPressed(Keyboard::A)) 
   { 
      m_LeftPressed = true; 
   } 
   else 
   { 
      m_LeftPressed = false; 
   } 

   if (Keyboard::isKeyPressed(Keyboard::D)) 
   { 
      m_RightPressed = true; 
   } 
   else 
   { 
      m_RightPressed = false; 
   } 

   return m_JustJumped; 
} 

```

这段代码应该看起来很熟悉。我们正在使用 SFML 的`isKeyPressed`函数来查看*W，A*或*D*键是否被按下。

当按下*W*键时，玩家正在尝试跳跃。然后代码使用`if(!m_IsJumping && !m_IsFalling)`代码，检查角色是否已经在跳跃，而且也不在下落。当这些测试都为真时，`m_IsJumping`设置为`true`，`m_TimeThisJump`设置为零，并且`m_JustJumped`设置为`true`。

当前两个测试不为`true`时，将执行`else`子句，并将`m_Jumping`设置为`false`，`m_IsFalling`设置为`true`。

处理按下*A*和*D*键的操作就是简单地将`m_LeftPressed`和/或`m_RightPressed`设置为`true`或`false`。`update`函数现在将能够处理移动角色。

函数中的最后一行代码返回`m_JustJumped`的值。这将让调用代码知道是否需要播放跳跃音效。

现在我们将编写`Bob`类，尽管这几乎与`Thomas`类相同，除了具有不同的跳跃能力，不同的`Texture`，并且在键盘上使用不同的键。

## 编写 Bob.h

`Bob`类在结构上与`Thomas`类相同。它继承自`PlayableCharacter`，有一个构造函数，并提供了`handleInput`函数的定义。与`Thomas`相比的区别是，我们以不同的方式初始化了一些 Bob 的成员变量，并且我们也以不同的方式处理输入（在`handleInput`函数中）。让我们编写这个类并查看细节。

在**解决方案资源管理器**中右键单击**头文件**，然后选择**添加** | **新项目...**。在**添加新项目**窗口中，通过左键单击突出显示（高亮）**头文件（** `.h` **）**，然后在**名称**字段中键入`Bob.h`。最后，单击**添加**按钮。我们现在准备为`Bob`类编写头文件。

将以下代码添加到`Bob.h`文件中：

```cpp
#pragma once 
#include "PlayableCharacter.h" 

class Bob : public PlayableCharacter 
{ 
public: 
   // A constructor specific to Bob 
   Bob::Bob(); 

   // The overriden input handler for Bob 
   bool virtual handleInput(); 

}; 

```

前面的代码与`Thomas.h`文件相同，除了类名和构造函数名。

## 编写 Bob.cpp

在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，通过左键单击**C++文件（** `.cpp` **）**，然后在**名称**字段中键入`Thomas.cpp`。最后，单击**添加**按钮。现在我们已经准备好为`Bob`类编写`.cpp`文件。

将`Bob`构造函数的代码添加到`Bob.cpp`文件中。请注意，纹理不同（`bob.png`），并且`m_JumpDuration`初始化为一个明显较小的值。Bob 现在是他自己独特的自己：

```cpp
#include "stdafx.h" 
#include "Bob.h" 
#include "TextureHolder.h" 

Bob::Bob() 
{ 
   // Associate a texture with the sprite 
   m_Sprite = Sprite(TextureHolder::GetTexture( 
      "graphics/bob.png")); 

   m_JumpDuration = .25; 
} 

```

在`Bob`构造函数之后立即添加`handleInput`代码：

```cpp
bool Bob::handleInput() 
{ 
   m_JustJumped = false; 

   if (Keyboard::isKeyPressed(Keyboard::Up)) 
   { 

      // Start a jump if not already jumping 
      // but only if standing on a block (not falling) 
      if (!m_IsJumping && !m_IsFalling) 
      { 
         m_IsJumping = true; 
         m_TimeThisJump = 0; 
         m_JustJumped = true; 
      } 

   } 
   else 
   { 
      m_IsJumping = false; 
      m_IsFalling = true; 

   } 
   if (Keyboard::isKeyPressed(Keyboard::Left)) 
   { 
      m_LeftPressed = true; 

   } 
   else 
   { 
      m_LeftPressed = false; 
   } 

   if (Keyboard::isKeyPressed(Keyboard::Right)) 
   { 

      m_RightPressed = true;; 

   } 
   else 
   { 
      m_RightPressed = false; 
   } 

   return m_JustJumped; 
} 

```

请注意，这段代码几乎与`Thomas`类的`handleInput`函数中的代码相同。唯一的区别是我们对不同的按键做出响应（**左**箭头键，**右**箭头键和**上**箭头键用于跳跃）。

现在我们有了一个通过`Bob`和`Thomas`扩展的`PlayableCharacter`类，我们可以在游戏中添加一个`Bob`和一个`Thomas`实例。

# 更新游戏引擎以使用 Thomas 和 Bob

为了能够运行游戏并看到我们的新角色，我们必须声明它们的实例，调用它们的`spawn`函数，每帧更新它们，并每帧绘制它们。现在让我们来做这些。

## 更新 Engine.h 以添加 Bob 和 Thomas 的实例

打开`Engine.h`文件，并添加下面显示的代码行：

```cpp
#pragma once 
#include <SFML/Graphics.hpp> 
#include "TextureHolder.h" 
#include "Thomas.h"
#include "Bob.h" 

using namespace sf; 

class Engine 
{ 
private: 
   // The texture holder 
   TextureHolder th; 

 // Thomas and his friend, Bob
   Thomas m_Thomas;
   Bob m_Bob; 

   const int TILE_SIZE = 50; 
   const int VERTS_IN_QUAD = 4; 
   ... 
   ... 

```

现在我们有了`Thomas`和`Bob`的实例，它们都是从`PlayableCharacter`派生出来的。

## 更新 input 函数以控制 Thomas 和 Bob

现在我们将添加控制这两个角色的能力。这段代码将放在代码的输入部分。当然，对于这个项目，我们有一个专门的`input`函数。打开`Input.cpp`并添加这段突出显示的代码：

```cpp
void Engine::input() 
{ 
   Event event; 
   while (m_Window.pollEvent(event)) 
   { 
      if (event.type == Event::KeyPressed) 
      { 
         // Handle the player quitting 
         if (Keyboard::isKeyPressed(Keyboard::Escape)) 
         { 
            m_Window.close(); 
         } 

         // Handle the player starting the game 
         if (Keyboard::isKeyPressed(Keyboard::Return)) 
         { 
            m_Playing = true; 
         } 

         // Switch between Thomas and Bob 
         if (Keyboard::isKeyPressed(Keyboard::Q)) 
         { 
            m_Character1 = !m_Character1; 
         } 

         // Switch between full and split-screen 
         if (Keyboard::isKeyPressed(Keyboard::E)) 
         { 
            m_SplitScreen = !m_SplitScreen; 
         } 
      } 
   } 

 // Handle input specific to Thomas
   if(m_Thomas.handleInput())
   {
     // Play a jump sound
   }

   // Handle input specific to Bob
   if(m_Bob.handleInput())
   {
     // Play a jump sound
   } 
} 

```

请注意，以前的代码是多么简单，因为所有的功能都包含在`Thomas`和`Bob`类中。代码只需要为`Thomas`和`Bob`类中的每一个添加一个包含指令。然后，在`input`函数中，代码只是调用`m_Thomas`和`m_Bob`上的纯虚拟`handleInput`函数。我们将在第十五章中处理播放跳跃音效，*声音空间化和 HUD*。

## 更新 update 函数以生成和更新 PlayableCharacter 实例

这可以分为两部分。首先，我们需要在新关卡开始时生成 Bob 和 Thomas，其次，我们需要每帧更新（通过调用它们的`update`函数）。

### 生成 Thomas 和 Bob

随着项目的进展，我们需要在几个不同的地方调用我们的`Thomas`和`Bob`对象的生成函数。最明显的是，当一个新的关卡开始时，我们需要生成这两个角色。在接下来的章节中，随着在关卡开始时需要执行的任务数量增加，我们将编写一个`loadLevel`函数。现在，让我们在`update`函数中调用`m_Thomas`和`m_Bob`的`spawn`，如下所示的突出显示的代码。添加这段代码，但请记住，这段代码最终将被删除和替换：

```cpp
void Engine::update(float dtAsSeconds) 
{ 
 if (m_NewLevelRequired)
   {
     // These calls to spawn will be moved to a new
     // loadLevel() function soon
     // Spawn Thomas and Bob
     m_Thomas.spawn(Vector2f(0,0), GRAVITY);
     m_Bob.spawn(Vector2f(100, 0), GRAVITY); 

     // Make sure spawn is called only once
     m_TimeRemaining = 10;
     m_NewLevelRequired = false;
   } 

   if (m_Playing) 
   { 
      // Count down the time the player has left 
      m_TimeRemaining -= dtAsSeconds; 

      // Have Thomas and Bob run out of time? 
      if (m_TimeRemaining <= 0) 
      { 
         m_NewLevelRequired = true; 
      } 

   }// End if playing 

} 

```

以前的代码只是调用`spawn`并传入游戏世界中的位置以及重力。代码包裹在一个`if`语句中，检查是否需要新的关卡。实际的生成代码将被移动到一个专门的`loadLevel`函数中，但`if`条件将成为完成项目的一部分。此外，`m_TimeRemaining`被设置为一个相当任意的 10 秒。

### 每帧更新 Thomas 和 Bob

接下来，我们将更新 Thomas 和 Bob。我们需要做的就是调用它们的`update`函数，并传入这一帧所花费的时间。

添加下面突出显示的代码：

```cpp
void Engine::update(float dtAsSeconds) 
{ 
   if (m_NewLevelRequired) 
   { 
      // These calls to spawn will be moved to a new 
      // LoadLevel function soon 
      // Spawn Thomas and Bob 
      m_Thomas.spawn(Vector2f(0,0), GRAVITY); 
      m_Bob.spawn(Vector2f(100, 0), GRAVITY); 

      // Make sure spawn is called only once 
      m_NewLevelRequired = false; 
   } 

   if (m_Playing) 
   { 
 // Update Thomas
      m_Thomas.update(dtAsSeconds);

      // Update Bob
      m_Bob.update(dtAsSeconds); 

      // Count down the time the player has left 
      m_TimeRemaining -= dtAsSeconds; 

      // Have Thomas and Bob run out of time? 
      if (m_TimeRemaining <= 0) 
      { 
         m_NewLevelRequired = true; 
      } 

   }// End if playing 

} 

```

现在角色可以移动了，我们需要更新适当的`View`对象，使它们围绕角色居中，并使它们成为关注的中心。当然，直到我们在游戏世界中有一些物体，才能实现实际运动的感觉。

请按照以下片段所示添加突出显示的代码：

```cpp
void Engine::update(float dtAsSeconds) 
{ 
   if (m_NewLevelRequired) 
   { 
      // These calls to spawn will be moved to a new 
      // LoadLevel function soon 
      // Spawn Thomas and Bob 
      m_Thomas.spawn(Vector2f(0,0), GRAVITY); 
      m_Bob.spawn(Vector2f(100, 0), GRAVITY); 

      // Make sure spawn is called only once 
      m_NewLevelRequired = false; 
   } 

   if (m_Playing) 
   { 
      // Update Thomas 
      m_Thomas.update(dtAsSeconds); 

      // Update Bob 
      m_Bob.update(dtAsSeconds); 

      // Count down the time the player has left 
      m_TimeRemaining -= dtAsSeconds; 

      // Have Thomas and Bob run out of time? 
      if (m_TimeRemaining <= 0) 
      { 
         m_NewLevelRequired = true; 
      } 

   }// End if playing 

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
} 

```

先前的代码处理了两种可能的情况。首先，`if(mSplitScreen)`条件将左侧视图定位在`m_Thomas`周围，右侧视图定位在`m_Bob`周围。当游戏处于全屏模式时执行的`else`子句测试`m_Character1`是否为`true`。如果是，则全屏视图（`m_MainView`）围绕托马斯居中，否则围绕鲍勃居中。您可能还记得玩家可以使用*E*键在分屏模式和全屏模式之间切换，使用*Q*键在全屏模式下切换 Bob 和 Thomas。我们在`Engine`类的`input`函数中编写了这个代码，回到第十二章，*抽象和代码管理-更好地利用 OOP*。

## 绘制鲍勃和托马斯

确保`Draw.cpp`文件已打开，并添加如下突出显示的代码，如下片段所示：

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

 // Draw thomas
     m_Window.draw(m_Thomas.getSprite());

     // Draw bob
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

 // Draw bob
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

请注意，我们在全屏模式下绘制了托马斯和鲍勃的全屏，左侧和右侧。还要注意，在分屏模式下绘制角色的方式有非常微妙的差异。在绘制屏幕的左侧时，我们切换了绘制角色的顺序，并在鲍勃之后绘制了托马斯。因此，托马斯将始终位于左侧的顶部，鲍勃位于右侧。这是因为左侧为托马斯控制的玩家，右侧为鲍勃控制的玩家。

您可以运行游戏，看到托马斯和鲍勃在屏幕中央：

![绘制鲍勃和托马斯](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_13_002.jpg)

如果您按*Q*键从托马斯切换焦点到鲍勃，您将看到`View`进行轻微调整。如果您移动其中一个角色向左或向右（托马斯使用*A*和*D*，鲍勃使用箭头键），您将看到它们相对于彼此移动。

尝试按*E*键在全屏和分屏之间切换。然后再次尝试移动两个角色以查看效果。在下面的截图中，您可以看到托马斯始终位于左侧窗口的中心，鲍勃始终位于右侧窗口的中心：

![绘制鲍勃和托马斯](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_13_003.jpg)

如果您让游戏运行足够长的时间，角色将每十秒重新生成在它们的原始位置。这是我们在完成游戏时需要的功能的开端。这种行为是由`m_TimeRemaining`下降到零以下，然后将`m_NewLevelRequired`变量设置为`true`引起的。

还要注意的是，直到我们绘制了层级的细节，我们才能看到移动的完整效果。实际上，虽然看不到，但两个角色都在以每秒 300 像素的速度持续下落。由于摄像头每帧都围绕它们居中，并且游戏世界中没有其他物体，我们看不到这种向下运动。

如果您想自己演示一下，请按照以下代码更改对`m_Bob.spawn`的调用：

```cpp
m_Bob.spawn(Vector2f(0,0), 0); 

```

现在鲍勃没有重力效应，托马斯将明显远离他。如下截图所示：

![绘制鲍勃和托马斯](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-gm-prog/img/image_13_004.jpg)

我们将在下一章中添加一些可玩的关卡以进行交互。

# 常见问题解答

Q）我们学习了多态性，但到目前为止，我没有注意到游戏代码中有任何多态性。

A）我们将在下一章中看到多态性的作用，当我们编写一个以`PlayableCharacter`作为参数的函数时。我们将看到如何将 Bob 或 Thomas 传递给这个新函数，并且它们将以相同的方式工作。

# 摘要

在这一章中，我们学习了一些新的 C++概念。首先，继承允许我们扩展一个类并获得其所有功能。我们还学到，我们可以将变量声明为受保护的，这将使子类可以访问它们，但它们仍然会被封装（隐藏）在所有其他代码之外。我们还使用了纯虚函数，这使得一个类成为抽象类，意味着该类不能被实例化，因此必须从中继承/扩展。我们还介绍了多态的概念，但需要等到下一章才能在我们的游戏中使用它。

接下来，我们将为游戏添加一些重要功能。在接下来的一章中，Thomas 和 Bob 将会行走、跳跃和下落。他们甚至可以跳在彼此的头上，以及探索一些从文本文件加载的关卡设计。
