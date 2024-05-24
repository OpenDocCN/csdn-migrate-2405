# C++ 编程入门指南（六）

> 原文：[`annas-archive.org/md5/024671a6ef06ea57693023eca62b8eea`](https://annas-archive.org/md5/024671a6ef06ea57693023eca62b8eea)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：音效，文件 I/O 和完成游戏

我们快要完成了。这一小节将演示如何使用 C++标准库轻松操作存储在硬盘上的文件，我们还将添加音效。当然，我们知道如何添加音效，但我们将讨论在代码中`play`的调用应该放在哪里。我们还将解决一些问题，使游戏更完整。

在本章中，我们将学习以下主题：

+   保存和加载最高分

+   添加音效

+   允许玩家升级

+   创建无尽的多波

# 保存和加载最高分

文件 I/O，即输入/输出，是一个相当技术性的主题。幸运的是，由于它在编程中是一个如此常见的需求，有一个库可以处理所有复杂性。与我们为 HUD 连接字符串一样，**标准库**通过`fstream`提供了必要的功能。

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

现在，在`ZombieArena/ZombieArena`文件夹中添加一个名为`gamedata`的新文件夹。接下来，在此文件夹中右键单击并创建一个名为`scores.txt`的新文件。在这个文件中，我们将保存玩家的最高分。您可以打开文件并向其中添加分数。如果您这样做，请确保它是一个相当低的分数，这样我们就可以很容易地测试是否击败该分数会导致新分数被添加。确保在完成后关闭文件，否则游戏将无法访问它。

在下一段代码中，我们创建一个名为`InputFile`的`ifstream`对象，并将刚刚创建的文件夹和文件作为参数发送到它的构造函数。

`if(InputFile.is_open())`代码检查文件是否存在并准备好从中读取。然后我们将文件的内容放入`hiScore`中，并关闭文件。添加突出显示的代码：

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

现在我们处理保存可能的新高分。在处理玩家生命值小于或等于零的代码块中，我们创建一个名为`outputFile`的`ofstream`对象，将`hiScore`的值写入文本文件，然后关闭文件：

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

首先添加所需的 SFML 包括：

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

现在继续添加七个`SoundBuffer`和`Sound`对象，它们加载和准备了我们在第六章中准备的七个音频文件：*面向对象编程，类和 SFML 视图*：

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

现在七种音效已经准备好播放。我们只需要弄清楚在我们的代码中每个`play`函数的调用将放在哪里。

# 升级

接下来我们要添加的代码使玩家可以在波之间升级。由于我们已经做过的工作，这是很容易实现的。

在`LEVELING_UP`状态中添加突出显示的代码，我们处理玩家输入：

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

玩家现在可以在清除一波僵尸时升级。但是，我们目前还不能增加僵尸的数量或级别的大小。

在`LEVELING_UP`状态的下一部分，在我们刚刚添加的代码之后，修改当状态从`LEVELING_UP`变为`PLAYING`时运行的代码。

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

前面的代码首先递增`wave`变量。然后修改代码，使僵尸的数量和竞技场的大小与`wave`的新值相关。最后，我们添加了`powerup.play()`的调用，以播放升级音效。

# 重新开始游戏

我们已经通过`wave`变量的值确定了竞技场的大小和僵尸的数量。我们还必须在每次新游戏开始时将弹药、枪支、`wave`和`score`重置为零。在游戏循环的事件处理部分中找到以下代码，并添加突出显示的代码：

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

现在我们可以玩游戏了，玩家可以变得更加强大，僵尸在不断增加的竞技场中也会变得更加众多，直到他死亡，然后一切重新开始。

# 播放其余的声音

现在我们将添加对`play`函数的其余调用。我们会分别处理它们，因为准确确定它们的位置对于在正确时刻播放它们至关重要。

## 在玩家重新加载时添加音效

在玩家按下***R***键尝试重新加载枪支时，在三个地方添加突出显示的代码以播放适当的`reload`或`reloadFailed`声音：

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

## 制作射击声音

在处理玩家点击鼠标左键的代码的末尾附近添加对`shoot.play()`的突出调用：

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

## 玩家被击中时播放声音

在下面的代码中，我们将对`hit.play`的调用包装在一个测试中，以查看`player.hit`函数是否返回`true`。请记住，`player.hit`函数用于测试前 100 毫秒内是否记录了击中。这将导致播放一个快速、重复的、沉闷的声音，但不会太快以至于声音模糊成一个噪音。

按照突出显示的方式添加对`hit.play`的调用：

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

## 获得拾取时播放声音

当玩家拾取生命值时，我们将播放常规的拾取声音，但当玩家获得弹药时，我们会播放重新加载的音效。

在适当的碰撞检测代码中，按照突出显示的方式添加两个播放声音的调用：

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

## 射中僵尸时制作尖啸声

在检测子弹与僵尸碰撞的代码部分的末尾添加对`splat.play`的调用：

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

现在你可以玩完整的游戏，并观察每一波僵尸和竞技场的数量增加。谨慎选择你的升级：

![射中僵尸时制作尖啸声](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_11_001.jpg)

恭喜！

# 常见问题解答

以下是一些可能会让你在意的问题：

Q)尽管使用了类，我发现代码变得非常冗长和难以管理，再次出现了这个问题。

A)最大的问题之一是我们的代码结构。随着我们学习更多的 C++，我们还将学习如何使代码更易管理，通常更短。

Q)声音效果似乎有点单调和不真实。如何改进它们？

A)显著改善玩家从声音中获得的感觉的一种方法是使声音具有方向性，并根据声源到玩家角色的距离改变音量。在下一个项目中，我们将使用 SFML 的高级声音功能。

# 摘要

我们已经完成了僵尸竞技场游戏。这是一段相当艰难的旅程。我们学到了许多 C++基础知识，比如引用、指针、面向对象编程和类。此外，我们还使用 SFML 来管理摄像机、顶点数组和碰撞检测。我们学会了如何使用精灵表来减少对`window.draw`的调用次数并提高帧率。使用 C++指针、STL 和一点面向对象编程，我们构建了一个单例类来管理我们的纹理，在下一个项目中，我们将扩展这个想法来管理我们游戏的所有资源。

在书的结束项目中，我们将发现粒子效果、定向声音和分屏多人游戏。在 C++中，我们还将遇到继承、多态性以及一些新概念。


# 第十二章：抽象和代码管理——更好地利用 OOP

在本章中，我们将首次查看本书的最终项目。该项目将具有高级功能，如方向性声音，根据玩家位置从扬声器发出。它还将具有分屏合作游戏。此外，该项目将引入**着色器**的概念，这是用另一种语言编写的程序，直接在图形卡上运行。到第十六章结束时，您将拥有一个完全功能的多人平台游戏，以命中经典**Thomas Was Alone**的风格构建。

本章的主要重点将是启动项目，特别是探讨如何构建代码以更好地利用 OOP。将涵盖以下主题：

+   介绍最终项目**Thomas Was Late**，包括游戏特点和项目资产

+   与以前的项目相比，我们将讨论如何改进代码结构

+   编写 Thomas Was Late 游戏引擎

+   实现分屏功能

# Thomas Was Late 游戏

此时，如果您还没有，我建议您去观看 Thomas Was Alone 的视频[`store.steampowered.com/app/220780/`](http://store.steampowered.com/app/220780/)。请注意其简单但美观的图形。视频还展示了各种游戏挑战，例如使用角色的不同属性（高度、跳跃、力量等）。为了保持我们的游戏简单而不失挑战，我们将比 Thomas Was Alone 少一些谜题特色，但将增加两名玩家合作游戏的挑战。为了确保游戏不会太容易，我们还将让玩家与时间赛跑，这就是我们的游戏名为 Thomas Was Late 的原因。

## Thomas Was Late 的特点

我们的游戏不会像我们试图模仿的杰作那样先进，但它将具有一系列令人兴奋的游戏特色：

+   一个从与关卡挑战相适应的时间开始倒计时的时钟。

+   发射火坑会根据玩家位置发出咆哮声，并在玩家掉下去时重新开始。水坑也有相同的效果，但没有方向性声音效果。

+   合作游戏——两名玩家必须在规定时间内将他们的角色带到目标处。他们经常需要合作，例如身材较矮、跳跃较低的 Bob 需要站在他朋友（Thomas）的头上。

+   玩家将有选择在全屏和分屏之间切换，这样他可以尝试自己控制两个角色。

+   每个关卡将设计并从文本文件中加载。这将使设计各种各样的关卡变得非常容易。

看一下游戏的注释截图，看看一些功能的运行和组件/资产组成游戏：

![Thomas Was Late 的特点](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/B05523_12_01.jpg)

让我们看看这些特点，并描述一些更多的特点：

+   截图显示了一个简单的 HUD，详细说明了关卡编号和玩家失败并重新开始关卡之前剩余的秒数。

+   您还可以清楚地看到分屏合作游戏的运行情况。请记住这是可选的。单人可以全屏玩游戏，同时在 Thomas 和 Bob 之间切换摄像头焦点。

+   在截图中并不太清楚（尤其是在打印品中），但当角色死亡时，他将爆炸成星花/烟火般的粒子效果。

+   水和火砖可以被策略性地放置，使关卡变得有趣，并迫使角色之间合作。更多内容请参阅第十四章, *构建可玩关卡和碰撞检测*。

+   注意托马斯和鲍勃——他们不仅身高不同，而且跳跃能力也有很大差异。这意味着鲍勃依赖于托马斯进行大跳跃，关卡可以设计成迫使托马斯选择避免碰头的路线。

+   此外，火砖将发出隆隆的声音。这些声音将与托马斯的位置相关。它们不仅是定向的，而且会从左侧或右侧扬声器发出，随着托马斯靠近或远离源头，声音会变得越来越大或越来越小。

+   最后，在带注释的截图中，您可以看到背景。如果您将其与`background.png`文件（本章后面显示）进行比较，您会发现它们是完全不同的。我们将在第十六章, *扩展 SFML 类、粒子系统和着色器*中使用 OpenGL 着色器效果来实现背景中移动的——几乎是冒泡的——效果。

所有这些特点都值得再多拍几张截图，这样我们在编写 C++代码时可以记住最终成品。

以下截图显示了托马斯和鲍勃到达一个火坑，鲍勃没有机会跳过去：

![《托马斯迟到的特点》](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_12_002.jpg)

以下截图显示了鲍勃和托马斯合作清除一个危险的跳跃：

![《托马斯迟到的特点》](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_12_003.jpg)

以下截图显示了我们如何设计需要“信仰之跃”才能达到目标的谜题：

![《托马斯迟到的特点》](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_12_004.jpg)

以下截图演示了我们如何设计几乎任何大小的压抑洞穴系统。我们还可以设计需要鲍勃和托马斯分开并走不同路线的关卡：

![《托马斯迟到的特点》](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_12_005.jpg)

## 从模板创建项目

创建《托马斯迟到》项目与其他两个项目相同。只需在 Visual Studio 中按照以下简单步骤进行操作：

1.  从主菜单中选择**文件** | **新建项目**。

1.  确保在左侧菜单中选择了**Visual C++**，然后从所呈现的选项列表中选择**HelloSFML**。以下截图应该能清楚地说明这一点：![从模板创建项目](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_12_006.jpg)

1.  在**名称：**字段中，键入`TWL`，并确保选中**为解决方案创建目录**选项。现在点击**确定**。

1.  现在我们需要将 SFML 的`.dll`文件复制到主项目目录中。我的主项目目录是`D:\Visual Studio Stuff\Projects\ TWL\TWL`。这个文件夹是在上一步中由 Visual Studio 创建的。如果您将`Projects`文件夹放在其他地方，请在那里执行此步骤。我们需要复制到`project`文件夹中的文件位于您的`SFML\bin`文件夹中。为每个位置打开一个窗口，并突出显示所需的`.dll`文件。

1.  现在将突出显示的文件复制并粘贴到项目中。

项目现在已经设置好，准备就绪。

## 项目资产

该项目的资产比僵尸竞技场游戏的资产更多样化和丰富。通常情况下，资产包括屏幕上的文字字体、不同动作的声音效果（如跳跃、达到目标或远处火焰的咆哮）以及托马斯和鲍勃的图形以及所有背景瓷砖的精灵表。

游戏所需的所有资产都包含在下载包中。它们分别位于`第十二章/graphics`和`第十二章/sound`文件夹中。

所需的字体没有提供。这是因为我想避免任何可能的许可歧义。不过这不会造成问题，因为我会准确地告诉你在哪里以及如何为自己选择和下载字体。

虽然我会提供资产本身或者获取它们的信息，但你可能想要自己创建和获取它们。

除了我们期望的图形、声音和字体之外，这款游戏还有两种新的资产类型。它们是关卡设计文件和 GLSL 着色器程序。让我们接下来了解一下它们各自的情况。

### 游戏关卡设计

所有的关卡都是在一个文本文件中创建的。通过使用数字 0 到 3，我们可以构建挑战玩家的关卡设计。所有的关卡设计都在 levels 文件夹中，与其他资产在同一个目录中。现在可以随意偷看一下，但我们将在第十四章《构建可玩关卡和碰撞检测》中详细讨论它们。

除了这些关卡设计资产，我们还有一种特殊类型的图形资产，称为着色器。

### GLSL 着色器

着色器是用**GLSL**（图形库着色语言）编写的程序。不用担心必须学习另一种语言，因为我们不需要深入学习就能利用着色器。着色器很特殊，因为它们是完整的程序，与我们的 C++代码分开，由 GPU 每一帧执行。事实上，一些着色器程序每一帧都会运行，对于每一个像素！我们将在第十六章《扩展 SFML 类、粒子系统和着色器》中了解更多细节。如果你等不及，可以看一下下载包的`Chapter 12/shaders`文件夹中的文件。

### 图形资产的近距离

游戏的场景由图形资产组成。看一下图形资产，就可以清楚地知道它们在游戏中将被用在哪里：

图形资产的近距离

如果`tiles_sheet`图形上的瓷砖看起来和游戏截图中的有些不同，这是因为它们部分透明，透过的背景会使它们有些变化。如果背景图看起来和游戏截图中的实际背景完全不同，那是因为我们将编写的着色器程序将操纵每一个像素，每一帧，以创建一种"熔岩"效果。

### 声音资产的近距离

声音文件都是`.wav`格式。这些文件包含了我们在游戏中特定事件中播放的声音效果。它们如下：

+   `fallinfire.wav`：当玩家的头进入火焰并且玩家没有逃脱的机会时，会播放这个声音。

+   `fallinwater.wav`：水和火有相同的效果：死亡。这个声音效果通知玩家他们需要从关卡的开始处重新开始。

+   `fire1.wav`：这个声音效果是单声道录制的。它将根据玩家距离火砖的距离和不同的扬声器播放不同的音量，根据玩家是在火砖的左侧还是右侧播放。显然，我们需要学习一些更多的技巧来实现这个功能。

+   `jump.wav`：当玩家跳跃时，会发出一种愉悦（略显可预测）的欢呼声。

+   `reachgoal.wav`：当玩家（或玩家们）将两个角色（Thomas 和 Bob）都带到目标砖时，会发出一种愉悦的胜利声音。

声音效果非常简单，你可以很容易地创建自己的声音。如果你打算替换`fire1.wav`文件，请确保将你的声音保存为单声道（而不是立体声）格式。这个原因将在第十五章《声音空间化和 HUD》中解释。

### 将资产添加到项目中

一旦您决定使用哪些资产，就该将它们添加到项目中了。以下说明将假定您使用了书籍下载包中提供的所有资产。

如果您使用自己的资产，只需用您选择的文件替换相应的声音或图形文件，文件名完全相同即可：

1.  浏览到 Visual `D:\Visual Studio Stuff\Projects\TWL\TWL`目录。

1.  在此文件夹中创建五个新文件夹，并将它们命名为`graphics`、`sound`、`fonts`、`shaders`和`levels`。

1.  从下载包中，将`第十二章/图形`文件夹中的所有内容复制到`D:\Visual Studio Stuff\Projects\TWL\TWL\graphics`文件夹中。

1.  从下载包中，将`第十二章/声音`文件夹中的所有内容复制到`D:\Visual Studio Stuff\Projects\TWL\TWL\sound`文件夹中。

1.  现在在您的网络浏览器中访问[`www.dafont.com/roboto.font`](http://www.dafont.com/roboto.font)，并下载**Roboto Light**字体。

1.  解压缩下载的内容，并将`Roboto-Light.ttf`文件添加到`D:\Visual Studio Stuff\Projects\TWL\TWL\fonts`文件夹中。

1.  从下载包中，将`第十二章/关卡`文件夹中的所有内容复制到`D:\Visual Studio Stuff\Projects\TWL\TWL\levels`文件夹中。

1.  从下载包中，将`第十二章/着色器`文件夹中的所有内容复制到`D:\Visual Studio Stuff\Projects\TWL\TWL\shaders`文件夹中。

现在我们有了一个新项目，以及整个项目所需的所有资产，我们可以讨论如何构建游戏引擎代码。

# 结构化 Thomas Was Late 代码

到目前为止，两个项目中都存在一个问题，那就是代码变得越来越长和难以控制。面向对象编程允许我们将项目分解为称为类的逻辑和可管理的块。

通过引入**Engine 类**，我们将在这个项目中大大改善代码的可管理性。除其他功能外，Engine 类将有三个私有函数。它们是`input`、`update`和`draw`。这应该听起来很熟悉。这些函数中的每一个将包含以前全部在`main`函数中的代码块。这些函数将分别在自己的代码文件中，`Input.cpp`、`Update.cpp`和`Draw.cpp`中。

`Engine`类中还将有一个公共函数，可以使用`Engine`的实例调用。这个函数是`run`，将负责调用`input`、`update`和`draw`，每帧游戏调用一次：

![结构化 Thomas Was Late 代码](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_12_008.jpg)

此外，由于我们已经将游戏引擎的主要部分抽象到了`Engine`类中，我们还可以将`main`中的许多变量移到`Engine`的成员中。我们只需要创建一个`Engine`的实例并调用它的`run`函数，就可以启动我们的游戏引擎。以下是一个简单的`main`函数的预览：

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

暂时不要添加前面的代码。

为了使我们的代码更易于管理和阅读，我们还将抽象出一些大任务的责任，例如加载关卡和碰撞检测，放到单独的函数中（在单独的代码文件中）。这两个函数是`loadLevel`和`detectCollisions`。我们还将编写其他函数来处理 Thomas Was Late 项目的一些新功能。我们将在出现时详细介绍它们。

为了更好地利用面向对象编程，我们将完全将游戏特定领域的责任委托给新的类。您可能还记得以前项目中的声音和 HUD 代码非常冗长。我们将构建`SoundManager`和`HUD`类来更清晰地处理这些方面。当我们实现它们时，将深入探讨它们的工作原理。

游戏关卡本身比以前的游戏更加深入，因此我们还将编写一个`LevelManager`类。

正如您所期望的，可玩角色也将使用类制作。但是，对于这个项目，我们将学习更多的 C++并实现一个`PlayableCharacter`类，其中包含 Thomas 和 Bob 的所有常见功能，然后`Thomas`和`Bob`类，它们将继承这些常见功能，并实现自己的独特功能和能力。这可能并不奇怪，被称为**继承**。我将在接下来的第十三章，“高级面向对象编程，继承和多态”中更详细地介绍继承。

我们还将实现一些其他类来执行特定的职责。例如，我们将使用粒子系统制作一些漂亮的爆炸效果。您可能能够猜到，为了做到这一点，我们将编写一个`Particle`类和一个`ParticleSystem`类。所有这些类都将作为`Engine`类的成员实例。以这种方式做事将使游戏的所有功能都可以从游戏引擎中访问，但将细节封装到适当的类中。

在我们继续查看将创建引擎类的实际代码之前，要提到的最后一件事是，我们将重用在僵尸竞技场游戏中讨论和编写的`TextureHolder`类，而且不会有任何改变。

# 构建游戏引擎

如前面讨论所建议的，我们将编写一个名为`Engine`的类，它将控制并绑定 Thomas Was Late 游戏的不同部分。

我们要做的第一件事是使上一个项目中的`TextureHolder`类在这个项目中可用。

## 重用 TextureHolder 类

我们讨论并为僵尸竞技场游戏编写的`TextureHolder`类在这个项目中也会很有用。虽然可以直接从上一个项目添加文件（`TextureHolder.h`和`TextureHolder.cpp`）而不需要重新编码或重新创建文件，但我不想假设你没有直接跳到这个项目。接下来是非常简要的说明，以及创建`TextureHolder`类的完整代码清单。如果您想要解释这个类或代码，请参阅第八章，“指针、标准模板库和纹理管理”。

### 提示

如果您完成了上一个项目，并且*确实*想要从僵尸竞技场项目中添加类，只需执行以下操作：在**解决方案资源管理器**窗口中，右键单击**头文件**，然后选择**添加** | **现有项...**。浏览到上一个项目的`TextureHolder.h`并选择它。在**解决方案资源管理器**窗口中，右键单击**源文件**，然后选择**添加** | **现有项...**。浏览到上一个项目的`TextureHolder.cpp`并选择它。现在您可以在这个项目中使用`TextureHolder`类。请注意，文件在项目之间共享，任何更改都将在两个项目中生效。

要从头开始创建`TextureHolder`类，请在**解决方案资源管理器**中右键单击**头文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，通过左键单击**头文件（.h）**，然后在**名称**字段中键入`TextureHolder.h`。最后，单击**添加**按钮。

将以下代码添加到`TextureHolder.h`：

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

在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，通过左键单击**C++文件（** `.cpp` **）**，然后在**名称**字段中键入`TextureHolder.cpp`。最后，单击**添加**按钮。

将以下代码添加到`TextureHolder.cpp`：

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

我们现在可以继续使用我们的新`Engine`类。

## 编写 Engine.h

像往常一样，我们将从头文件开始，其中包含函数声明和成员变量。请注意，我们将在整个项目中重新访问此文件，以添加更多函数和成员变量。目前，我们将只添加在此阶段必要的代码。

在**解决方案资源管理器**中右键单击**头文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，通过左键单击**头文件（**`.h`**）**，然后在**名称**字段中输入`Engine.h`。最后，单击**添加**按钮。现在我们准备为`Engine`类编写头文件。

添加以下成员变量以及函数声明。其中许多我们在其他项目中已经见过，有些我们在*Structuring the Thomas Was Late*代码部分讨论过。请注意函数和变量的名称，以及它们是私有的还是公共的。添加以下代码到`Engine.h`文件，然后我们将讨论它：

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

这是所有私有变量和函数的完整说明。在适当的情况下，我会更详细地解释一下：

+   `TextureHolder th`：`TextureHolder` 类的唯一实例。

+   `TILE_SIZE`：一个有用的常量，提醒我们精灵表中的每个瓷砖都是 50 像素宽和 50 像素高。

+   `VERTS_IN_QUAD`：一个有用的常量，使我们对 `VertexArray` 的操作不那么容易出错。事实上，一个四边形中有四个顶点。现在我们不会忘记它了。

+   `GRAVITY`：一个表示游戏角色每秒向下推动的像素数的常量`int`值。一旦游戏完成，这个值就变得非常有趣。我们将其初始化为`300`，因为这对我们最初的关卡设计效果很好。

+   `m_Window`：通常的 `RenderWindow` 对象，就像我们在所有项目中都有的那样。

+   SFML `View` 对象，`m_MainView`，`m_LeftView`，`m_RightView`，`m_BGMainView`，`m_BGLeftView`，`m_BGRightView` 和 `m_HudView`：前三个 `View` 对象用于全屏视图，左右分屏游戏视图。我们还为这三个视图中的每一个单独创建了一个 SFML `View` 对象，用于绘制背景。最后一个 `View` 对象 `m_HudView` 将在其他六个视图的适当组合上方绘制，以显示得分、剩余时间和向玩家发送的任何消息。有七个不同的 `View` 对象可能意味着复杂性，但当您在本章的进展中看到我们如何处理它们时，您会发现它们非常简单。我们将在本章结束时解决整个分屏/全屏问题。

+   `Sprite m_BackgroundSprite` 和 `Texture m_BackgroundTexture`：可以预料到，这对 SFML `Sprite` 和 `Texture` 将用于显示和保存来自图形资产文件夹的背景图形。

+   `m_Playing`：这个布尔值将让游戏引擎知道关卡是否已经开始（通过按下***Enter***键）。一旦玩家开始游戏，他们就没有暂停游戏的选项。

+   `m_Character1`：当屏幕全屏时，它应该居中显示 Thomas（m_Character1 = true），还是 Bob（m_Character1 = false）？最初，它被初始化为 true，以便居中显示 Thomas。

+   `m_SplitScreen`：游戏当前是否以分屏模式进行？我们将使用这个变量来决定如何使用我们之前声明的所有 `View` 对象。

+   `m_TimeRemaining` 变量：这个 `float` 变量保存当前关卡剩余的时间。在之前的代码中，为了测试目的，它被设置为`10`，直到我们真正为每个关卡设置特定的时间。

+   `m_GameTimeTotal` 变量：这个变量是一个 SFML Time 对象。它跟踪游戏已经进行了多长时间。

+   `m_NewLevelRequired`布尔变量：此变量检查玩家是否刚刚完成或失败了一个级别。然后我们可以使用它来触发加载下一个级别或重新启动当前级别。

+   `input`函数：此函数将处理玩家的所有输入，这在本游戏中完全来自键盘。乍一看，似乎它直接处理所有键盘输入。然而，在这个游戏中，我们将直接处理影响`Thomas`和`Bob`类中的 Thomas 或 Bob 的键盘输入。我们将调用`input`函数，而这个函数将直接处理键盘输入，例如退出、切换到分屏以及其他任何键盘输入。

+   `update`函数：此函数将执行我们以前在`main`函数的更新部分中执行的所有工作。我们还将从`update`函数中调用一些其他函数，以便保持代码组织良好。如果您回顾代码，您将看到它接收一个`float`参数，该参数将保存自上一帧以来经过的秒数的分数。当然，这正是我们需要更新所有游戏对象的内容。

+   `draw`函数：此函数将包含以前项目的主函数中绘图部分中的所有代码。然而，当我们学习使用 SFML 进行其他绘图方式时，将有一些绘图代码不在此函数中。当我们学习第十六章中的粒子系统时，我们将看到这些新代码，*扩展 SFML 类、粒子系统和着色器*。

现在让我们逐一运行所有公共函数：

+   `Engine`构造函数：正如我们所期望的那样，当我们首次声明`Engine`的实例时，将调用此函数。它将对类进行所有设置和初始化。我们将很快在编写`Engine.cpp`文件时看到确切的情况。

+   `run`函数：这是我们需要调用的唯一公共函数。它将触发输入、更新和绘制的执行，这将完成所有工作。

接下来，我们将看到所有这些函数的定义以及一些变量的作用。

## 编写 Engine.cpp

在我们之前的所有类中，我们将所有函数定义放入`.cpp`文件中，并以类名为前缀。由于我们这个项目的目标是使代码更易管理，我们正在以稍有不同的方式进行操作。

在`Engine.cpp`文件中，我们将放置构造函数（`Engine`）和公共`run`函数。所有其他函数将放在自己的`.cpp`文件中，文件名清楚地说明了哪个函数放在哪里。只要我们在包含`Engine`类函数定义的所有文件顶部添加适当的包含指令（`#include "Engine.h"`），这对编译器来说不会是问题。

让我们开始编写`Engine`并在`Engine.cpp`中运行它。在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，通过左键单击**C++文件（.cpp）**，然后在**名称**字段中键入`Engine.cpp`。最后，单击**添加**按钮。现在我们准备好为`Engine`类编写`.cpp`文件。

### 编写 Engine 类构造函数定义

此函数的代码将放在我们最近创建的`Engine.cpp`文件中。

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

我们之前见过很多代码。例如，有通常的代码行来获取屏幕分辨率以及创建`RenderWindow`。在前面的代码末尾，我们使用了现在熟悉的代码来加载纹理并将其分配给 Sprite。在这种情况下，我们正在加载`background.png`纹理并将其分配给`m_BackgroundSprite`。

在四次调用`setViewport`函数之间的代码需要一些解释。`setViewport`函数将屏幕的一部分分配给 SFML`View`对象。但它不使用像素坐标，而是使用比例。其中“1”是整个屏幕（宽度或高度），每次调用`setViewport`的前两个值是起始位置（水平，然后垂直），最后两个值是结束位置。

注意，`m_LeftView`和`m_BGLeftView`放置在完全相同的位置，从屏幕的几乎最左边（0.001）开始，到离中心的两千分之一（0.498）结束。

`m_RightView`和`m_BGRightView`也处于完全相同的位置，从前两个`View`对象的左侧开始（0.5），延伸到屏幕的几乎最右侧（0.998）。

此外，所有视图在屏幕的顶部和底部留下一小片空隙。当我们在白色背景上绘制这些`View`对象时，它将产生在屏幕的两侧之间有一条细白线以及边缘周围有一条细白边框的效果。

我已经尝试在以下图表中表示这种效果：

![编写引擎类构造函数定义](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_12_009.jpg)

理解它的最佳方法是完成本章，运行代码，并看到它的实际效果。

### 编写运行函数定义

此函数的代码将放在我们最近创建的`Engine.cpp`文件中。

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

运行函数是我们引擎的中心-它启动所有其他部分。首先，我们声明一个 Clock 对象。接下来，我们有熟悉的`while(window.isOpen())`循环，它创建游戏循环。在这个 while 循环内，我们做以下事情：

1.  重新启动`clock`并保存上一个循环中所花费的时间`dt`。

1.  在`m_GameTimeTotal`中跟踪总经过时间。

1.  声明并初始化一个`float`来表示上一帧经过的秒数。

1.  调用`input`。

1.  调用`update`并传入经过的时间（`dtAsSeconds`）。

1.  调用`draw`。

所有这些都应该看起来非常熟悉。新的是它包含在`run`函数中。

### 编写输入函数定义

如前所述，此函数的代码将放在自己的文件中，因为它比构造函数或`run`函数更加复杂。我们将使用`#include "Engine.h"`并在函数签名前加上`Engine::`以确保编译器知道我们的意图。

在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加** | **新项目...**。在**添加新项目**窗口中，通过左键单击突出显示（单击）**C++文件（**`.cpp`**）**，然后在**名称**字段中键入`Input.cpp`。最后，单击**添加**按钮。现在我们准备编写`input`函数。

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

与之前的两个项目一样，我们每帧都会检查`RenderWindow`事件队列。同样，我们之前所做的一样，使用`if (Keyboard::isKeyPressed(Keyboard::E))`来检测特定的键。我们刚刚添加的代码中最重要的是这些键实际上做了什么：

+   通常，***Esc***键关闭窗口，游戏将退出。

+   ***Enter***键将`m_Playing`设置为 true，最终，这将导致开始关卡。

+   ***Q***键在全屏模式下在`m_Character1`的值之间切换`true`和`false`。它将在主`View`的 Thomas 和 Bob 之间切换。

+   ***E***键在`m_SplitScreen`之间切换`true`和`false`。这将导致在全屏和分屏视图之间切换。

大部分键盘功能将在本章结束时完全可用。我们即将能够运行我们的游戏引擎。接下来，让我们编写`update`函数。

### 编写更新函数定义

如前所述，此函数的代码将放在自己的文件中，因为它比构造函数或`run`函数更加复杂。我们将使用`#include "Engine.h"`并在函数签名前加上`Engine::`以确保编译器了解我们的意图。

在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加** | **新建项目...**。在**添加新项目**窗口中，通过左键单击选择**C++文件（**`.cpp` **）**，然后在**名称**字段中键入`Update.cpp`。最后，单击**添加**按钮。现在我们准备为`update`函数编写一些代码。

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

首先要注意的是，`update`函数接收上一帧所用时间作为参数。这当然对于`update`函数履行其职责至关重要。

在这个阶段，上述代码并没有实现任何可见的效果。它为我们将来的章节提供了所需的结构。它从`m_TimeRemaining`中减去了上一帧所用的时间。它检查时间是否已经用完，如果是，则将`m_NewLevelRequired`设置为`true`。所有这些代码都包裹在一个`if`语句中，只有当`m_Playing`为`true`时才执行。原因是，与以前的项目一样，我们不希望在游戏尚未开始时时间推移和对象更新。

随着项目的继续，我们将在此基础上构建代码。

### 编写绘制函数定义

如前所述，此函数的代码将放在自己的文件中，因为它比构造函数或`run`函数更加复杂。我们将使用`#include "Engine.h"`并在函数签名前加上`Engine::`以确保编译器了解我们的意图。

在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加** | **新建项目...**。在**添加新项目**窗口中，通过左键单击选择**C++文件（**`.cpp` **）**，然后在**名称**字段中键入`Draw.cpp`。最后，单击**添加**按钮。现在我们准备为`draw`函数添加一些代码。

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

在上述代码中，没有什么是我们以前没有见过的。代码通常从清除屏幕开始。在这个项目中，我们用白色清除屏幕。新的是不同的绘制选项是如何通过条件分隔的，检查屏幕当前是分割还是全屏：

```cpp
if (!m_SplitScreen) 
{ 
} 
else 
{ 
} 

```

如果屏幕没有分割，我们在背景`View`（`m_BGView`）中绘制背景精灵，然后切换到主全屏`View`（`m_MainView`）。请注意，目前我们实际上并没有在`m_MainView`中进行任何绘制。

另一方面，如果屏幕被分割，将执行`else`块中的代码，并在屏幕左侧绘制`m_BGLeftView`上的背景精灵，然后切换到`m_LeftView`。

然后，在`else`块中，我们绘制`m_BGRightView`上的背景精灵，然后切换到`m_RightView`。

在刚才描述的`if...else`结构之外，我们切换到`m_HUDView`。在这个阶段，我们实际上并没有在`m_HUDView`中绘制任何东西。

与另外两个（`input`，`update`）最重要的函数一样，我们经常会回到`draw`函数。我们将添加需要绘制的游戏新元素。您会注意到，每次我们这样做时，我们都会在主要、左侧和右侧的每个部分中添加代码。

让我们快速回顾一下`Engine`类，然后我们可以启动它。

## 到目前为止的 Engine 类

我们所做的是将以前在`main`函数中的所有代码抽象成`input`，`update`和`draw`函数。这些函数的连续循环以及时间控制由`run`函数处理。

考虑在 Visual Studio 中保持**Input.cpp**、**Update.cpp**和**Draw.cpp**标签页打开，可能按顺序组织，如下截图所示：

![到目前为止的 Engine 类](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_12_010.jpg)

在项目的过程中，我们将重新审视这些函数，添加更多的代码。现在我们已经有了`Engine`类的基本结构和功能，我们可以在`main`函数中创建一个实例，并看到它的运行情况。

# 编写主函数

让我们将`HelloSFML.cpp`文件重命名为`Main.cpp`。在**解决方案资源管理器**中右键单击`HelloSFML`文件，然后选择**重命名**。将名称更改为`Main.cpp`。这将是包含我们的`main`函数和实例化`Engine`类的代码的文件。

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

我们所做的就是为`Engine`类添加一个包含指令，声明一个`Engine`的实例，然后调用它的`run`函数。直到玩家退出并且执行返回到`main`和`return 0`语句之前，所有的事情都将由`Engine`类处理。

这很容易。现在我们可以运行游戏，看到空的背景，无论是全屏还是分屏，最终将包含所有动作。

到目前为止，游戏是全屏模式，只显示背景：

![编写主函数](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_12_011.jpg)

现在按下***E***键，您将能够看到屏幕被整齐地分成两半，准备进行分屏合作游戏：

![编写主函数](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_12_012.jpg)

以下是一些可能会让您感到困惑的问题。

# 常见问题解答

Q) 我并不完全理解代码文件的结构。

A) 抽象确实可以使我们的代码结构变得不太清晰，但实际的代码本身变得更容易。与我们在以前的项目中将所有内容塞进主函数不同，我们将把代码分成`Input.cpp`、`Update.cpp`和`Draw.cpp`。此外，随着我们的进行，我们将使用更多的类来将相关代码分组。再次研究《构建 Thomas Was Late 代码》部分，特别是图表。

# 总结

在本章中，我们介绍了 Thomas Was Late 游戏，并为项目的其余部分奠定了理解和代码结构的基础。解决方案资源管理器中确实有很多文件，但只要我们理解每个文件的目的，我们会发现项目的实现变得更加容易。

在接下来的章节中，我们将学习另外两个基本的 C++主题，继承和多态。我们还将开始利用它们，构建三个类来代表两个可玩角色。


# 第十三章：高级 OOP-继承和多态

在本章中，我们将通过学习稍微更高级的**继承**和**多态**概念来进一步扩展我们对 OOP 的知识。然后，我们将能够使用这些新知识来实现我们游戏的明星角色，Thomas 和 Bob。在本章中，我们将更详细地介绍以下内容：

+   如何使用继承扩展和修改类？

+   通过多态将一个类的对象视为多种类型的类

+   抽象类以及设计永远不会实例化的类实际上可以很有用

+   构建一个抽象的`PlayableCharacter`类

+   使用`Thomas`和`Bob`类来实现继承

+   将 Thomas 和 Bob 添加到游戏项目中

# 继承

我们已经看到了如何通过实例化/创建对象来使用 SFML 库的类的其他人的辛勤工作。但是，这整个面向对象的东西甚至比那更深入。

如果有一个类中有大量有用的功能，但不完全符合我们的要求怎么办？在这种情况下，我们可以**继承**自其他类。就像它听起来的那样，**继承**意味着我们可以利用其他人的类的所有特性和好处，包括封装，同时进一步完善或扩展代码，使其特别适合我们的情况。在这个项目中，我们将继承并扩展一些 SFML 类。我们也会用我们自己的类来做同样的事情。

让我们看一些使用继承的代码，

## 扩展一个类

考虑到所有这些，让我们看一个示例类，并看看我们如何扩展它，只是为了看看语法并作为第一步。

首先，我们定义一个要继承的类。这与我们创建任何其他类没有什么不同。看一下这个假设的`Soldier`类声明：

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

在前面的代码中，我们定义了一个`Soldier`类。它有四个私有变量，`m_Health`，`m_Armour`，`m_Range`和`m_ShotPower`。它有四个公共函数`setHealth`，`setArmour`，`setRange`和`setShotPower`。我们不需要看到函数的定义，它们只是简单地初始化它们的名字明显的适当变量。

我们还可以想象，一个完全实现的`Soldier`类会比这更加深入。它可能有函数，比如`shoot`，`goProne`等。如果我们在一个 SFML 项目中实现了`Soldier`类，它可能会有一个`Sprite`对象，以及一个`update`和一个`getPostion`函数。

这里呈现的简单场景适合学习继承。现在让我们看看一些新东西，实际上是从`Soldier`类继承。看看这段代码，特别是突出显示的部分：

```cpp
class Sniper : public Soldier 
{ 
public: 
   // A constructor specific to Sniper 
   Sniper::Sniper(); 
}; 

```

通过将`: public Soldier`代码添加到`Sniper`类声明中，`Sniper`继承自`Soldier`。但这到底意味着什么？`Sniper`是一个`Soldier`。它拥有`Soldier`的所有变量和函数。然而，继承不仅仅是这样。

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

我们可以继续编写一堆其他类，这些类是`Soldier`类的扩展，也许是`Commando`和`Infantryman`。每个类都有完全相同的变量和函数，但每个类也可以有一个独特的构造函数，用于初始化适合`Soldier`类型的变量。`Commando`可能有非常高的`m_Health`和`m_ShotPower`，但是`m_Range`非常小。`Infantryman`可能介于`Commando`和`Sniper`之间，每个变量的值都是中等水平。

### 提示

好像面向对象编程已经足够有用了，现在我们可以模拟现实世界的对象，包括它们的层次结构。我们通过子类化、扩展和继承其他类来实现这一点。

我们可能想要学习的术语是从中扩展的类是**超类**，从超类继承的类是**子类**。我们也可以说**父**类和**子**类。

### 提示

关于继承，您可能会问这样一个问题：为什么？原因是这样的：我们可以编写一次通用代码；在父类中，我们可以更新该通用代码，所有继承自它的类也会被更新。此外，子类只能使用公共和**受保护**实例变量和函数。因此，如果设计得当，这也进一步增强了封装的目标。

你说受保护？是的。有一个称为**受保护**的类变量和函数的访问限定符。您可以将受保护的变量视为介于公共和私有之间。以下是访问限定符的快速摘要，以及有关受保护限定符的更多详细信息：

+   `公共`变量和函数可以被任何人访问和使用。

+   `私有`变量和函数只能被类的内部代码访问/使用。这对封装很有用，当我们需要访问/更改私有变量时，我们可以提供公共的`getter`和`setter`函数（如`getSprite`等）。如果我们扩展了一个具有`私有`变量和函数的类，那么子类*不能*直接访问其父类的私有数据。

+   `受保护`变量和函数几乎与私有变量和函数相同。它们不能被类的实例直接访问/使用。但是，它们*可以*被扩展它们所声明的类的任何类直接使用。因此，它们就像是私有的，只不过对子类是可见的。

要充分理解受保护的变量和函数以及它们如何有用，让我们先看看另一个主题，然后我们可以看到它们的作用。

# 多态

**多态**允许我们编写的代码不那么依赖于我们试图操作的类型。这可以使我们的代码更清晰和更高效。多态意味着不同的形式。如果我们编写的对象可以是多种类型的东西，那么我们就可以利用这一点。

### 注意

多态对我们意味着什么？简而言之，多态就是：任何子类都可以作为使用超类的代码的一部分。这意味着我们可以编写更简单、更易于理解的代码，也更容易修改或更改。此外，我们可以为超类编写代码，并依赖于这样一个事实：在一定的参数范围内，无论它被子类化多少次，代码仍然可以正常工作。

让我们讨论一个例子。

假设我们想利用多态来帮助编写一个动物园管理游戏，我们需要喂养和照顾动物的需求。我们可能会想要有一个名为`feed`的函数。我们可能还想将要喂养的动物的实例传递给`feed`函数。

当然，动物园有很多种类的动物——`狮子`、`大象`和`三趾树懒`。有了我们对 C++继承的新知识，编写一个`Animal`类并让所有不同类型的动物从中继承就会有意义。

如果我们想编写一个函数（`feed`），我们可以将狮子、大象和三趾树懒作为参数传递进去，似乎需要为每种类型的`Animal`编写一个`feed`函数。但是，我们可以编写多态函数，具有多态返回类型和参数。看一下这个假设的`feed`函数的定义：

```cpp
void feed(Animal& a) 
{ 
   a.decreaseHunger(); 
} 

```

前面的函数将`Animal`引用作为参数，这意味着可以将任何从扩展`Animal`的类构建的对象传递给它。

因此，今天你甚至可以编写代码，然后在一周、一个月或一年后创建另一个子类，相同的函数和数据结构仍然可以工作。此外，我们可以对子类强制执行一组规则，规定它们可以做什么，不能做什么，以及如何做。因此，一个阶段的良好设计可以影响其他阶段。

但我们真的会想要实例化一个真正的动物吗？

# 抽象类 - 虚拟和纯虚拟函数

**抽象类**是一个不能被实例化的类，因此不能被制作成对象。

### 提示

在这里我们可能想学习的一些术语是**具体**类。**具体**类是任何不是抽象的类。换句话说，到目前为止我们编写的所有类都是具体类，可以实例化为可用的对象。

那么，这段代码永远不会被使用了吗？但这就像付钱给一个建筑师设计你的房子，然后永远不建造它！

如果我们或一个类的设计者想要强制其用户在使用他们的类之前继承它，他们可以将一个类**抽象化**。然后，我们就不能从中创建一个对象；因此，我们必须首先扩展它，然后从子类创建一个对象。

为此，我们可以创建一个**纯虚拟**函数并不提供任何定义。然后，任何扩展它的类都必须**覆盖**（重新编写）该函数。

让我们看一个例子；这会有所帮助。我们通过添加一个纯虚拟函数使一个类变成抽象类，比如这个只能执行通用动作`makeNoise`的抽象`Animal`类：

```cpp
Class Animal 
   private: 
      // Private stuff here 

   public: 

      void virtual makeNoise() = 0; 

      // More public stuff here 
}; 

```

如你所见，我们在函数声明之前添加了 C++关键字`virtual`，之后添加了`= 0`。现在，任何扩展/继承自`Animal`的类都必须覆盖`makeNoise`函数。这是有道理的，因为不同类型的动物发出的声音非常不同。也许我们可以假设任何扩展`Animal`类的人都足够聪明，能够注意到`Animal`类不能发出声音，他们需要处理它，但如果他们没有注意到呢？关键是通过创建一个纯虚拟函数，我们保证他们会注意到，因为他们必须注意到。

抽象类也很有用，因为有时我们需要一个可以用作多态类型的类，但需要保证它永远不能用作对象。例如，`Animal`单独使用并没有太多意义。我们不谈论动物；我们谈论动物的类型。我们不会说，“哦，看那只可爱的、蓬松的、白色的动物！”或者，“昨天我们去宠物店买了一只动物和一个动物床”。这太抽象了。

因此，抽象类有点像一个**模板**，可以被任何扩展它的类使用（继承自它）。如果我们正在构建一个*工业帝国*类型的游戏，玩家管理企业和员工，我们可能需要一个`Worker`类，并将其扩展为`Miner`、`Steelworker`、`OfficeWorker`，当然还有`Programmer`。但是一个普通的`Worker`到底是做什么的呢？我们为什么要实例化一个？

答案是我们不想实例化一个，但我们可能想将其用作多态类型，以便在函数之间传递多个`Worker`子类，并且有可以容纳所有类型的工人的数据结构。

所有纯虚拟函数必须被扩展父类的任何类覆盖，该父类包含纯虚拟函数。这意味着抽象类可以提供一些在所有子类中都可用的公共功能。例如，`Worker`类可能有`m_AnnualSalary`、`m_Productivity`和`m_Age`成员变量。它可能还有`getPayCheck`函数，这不是纯虚拟的，并且在所有子类中都是相同的，但它可能有一个`doWork`函数，这是纯虚拟的，必须被覆盖，因为所有不同类型的`Worker`都会以非常不同的方式`doWork`。

### 注意

顺便说一句，**virtual**与纯虚函数相反，是一个**可选重写**的函数。你声明一个虚函数的方式与声明纯虚函数的方式相同，但是最后不加上`= 0`。在当前的游戏项目中，我们将使用一个纯虚函数。

如果对虚拟、纯虚拟或抽象的任何内容不清楚，使用它可能是理解它的最佳方式。

# 构建 PlayableCharacter 类

现在我们已经了解了继承、多态和纯虚函数的基础知识，我们将把它们应用起来。我们将构建一个`PlayableCharacter`类，它将拥有我们游戏中任何角色大部分功能所需的功能。它将有一个纯虚函数，`handleInput`。`handleInput`函数在子类中需要有很大的不同，所以这是有道理的。

由于`PlayableCharacter`将有一个纯虚函数，它将是一个抽象类，不可能有它的对象。然后我们将构建`Thomas`和`Bob`类，它们将继承自`PlayableCharacter`，实现纯虚函数的定义，并允许我们在游戏中实例化`Bob`和`Thomas`对象。

## 编写 PlayableCharacter.h

通常，在创建一个类时，我们将从包含成员变量和函数声明的头文件开始。新的是，在这个类中，我们将声明一些**protected**成员变量。请记住，受保护的变量可以被继承自具有受保护变量的类的类使用，就好像它们是`Public`一样。

在**解决方案资源管理器**中右键单击**头文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，通过左键单击**头文件（** `.h` **）**突出显示，然后在**名称**字段中键入`PlayableCharacter.h`。最后，单击**添加**按钮。我们现在准备为`PlayableCharacter`类编写头文件。

我们将在三个部分中添加和讨论`PlayableCharacter.h`文件的内容。首先是**protected**部分，然后是**private**，最后是**public**。

在`PlayableCharacter.h`文件旁边添加下面显示的代码：

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

我们刚刚编写的代码中要注意的第一件事是所有变量都是`protected`的。这意味着当我们扩展类时，我们刚刚编写的所有变量将对扩展它的类可访问。我们将用`Thomas`和`Bob`类扩展这个类。

除了`protected`访问规范之外，先前的代码没有什么新的或复杂的。然而，值得注意的是一些细节。然后随着我们的进展，理解类的工作原理将变得容易。因此，让我们逐个运行这些`protected`变量。

我们有一个相对可预测的`Sprite`，`m_Sprite`。我们有一个名为`m_JumpDuration`的浮点数，它将保存代表角色能够跳跃的时间值。数值越大，角色就能够跳得越远/高。

接下来，我们有一个布尔值，`m_IsJumping`，当角色跳跃时为`true`，否则为`false`。这将有助于确保角色在空中时无法跳跃。

`m_IsFalling`变量与`m_IsJumping`有类似的用途。它将有助于知道角色何时下落。

接下来，我们有两个布尔值，如果角色的左或右键盘按钮当前被按下，则为`true`。这取决于角色（*A*和*D*为 Thomas，左右箭头键为 Bob）。我们将在`Thomas`和`Bob`类中看到如何响应这些布尔值。

`m_TimeThisJump`浮点变量在每一帧`m_IsJumping`为`true`时更新。然后我们就可以知道`m_JumpDuration`何时被达到。

最后一个`protected`变量是布尔值`m_JustJumped`。如果在当前帧中启动了跳跃，它将为`true`。这对于知道何时播放跳跃音效将很有用。

接下来，将以下`private`变量添加到`PlayableCharacter.h`文件中：

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

在之前的代码中，我们有一些有趣的`private`变量。请记住，这些变量只能被`PlayableCharacter`类中的代码直接访问。`Thomas`和`Bob`类将无法直接访问它们。

`m_Gravity`变量将保存角色下落的每秒像素数。`m_Speed`变量将保存角色每秒可以向左或向右移动的像素数。

`Vector2f`，`m_Position`变量是角色在世界中（而不是屏幕上）的位置，即角色的中心位置。

接下来的四个`FloatRect`对象很重要。在*Zombie Arena*游戏中进行碰撞检测时，我们只是检查两个`FloatRect`对象是否相交。每个`FloatRect`对象代表整个角色、拾取物或子弹。对于非矩形形状的对象（僵尸和玩家），这有点不准确。

在这个游戏中，我们需要更加精确。`m_Feet`，`m_Head`，`m_Right`和`m_Left` `FloatRect`对象将保存角色身体不同部位的坐标。这些坐标将在每一帧中更新。

通过这些坐标，我们将能够准确地判断角色何时落在平台上，跳跃时是否碰到头部，或者与侧面的瓷砖擦肩而过。

最后，我们有`Texture`。`Texture`是`private`的，因为它不会被`Thomas`或`Bob`类直接使用，但正如我们所看到的，`Sprite`是`protected`的，因为它被直接使用。

现在将所有`public`函数添加到`PlayableCharacter.h`文件中，然后我们将讨论它们：

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

+   `spawn`函数接收一个名为`startPosition`的`Vector2f`和一个名为`gravity`的`float`。顾名思义，`startPosition`将是角色在关卡中开始的坐标，`gravity`将是角色下落的每秒像素数。

+   `bool virtual handleInput() = 0`当然是我们的纯虚函数。由于`PlayableCharacter`有这个函数，任何扩展它的类，如果我们想要实例化它，必须为这个函数提供定义。因此，当我们在一分钟内为`PlayableCharacter`编写所有函数定义时，我们将不为`handleInput`提供定义。当然，`Thomas`和`Bob`类中也需要有定义。

+   `getPosition`函数返回一个代表整个角色位置的`FloatRect`。

+   `getFeet()`函数，以及`getHead`，`getRight`和`getLeft`，每个都返回一个代表角色身体特定部位位置的`FloatRect`。这正是我们需要进行详细的碰撞检测。

+   `getSprite`函数像往常一样，将`m_Sprite`的副本返回给调用代码。

+   `stopFalling`，`stopRight`，`stopLeft`和`stopJump`函数接收一个`float`值，函数将使用它来重新定位角色并阻止它在实心瓷砖上行走或跳跃。

+   `getCenter`函数将一个`Vector2f`返回给调用代码，让它准确地知道角色的中心在哪里。这个值当然保存在`m_Position`中。我们将在后面看到，它被`Engine`类用来围绕适当的角色中心适当地居中适当的`View`。

+   我们之前多次见过的`update`函数和往常一样，它接受一个`float`参数，表示当前帧所花费的秒数的一部分。然而，这个`update`函数需要做的工作比以前的`update`函数（来自其他项目）更多。它需要处理跳跃，以及更新代表头部、脚部、左侧和右侧的`FloatRect`对象。

现在我们可以为所有函数编写定义，当然，除了`handleInput`。

## 编写 PlayableCharacter.cpp

在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，通过左键单击**C++文件（**`.cpp`**）**，然后在**名称**字段中键入`PlayableCharacter.cpp`。最后，单击**添加**按钮。现在我们准备为`PlayableCharacter`类编写`.cpp`文件。

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

接下来，在前面的代码之后立即添加`update`函数的定义：

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

1.  用`elapsedTime`更新`m_TimeThisJump`。

1.  检查`m_TimeThisJump`是否仍然小于`m_JumpDuration`。如果是，则通过重力乘以经过的时间两倍来改变`m_Position`的 y 坐标。

1.  在`else`子句中，当`m_TimeThisJump`不低于`m_JumpDuration`时，`m_Falling`被设置为`true`。这样做的效果将在下面看到。此外，`m_Jumping`被设置为`false`。这样做是为了防止我们刚刚讨论的代码执行，因为`if(m_IsJumping)`现在为 false。

`if(m_IsFalling)`块每帧将`m_Position`向下移动。它使用`m_Gravity`的当前值和经过的时间进行移动。

以下代码（几乎所有剩余的代码）相对于精灵的当前位置更新角色的身体部位。看一下下面的图表，看看代码如何计算角色的虚拟头部、脚部、左侧和右侧的位置：

![编写 PlayableCharacter.cpp](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_13_001.jpg)

代码的最后一行使用`setPosition`函数将精灵移动到`update`函数的所有可能性之后的正确位置。

现在立即在上一个代码之后添加`getPosition`、`getCenter`、`getFeet`、`getHead`、`getLeft`、`getRight`和`getSprite`函数的定义：

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

`getPosition`函数返回包装整个精灵的`FloatRect`，`getCenter`返回一个包含精灵中心的`Vector2f`。请注意，我们将精灵的高度和宽度除以二，以便动态地得到这个结果。这是因为 Thomas 和 Bob 的身高不同。

`getFeet`、`getHead`、`getLeft`和`getRight`函数返回表示角色各个身体部位的`FloatRect`对象，我们在`update`函数中每帧更新它们。我们将在下一章中编写使用这些函数的**碰撞检测代码**。

`getSprite`函数像往常一样返回`m_Sprite`的副本。

最后，对于`PlayableCharacter`类，立即在上一个代码之后添加`stopFalling`、`stopRight`、`stopLeft`和`stopJump`函数的定义：

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

每个前面的函数都接收一个值作为参数，用于重新定位精灵的顶部、底部、左侧或右侧。这些值是什么以及如何获得它们将在下一章中看到。每个前面的函数也重新定位精灵。

最后一个函数是`stopJump`函数，它也将在碰撞检测中使用。它设置了`m_IsJumping`和`m_IsFalling`的必要值来结束跳跃。

# 构建 Thomas 和 Bob 类

现在我们真正要使用继承了。我们将为 Thomas 建立一个类，为 Bob 建立一个类。它们都将继承我们刚刚编写的`PlayableCharacter`类。然后它们将拥有`PlayableCharacter`类的所有功能，包括直接访问其`protected`变量。我们还将添加纯虚函数`handleInput`的定义。您会注意到，`Thomas`和`Bob`的`handleInput`函数将是不同的。

## 编写 Thomas.h

在**解决方案资源管理器**中右键单击**头文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，通过左键单击**头文件**（`.h`）并在**名称**字段中键入`Thomas.h`。最后，单击**添加**按钮。现在我们准备好为`Thomas`类编写头文件了。

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

上面的代码非常简短而简洁。我们可以看到我们有一个构造函数，我们将要实现纯虚的`handleInput`函数，所以现在让我们来做吧。

## 编写 Thomas.cpp

在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，通过左键单击**C++文件**（`.cpp`）并在**名称**字段中键入`Thomas.cpp`。最后，单击**添加**按钮。现在我们准备好为`Thomas`类编写`.cpp`文件了。

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

我们只需要加载`thomas.png`图形并将跳跃持续时间（`m_JumpDuration`）设置为`.45`（几乎半秒）。

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

这段代码应该看起来很熟悉。我们使用 SFML 的`isKeyPressed`函数来查看*W*、*A*或*D*键是否被按下。

当按下*W*键时，玩家正在尝试跳跃。然后代码使用`if(!m_IsJumping && !m_IsFalling)`代码，检查角色是否已经在跳跃，而且也没有在下落。当这些测试都为真时，`m_IsJumping`被设置为`true`，`m_TimeThisJump`被设置为零，`m_JustJumped`被设置为 true。

当前两个测试不为`true`时，执行`else`子句，并将`m_Jumping`设置为`false`，将`m_IsFalling`设置为 true。

按下*A*和*D*键的处理就是简单地将`m_LeftPressed`和/或`m_RightPressed`设置为`true`或`false`。`update`函数现在将能够处理移动角色。

函数中的最后一行代码返回`m_JustJumped`的值。这将让调用代码知道是否需要播放跳跃音效。

我们现在将编写`Bob`类，尽管这几乎与`Thomas`类相同，但它具有不同的跳跃能力，不同的`Texture`，并且在键盘上使用不同的键。

## 编写 Bob.h

`Bob`类的结构与`Thomas`类相同。它继承自`PlayableCharacter`，有一个构造函数，并提供`handleInput`函数的定义。与`Thomas`相比的区别是，我们以不同的方式初始化了一些 Bob 的成员变量，并且我们也以不同的方式处理输入（在`handleInput`函数中）。让我们编写这个类并看看细节。

在**解决方案资源管理器**中右键单击**头文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，通过左键单击**头文件**（`.h`）并在**名称**字段中键入`Bob.h`。最后，单击**添加**按钮。现在我们准备好为`Bob`类编写头文件了。

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

上面的代码与`Thomas.h`文件相同，除了类名和构造函数名。

## 编写 Bob.cpp

在**解决方案资源管理器**中右键单击**源文件**，然后选择**添加** | **新建项...**。在**添加新项**窗口中，通过左键单击**C++文件（**`.cpp`**）**突出显示，然后在**名称**字段中键入`Thomas.cpp`。最后，单击**添加**按钮。我们现在准备为`Bob`类编写`.cpp`文件。

将`Bob`构造函数的代码添加到`Bob.cpp`文件中。注意纹理不同（`bob.png`），并且`m_JumpDuration`初始化为一个显着较小的值。Bob 现在是他自己独特的自己：

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

注意，代码几乎与`Thomas`类的`handleInput`函数中的代码相同。唯一的区别是我们对不同的键（**左**箭头键，**右**箭头键和**上**箭头键用于跳跃）做出响应。

现在我们有一个`PlayableCharacter`类，它已经被`Bob`和`Thomas`扩展，我们可以在游戏中添加一个`Bob`和一个`Thomas`实例。

# 更新游戏引擎以使用 Thomas 和 Bob

为了能够运行游戏并看到我们的新角色，我们必须声明它们的实例，调用它们的`spawn`函数，每帧更新它们，并每帧绘制它们。现在让我们来做这个。

## 更新 Engine.h 以添加 Bob 和 Thomas 的实例

打开`Engine.h`文件并添加下面突出显示的代码行，如下所示：

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

## 更新输入函数以控制 Thomas 和 Bob

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

请注意，以前的代码是多么简单，因为所有功能都包含在`Thomas`和`Bob`类中。所有代码只需为`Thomas`和`Bob`类添加一个包含指令。然后，在`input`函数中，代码只需在`m_Thomas`和`m_Bob`上调用纯虚拟的`handleInput`函数。我们将每个调用包装在`if`语句中的原因是因为它们基于刚刚成功启动的新跳跃返回`true`或`false`。我们将在第十五章中处理播放跳跃音效，*声音空间化和 HUD*。

## 更新更新函数以生成和更新 PlayableCharacter 实例

这被分成两部分。首先，我们需要在新级别开始时生成 Bob 和 Thomas，其次，我们需要每帧更新（通过调用它们的`update`函数）。

### 生成 Thomas 和 Bob

随着项目的进展，我们需要在几个不同的地方调用我们的`Thomas`和`Bob`对象的生成函数。最明显的是，当新级别开始时，我们需要生成这两个角色。在接下来的章节中，随着我们需要在级别开始时执行的任务数量增加，我们将编写一个`loadLevel`函数。现在，让我们在`update`函数中调用`m_Thomas`和`m_Bob`的`spawn`函数，如下所示的突出显示的代码。添加这段代码，但请记住，这段代码最终将被删除并替换：

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

先前的代码只是调用`spawn`并传入游戏世界中的位置以及重力。该代码包裹在一个`if`语句中，检查是否需要新的级别。实际的生成代码将被移动到一个专门的`loadLevel`函数中，但`if`条件将成为完成项目的一部分。此外，`m_TimeRemaining`被设置为一个相当任意的 10 秒。

### 每帧更新 Thomas 和 Bob

接下来，我们将更新 Thomas 和 Bob。我们只需要调用它们的`update`函数并传入本帧所花费的时间。

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

现在角色可以移动了，我们需要更新适当的`View`对象，使其围绕角色居中并使其成为关注的中心。当然，直到我们的游戏世界中有一些物体，才能实现实际移动的感觉。

添加下面片段中显示的突出代码：

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

先前的代码处理了两种可能的情况。首先，`if(mSplitScreen)`条件将左侧视图定位在`m_Thomas`周围，右侧视图定位在`m_Bob`周围。当游戏处于全屏模式时执行的`else`子句测试`m_Character1`是否为`true`。如果是，则全屏视图（`m_MainView`）围绕 Thomas 居中，否则围绕 Bob 居中。您可能还记得玩家可以使用*E*键在分屏模式和全屏模式之间切换，使用*Q*键在全屏模式下切换 Bob 和 Thomas。我们在`Engine`类的`input`函数中编写了这些内容，回到第十二章。

## 绘制 Bob 和 Thomas

确保`Draw.cpp`文件已打开，并添加下面片段中显示的突出代码：

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

请注意，我们在全屏、左侧和右侧都绘制了 Thomas 和 Bob。还要注意在分屏模式下绘制角色的微妙差异。在绘制屏幕的左侧时，我们改变了角色的绘制顺序，并在 Bob 之后绘制 Thomas。因此，Thomas 将始终位于左侧的顶部，Bob 位于右侧。这是因为左侧是为控制 Thomas 的玩家而设计的，右侧是为控制 Bob 的玩家而设计的。

您可以运行游戏，看到 Thomas 和 Bob 位于屏幕中央：

![绘制 Bob 和 Thomas](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_13_002.jpg)

如果按下*Q*键从 Thomas 切换到 Bob，您将看到`View`进行了轻微调整。如果移动任何一个角色向左或向右（Thomas 使用*A*和*D*，Bob 使用箭头键），您将看到它们相对移动。

尝试按下*E*键在全屏和分屏模式之间切换。然后尝试再次移动两个角色以查看效果。在下面的截图中，您可以看到 Thomas 始终位于左侧窗口的中心，Bob 始终位于右侧窗口的中心：

![绘制 Bob 和 Thomas](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_13_003.jpg)

如果您让游戏运行足够长的时间，角色将每十秒重新生成在它们的原始位置。这是我们在完成游戏时需要的功能的开端。这种行为是由`m_TimeRemaining`变为负值，然后将`m_NewLevelRequired`变量设置为`true`引起的。

还要注意，直到我们绘制了关卡的细节，我们才能看到移动的完整效果。实际上，虽然看不到，但两个角色都在以每秒 300 像素的速度持续下落。由于摄像机每帧都围绕它们居中，并且游戏世界中没有其他物体，我们看不到这种向下运动。

如果您想自己演示这一点，只需按照以下代码中所示更改对`m_Bob.spawn`的调用：

```cpp
m_Bob.spawn(Vector2f(0,0), 0); 

```

现在 Bob 没有重力效果，Thomas 会明显远离他。如下截图所示：

![绘制 Bob 和 Thomas](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/bg-cpp-prog/img/image_13_004.jpg)

在接下来的章节中，我们将添加一些可玩的关卡进行交互。

# 常见问题解答

Q）我们学习了多态性，但到目前为止，我没有注意到游戏代码中有任何多态性。

A）在接下来的章节中，当我们编写一个以`PlayableCharacter`作为参数的函数时，我们将看到多态性的实际应用。我们将看到如何可以将 Bob 或 Thomas 传递给这个新函数，并且无论使用哪个，它都能正常工作。

# 摘要

在本章中，我们学习了一些新的 C++概念。首先，继承允许我们扩展一个类并获得其所有功能。我们还学到，我们可以将变量声明为受保护的，这将使子类可以访问它们，但它们仍将被封装（隐藏）在所有其他代码之外。我们还使用了纯虚函数，这使得一个类成为抽象类，意味着该类不能被实例化，因此必须从中继承/扩展。我们还介绍了多态的概念，但需要等到下一章才能在我们的游戏中使用它。

接下来，我们将为游戏添加一些重要功能。在接下来的一章中，Thomas 和 Bob 将会行走、跳跃和下落。他们甚至可以跳在彼此的头上，以及探索从文本文件加载的一些关卡设计。
