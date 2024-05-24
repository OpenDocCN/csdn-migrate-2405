# 构建 Cocos2dx 安卓游戏（二）

> 原文：[`zh.annas-archive.org/md5/C5B09CE8256BCC61162F0F46EF01CFDE`](https://zh.annas-archive.org/md5/C5B09CE8256BCC61162F0F46EF01CFDE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：音频

Cocos2d-x 框架带有一个名为`CocosDenshion`的音频引擎，它从 Cocos2d for iPhone 继承而来。这个引擎封装了播放声音效果和背景音乐的所有复杂性。现在，Cocos2d-x 有一个从零开始构建的新的音频引擎，旨在提供比`CocosDenshion`库更多的灵活性。请注意，没有计划从 Cocos2d-x 框架中消除`CocosDenshion`音频引擎，现在在 Cocos2d-x 中通常会有冗余的组件，以便程序员可以选择更适合他们需求的部分。

本章将涵盖以下主题：

+   播放背景音乐和声音效果

+   修改音频属性

+   离开游戏时处理音频

+   新的音频引擎

# 播放背景音乐和声音效果

为了通过使用`CocosDenshion`音频引擎向我们的游戏中添加背景音乐，第一步是在我们的`HelloWorldScene.cpp`实现文件中添加以下文件包含：

```java
#include "SimpleAudioEngine.h"
```

在这个头文件中，我们将在私有成员部分也添加我们新的`initAudio`方法的声明，该方法将用于启动背景音乐以及预加载每次`player`精灵被炸弹撞击时要播放的音效：

```java
void initAudio();
```

现在，在`HelloWorld.cpp`实现文件中，我们将使用`CocosDenshion`命名空间，这样我们在每次访问音频引擎单例实例时就不必隐式引用这个命名空间：

```java
using namespace CocosDenshion;
```

现在，在同一个实现文件中，我们将编写`initAudio`方法的主体，正如我们之前提到的，它将开始播放循环的背景音乐。我们提供了这一章的源代码，并将预加载每次我们的玩家失败时要播放的音效。`playBackgroundMusic`方法的第二个参数是一个布尔值，它决定了我们是否希望背景音乐永远重复。

```java
void HelloWorld::initAudio()
{
   SimpleAudioEngine::getInstance()->playBackgroundMusic("music.mp3",    true);
   SimpleAudioEngine::getInstance()->preloadEffect("uh.wav");   
}
```

让我们在`Resources`目录中创建一个名为`sounds`的文件夹，这样我们可以把所有的声音文件以有组织的方式放在那里。完成此操作后，我们需要在`AppDelegate.cpp`实现文件中实例化`searchPaths std::vector`之后添加以下行，将`sounds`目录添加到搜索路径中，以便音频引擎可以找到我们的文件：

```java
searchPaths.push_back("sounds");
```

### 注意

我们鼓励您组织您的`Resources`文件夹，为音频和音乐创建一个声音文件夹以及子文件夹，这样我们就不必把所有内容都放在根目录下。

让我们转到每次两个物理体碰撞时调用的`onCollision`方法。如果玩家的精灵物理体涉及到碰撞，那么我们将在添加以下代码行之后停止背景音乐并播放`uh.wav`音效，然后切换到游戏结束场景：

```java
SimpleAudioEngine::getInstance()->stopBackgroundMusic();
SimpleAudioEngine::getInstance()->playEffect("uh.wav");
```

最后，我们将在`HelloWorld.cpp`实现文件中的`init`方法末尾添加对我们`initAudio`方法的调用：

```java
initAudio();
```

# 修改音频属性

您可以通过调用`setBackgroundMusicVolume`方法和`setEffectsVolume`方法轻松修改背景音乐和声音效果的基本音频属性。两者都接收一个`float`类型的参数，其中`0.0`表示静音，`1.0`表示最大音量，如下面的代码清单所示：

```java
SimpleAudioEngine::getInstance()->setBackgroundMusicVolume(0.5f);
SimpleAudioEngine::getInstance()->setEffectsVolume(1.0f);
```

## 处理离开游戏时的音频

当游戏活动不再处于活动状态时，背景音乐和声音效果不会自动停止，应该通过从`AppDelegate`类的`applicationDidEnterBackgound`方法中移除以下注释块来手动停止：

```java
// if you use SimpleAudioEngine, it must be pause
 SimpleAudioEngine::getInstance()->pauseBackgroundMusic();
```

为了让这行新代码工作，我们需要在`HelloWorld.cpp`实现文件中添加相同的行，以便使用`CocosDenshion`命名空间：

```java
using namespace CocosDenshion;
```

当用户切换到另一个应用程序时，您的游戏将停止所有当前的声音。用户一回到我们的游戏，我们就需要恢复音乐。我们可以像以前一样做，但现在，我们将从`AppDelegate`类的`applicationWillEnterForeground`方法中移除以下注释块：

```java
 // if you use SimpleAudioEngine, it must resume here
SimpleAudioEngine::getInstance()->resumeBackgroundMusic();
```

# 新的音频引擎

在 Cocos2d-x 3.4 的实验阶段，从头开始构建了一个新的音频引擎，以便添加更多功能和灵活性。现在 Cocos2d-x 的新音频引擎可用于 Android、iOS、Mac OS 和 win-32 平台。它能够在 Android 平台上同时播放多达 24 个声音；这个数字可能会根据平台的不同而改变。

如果您运行与 Cocos2d-x 框架捆绑的测试，那么您可以测试两个音频引擎。在运行时，它们可能听起来没有明显差异，但它们在内部是非常不同的。

与`CocosDenshion`引擎不同，这个新引擎中声音效果和背景音乐没有区别。因此，与`CocosDenshion`的两个方法—`setBackgroundMusicVolume`和`setEffectsVolume`相比，框架只有一个`setVolume`方法。在本节后面，我们将向您展示如何调整每个播放音频的音量，无论它是声音效果还是背景音乐。

让我们在`HelloWorldScene.h`头文件中添加一个新的方法声明，名为`initAudioNewEngine`，顾名思义，它将初始化我们游戏的音频功能，但现在它将使用新的音频引擎来完成同样的任务。

我们需要在我们的`HelloWorldScene.h`文件中包含新的引擎头文件，如下所示：

```java
#include "audio/include/AudioEngine.h"
```

让我们在`HelloWorld.cpp`实现文件中包含以下代码行，以便我们可以直接调用`AudioEngine`类，而无需每次使用时都引用其命名空间：

```java
using namespace cocos2d::experimental;
```

现在，让我们按照以下方式在我们的实现文件中编写`initAudioNewEngine`方法的代码：

```java
void HelloWorld::initAudioNewEngine()
{   
   if(AudioEngine::lazyInit())
   {
      auto musicId = AudioEngine::play2d("music.mp3");
      AudioEngine::setVolume(musicId, 0.25f);
      CCLOG("Audio initialized successfully");

   }else
   {
      log("Error while initializing new audio engine");
   }   
}
```

与使用单例实例的`CocosDenshion`不同，新音频引擎的所有方法都是静态声明的。

从前面的代码清单中我们可以看到，在调用`play2d`方法之前，我们调用了`lazyInit`方法。尽管`play2d`内部调用了`lazyInit`方法，但我们希望尽快知道我们的 Android 系统是否能够播放音频并采取行动。请注意，当`play2d`方法返回`AudioEngine::INVALID_AUDIO_ID`值时，您还需要找出音频初始化是否出现了问题。

每次我们通过调用`play2d`方法播放任意声音时，它都会返回一个唯一的递增的基于零的`audioID`索引，我们将保存它，这样每次我们想要对该特定音频实例执行特定操作时，比如更改音量、移动到特定位置、停止、暂停或恢复，我们都可以引用它。

新音频引擎的一个缺点是它仍然支持有限的音频格式。它目前不支持`.wav`文件。因此，为了播放`uh.wav`声音，我们将它转换为 mp3，然后在`onCollision`方法中通过如下调用`play2d`来播放：

```java
AudioEngine::stopAll();
AudioEngine::play2d("uh.mp3");
```

我们在本章提供的代码资源存档中包含了新的`uh.mp3`音频文件。

对于我们的游戏，我们将实施两种方案；传统的`CocosDenshion`引擎，这是最成熟的音频引擎，为我们提供了所需的基本功能，比如播放音效和背景音乐；以及新引擎中的相同音频功能。

## 新音频引擎中包含的新功能

`play2d`方法被重载，以便我们可以指定是否希望声音循环播放、初始音量以及我们希望应用的声音配置文件。`AudioProfile`类是 Cocos2d-x 框架的一部分，它只有三个属性：`name`，不能为空；`maxInstances`，将定义将同时播放多少个声音；以及`minDelay`，它是一个`double`数据类型，将指定声音之间的最小延迟。

新音频引擎具有的另一个功能是，通过调用`setCurrentTime`方法并传递`audioID`方法和以秒为单位的自定义位置（由`float`表示）来从自定义位置播放音频。

在新音频引擎中，您可以指定在给定音频实例播放完成时您希望调用的函数。这可以通过调用`setFinishCallback`方法来实现。

每次播放音频时，它都会被缓存，因此无需再次从文件系统中读取。如果我们想要释放一些资源，可以调用`uncacheAll`方法来移除音频引擎内部用于回放音频的所有缓冲区，或者可以通过调用`uncache`方法并指定要移除的文件系统中的文件路径来从缓存中移除任何特定的音频。

本节的目的是让您了解另一个处于实验阶段的音频引擎，如果`CocosDenshion`没有您想要添加到游戏中的任何音频功能，那么您应该检查另一个音频引擎，看看它是否具备您所需的功能。

### 注意

新的音频引擎可以在 Mac OS、iOS 和 win-32 平台上同时播放多达 32 个声音，但在 Android 上只能同时播放多达 24 个声音。

# 向我们的游戏添加静音按钮

在本章结束之前，我们将在游戏中添加一个静音按钮，这样我们就可以通过一次触摸将音效和背景音乐音量设置为零。

为了实现这一点，我们将在`HelloWorld`类中添加两个方法；一个用于初始化按钮，另一个用于实际静音所有声音。

为了实现这一点，我们将在`HelloWorldScene.h`头文件的私有部分添加以下几行：

```java
int _musicId;
cocos2d::MenuItemImage* _muteItem;
cocos2d::MenuItemImage* _unmuteItem;
void initMuteButton();
void muteCallback(cocos2d::Ref* pSender);
```

现在，我们将以下`initMuteButton`实现代码添加到`HelloWorldScene.cpp`文件中：

```java
void HelloWorld::initMuteButton()
{
   _muteItem = MenuItemImage::create("mute.png", "mute.png", CC_CALLBACK_1(HelloWorld::muteCallback, this));    

   _muteItem->setPosition(Vec2(_visibleSize.width - _muteItem-  >getContentSize().width/2 ,
   _visibleSize.height - _muteItem->getContentSize(). height / 2));
   _unmuteItem = MenuItemImage::create("unmute.png", "unmute.png", CC_CALLBACK_1(HelloWorld::muteCallback, this));    

   _unmuteItem->setPosition(Vec2(_visibleSize.width - _unmuteItem- >getContentSize().width/2 , _visibleSize.height - _unmuteItem->getContentSize().height /2));
   _unmuteItem -> setVisible(false);

   auto menu = Menu::create(_muteItem, _unmuteItem , nullptr);
   menu->setPosition(Vec2::ZERO);
   this->addChild(menu, 1);
}
```

如您所见，我们刚刚创建了一个新的菜单，我们在其中添加了两个按钮，一个用于静音游戏，另一个不可见用于取消静音。我们将这些分别存储在成员变量中，这样我们就可以通过在以下代码清单中声明的`muteCallback`方法访问它们：

```java
void HelloWorld::muteCallback(cocos2d::Ref* pSender)
{   
   if(_muteItem -> isVisible())
   {

      //CocosDenshion
      //SimpleAudioEngine::getInstance()->setBackgroundMusicVolume(0);
      AudioEngine::setVolume(_musicId, 0);
   }else
   {   
      //SimpleAudioEngine::getInstance()->setBackgroundMusicVolume(1);
      AudioEngine::setVolume(_musicId, 1);
   }

   _muteItem->setVisible(!_muteItem->isVisible());
   _unmuteItem->setVisible(!_muteItem->isVisible());
}
```

在这里，我们基本上只是判断`_muteItem`菜单项是否可见。如果可见，则通过使用新的音频引擎`CocosDenshion`将音量设置为零，否则将音量设置为最大值，即一。在任何一种情况下，都要改变静音和取消静音菜单项的实际可见值。

我们可以在以下屏幕截图中看到最终结果：

![向我们的游戏添加静音按钮](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_06_01.jpg)

# 把所有内容放在一起

在我们添加了将`sounds`文件夹包含在`resources`路径中的行之后，我们的`AppDelegate.cpp`实现文件中的`applicationDidFinishLaunching`方法如下所示：

```java
bool AppDelegate::applicationDidFinishLaunching() {
    auto director = Director::getInstance();
    // OpenGL initialization done by cocos project creation script
    auto glview = director->getOpenGLView();
    if(!glview) {
    glview = GLViewImpl::create("Happy Bunny");
    glview->setFrameSize(480, 800);
    director->setOpenGLView(glview);
   }

   Size screenSize = glview->getFrameSize();
   Size designSize(768, 1280);
   std::vector<std::string> searchPaths;   
 searchPaths.push_back("sounds");

   if (screenSize.height > 800){
      //High Resolution
      searchPaths.push_back("images/high");
      director->setContentScaleFactor(1280.0f / designSize.height);
   }
   else if (screenSize.height > 600){
      //Mid resolution
      searchPaths.push_back("images/mid");
      director->setContentScaleFactor(800.0f / designSize.height);
   }
   else{
      //Low resolution
      searchPaths.push_back("images/low");
      director->setContentScaleFactor(320.0f / designSize.height);
   }
   FileUtils::getInstance()->setSearchPaths(searchPaths);
   glview->setDesignResolutionSize(designSize.width, designSize. height, ResolutionPolicy::EXACT_FIT);
   auto scene = HelloWorld::createScene();
   director->runWithScene(scene);
   return true;
}
```

下面的代码清单显示了我们在本章中进行更改后`HelloWorldScene.h`头文件的样子：

```java
#ifndef __HELLOWORLD_SCENE_H__
#define __HELLOWORLD_SCENE_H__

#include "cocos2d.h"
#include "PauseScene.h"
#include "GameOverScene.h"

class HelloWorld : public cocos2d::Layer
{
public:
    static cocos2d::Scene* createScene();
    virtual bool init();
    CREATE_FUNC(HelloWorld);
private:
   cocos2d::Director *_director;
   cocos2d::Size _visibleSize;   
   cocos2d::Sprite* _sprBomb;
   cocos2d::Sprite* _sprPlayer;   
   cocos2d::MenuItemImage* _muteItem;
   cocos2d::MenuItemImage* _unmuteItem;   
   int _score;
   int _musicId;
   void initPhysics();
   void pauseCallback(cocos2d::Ref* pSender);
   void muteCallback(cocos2d::Ref* pSender);
   bool onCollision(cocos2d::PhysicsContact& contact);
   void setPhysicsBody(cocos2d::Sprite* sprite);
   void initTouch();
   void movePlayerByTouch(cocos2d::Touch* touch, cocos2d::Event* event);
   void movePlayerIfPossible(float newX);
   void movePlayerByAccelerometer(cocos2d::Acceleration* acceleration, cocos2d::Event* event);
   void initAccelerometer();
   void initBackButtonListener();
   void onKeyPressed(cocos2d::EventKeyboard::KeyCode keyCode, cocos2d::Event* event);
   void updateScore(float dt);
   void addBombs(float dt);   
   void initAudio();
   void initAudioNewEngine();
   void initMuteButton();
};

#endif // __HELLOWORLD_SCENE_H__
```

最后，在添加了音频管理代码之后，我们的`HelloWorldScene.cpp`实现文件如下所示：

```java
#include "HelloWorldScene.h"#include "SimpleAudioEngine.h"
#include "audio/include/AudioEngine.h"
#include "../cocos2d/cocos/platform/android/jni/Java_org_cocos2dx_lib_Cocos2dxHelper.h"

USING_NS_CC;
using namespace CocosDenshion;
using namespace cocos2d::experimental;

Scene* HelloWorld::createScene()
{
  //no changes here
}

// physics code …

// event handling code …
```

在以下方法中，我们将通过使用新的音频引擎来初始化音频。注意，我们会将音频实例的背景音乐的 ID 存储在`_musicId`整型成员变量中：

```java
void HelloWorld::initAudioNewEngine()
{   
   if(AudioEngine::lazyInit())
   {      
      _musicId = AudioEngine::play2d("music.mp3");
      AudioEngine::setVolume(_musicId, 1);      
      AudioEngine::setLoop(_musicId,true);      
      CCLOG("Audio initialized successfully");
   }else
   {
      CCLOG("Error while initializing new audio engine");
   }   
}
```

在这里，我们执行了与上一个方法中相同的初始化工作，但现在我们是使用`CocosDenshion`音频引擎来完成：

```java
void HelloWorld::initAudio()
{
   SimpleAudioEngine::getInstance()->playBackgroundMusic("music. mp3",true);   
   SimpleAudioEngine::getInstance()->preloadEffect("uh.wav");   
   SimpleAudioEngine::getInstance()->setBackgroundMusicVolume(1.0f);
}
```

在以下方法中，我们创建了一个简单的菜单，以展示静音和取消静音游戏的选项。这里我们将静音和取消静音的精灵存储在对应的成员变量中，以便我们可以在`muteCallback`方法中稍后访问它们，并操作它们的`visibility`属性：

```java
void HelloWorld::initMuteButton()
{
   _sprMute = Sprite::create("mute.png");
   _sprUnmute = Sprite::create("unmute.png");
   _muteItem = MenuItemImage::create("mute.png", "mute.png", CC_CALLBACK_1(HelloWorld::muteCallback, this));    
   _muteItem->setPosition(Vec2(_visibleSize.width - _muteItem- >getContentSize().width/2 ,
   _visibleSize.height - _muteItem->getContentSize().height / 2));
   _unmuteItem = MenuItemImage::create("unmute.png", "unmute.png", CC_CALLBACK_1(HelloWorld::muteCallback, this));    
   _unmuteItem->setPosition(Vec2(_visibleSize.width - _unmuteItem->getContentSize().width/2 ,
   _visibleSize.height - _unmuteItem->getContentSize(). height /2));
   _unmuteItem -> setVisible(false);
   auto menu = Menu::create(_muteItem, _unmuteItem , nullptr);
    menu->setPosition(Vec2::ZERO);
    this->addChild(menu, 1);

}
```

以下方法将在每次按下静音或取消静音菜单项时被调用，在这个方法中，我们只需将音量设置为 0，并根据触摸的选项显示静音或取消静音按钮：

```java
void HelloWorld::muteCallback(cocos2d::Ref* pSender)
{   
   if(_muteItem -> isVisible())
   {
      //CocosDenshion
      //SimpleAudioEngine::getInstance()->setBackgroundMusicVolume(0);
      AudioEngine::setVolume(_musicId, 0);   

   }else
   {   
      //SimpleAudioEngine::getInstance()->setBackgroundMusicVolume(1);
      AudioEngine::setVolume(_musicId, 1);
   }

   _muteItem->setVisible(!_muteItem->isVisible());
   _unmuteItem->setVisible(!_muteItem->isVisible());
}
```

我们对`init`方法做的唯一修改是在其最后添加了对`initMuteButton();`方法的调用：

```java
bool HelloWorld::init()
{
    if ( !Layer::init() )
    {
        return false;
    }
   _score = 0;
   _director = Director::getInstance();
   _visibleSize = _director->getVisibleSize();
   auto origin = _director->getVisibleOrigin();
   auto closeItem = MenuItemImage::create("pause.png", "pause_pressed.png", CC_CALLBACK_1(HelloWorld::pauseCallback, this));
   closeItem->setPosition(Vec2(_visibleSize.width - closeItem->getContentSize().width/2, closeItem->getContentSize().height/2));
   auto menu = Menu::create(closeItem, nullptr);
   menu->setPosition(Vec2::ZERO);
   this->addChild(menu, 1);
   _sprBomb = Sprite::create("bomb.png");   
   _sprBomb->setPosition(_visibleSize.width / 2, _visibleSize.height +_sprBomb->getContentSize().height/2);
   this->addChild(_sprBomb,1);
   auto bg = Sprite::create("background.png");
   bg->setAnchorPoint(Vec2());
   bg->setPosition(0,0);
   this->addChild(bg, -1);
   _sprPlayer = Sprite::create("player.png");   
   _sprPlayer->setPosition(_visibleSize.width / 2, _visibleSize.height* 0.23);
   setPhysicsBody(_sprPlayer);
   this->addChild(_sprPlayer, 0);
   //Animations
   Vector<SpriteFrame*> frames;
   Size playerSize = _sprPlayer->getContentSize();
   frames.pushBack(SpriteFrame::create("player.png", Rect(0, 0, playerSize.width, playerSize.height)));
   frames.pushBack(SpriteFrame::create("player2.png", Rect(0, 0, playerSize.width, playerSize.height)));
   auto animation = Animation::createWithSpriteFrames(frames,0.2f);
   auto animate = Animate::create(animation);
   _sprPlayer->runAction(RepeatForever::create(animate));      
   setPhysicsBody(_sprBomb);   
   initPhysics();   
   _sprBomb->getPhysicsBody()->setVelocity(Vect(0,-100));   
   initTouch();
   initAccelerometer();   
   #if (CC_TARGET_PLATFORM == CC_PLATFORM_ANDROID)
   setKeepScreenOnJni(true);
   #endif
   initBackButtonListener();
   schedule(CC_SCHEDULE_SELECTOR(HelloWorld::updateScore), 3.0f);
   schedule(CC_SCHEDULE_SELECTOR(HelloWorld::addBombs), 8.0f);
   initAudioNewEngine();
 initMuteButton();
   return true;
}
```

如你所见，尽管我们使用了新的音频引擎来播放声音，但我们展示了使用传统`CocosDenshion`音频引擎所需的所有代码。为了启用`CocosDenshion`实现，你只需在`HelloWorld.cpp`文件的`init`方法的底部调用`initAudio`方法，而不是调用`initAudioNewEngine`方法，最后，你还需要在`onCollision`方法中移除`CocosDenshion`实现代码的注释斜杠，并注释掉新的音频引擎播放代码。

# 总结

在本章中，我们通过使用 Cocos2d-x 框架捆绑的两个音频引擎，以非常简单的方式为我们的游戏添加了背景音乐和音效。

在下一章中，我们将介绍如何将粒子系统添加到我们的游戏中，以模拟每次炸弹击中`player`精灵时的更真实的爆炸效果。


# 第七章：创建粒子系统

通过使用 Cocos2d-x 框架内置的粒子系统，您可以轻松模拟火、烟、爆炸、雪和雨。本章将教您如何创建这里提到的效果，并教您如何自定义它们。

本章将涵盖以下主题：

+   创建 Cocos2d-x 对象的集合

+   将粒子系统添加到我们的游戏中

+   配置粒子系统

+   创建自定义粒子系统

# 创建 Cocos2d-x 对象的集合

我们将向游戏中添加一个粒子系统，以模拟每次玩家触摸炸弹时的爆炸效果。为了做到这一点，我们将使用 Cocos2d-x 框架中的`Vector`类来创建游戏中创建的所有炸弹对象的集合，这样当玩家触摸屏幕时，我们将遍历这个集合以验证玩家是否触摸到了任何炸弹。

如果玩家触摸到任何炸弹，我们将要：

+   在炸弹精灵所在位置显示爆炸效果

+   使炸弹不可见

+   使用继承的`removeChild`方法从屏幕上移除炸弹，最后

+   从集合中移除炸弹对象，这样下次我们遍历向量时，就会忽略它

为此，我们将炸弹集合按照以下方式添加到我们的`HelloWorldScene.h`定义文件中：

```java
cocos2d::Vector<cocos2d::Sprite*> _bombs;
```

请注意，我们指定要使用`cocos2d`命名空间中捆绑的`Vector`类，这样编译器可以清楚地知道我们是指向框架内置的集合类，而不是`std`命名空间中的`Vector`类。尽管可以使用`std`命名空间中的`Vector`类，但位于框架中的类是针对在 Cocos2d-x 对象集合中使用而优化的。

### 注意

Cocos2d-x 3.0 中引入的`Vector`类使用 C++标准来表示对象集合，与使用 Objective-C 容器类来建模 Cocos2d-x 对象集合的已弃用的`CCArray`类相对。这个新类处理 Cocos2d-x 中用于内存管理的引用计数机制，它还添加了`std::vector`中不存在的功能，如`random`、`contains`和`equals`方法。

只有在需要将实例作为参数传递给预期数据类型的 Cocos2d-x API 类函数时，才应使用`std::vector`实例，例如`FileUtils`类中的`setSearchPaths`方法。

现在，让我们转到位于`HelloWorldScene.cpp`实现文件中的`init`方法，在声明持有第一个炸弹精灵引用的`_sprBomb`变量旁边，我们将按照以下方式将此引用添加到我们的新`_bombs`集合中：

```java
_bombs.pushBack(_sprBomb);
```

现在，让我们回到在我们之前章节中创建的 `addBombs` 方法，以向我们的游戏中添加更多炸弹。在这个方法中，我们将把游戏中场景中生成的每个炸弹添加到 `_bombs` 集合中，如下所示：

```java
void HelloWorld::addBombs(float dt)
{
Sprite* bomb = nullptr;
for(int i = 0; i < 3; i++){
  bomb = Sprite::create("bomb.png");
  bomb->setPosition(CCRANDOM_0_1() * visibleSize.width, visibleSize.height + bomb->getContentSize().height/2);
  this->addChild(bomb,1);
  setPhysicsBody(bomb);
  bomb->getPhysicsBody()->setVelocity(Vect(0, ( (CCRANDOM_0_1() + 0.2f) * -250) ));
  _bombs.pushBack(bomb);
}
}
```

## 爆炸的炸弹

我们希望当我们触摸炸弹时它们能爆炸。为了实现这一点，我们将创建我们的 `explodeBombs` 方法。在 `HelloWorldScene.h` 头文件中，我们将按以下方式编写声明：

```java
bool explodeBombs(cocos2d::Touch* touch, cocos2d::Event* event);
```

现在，我们将在 `HelloWorldScene.cpp` 实现文件中编写方法体；如前所述，每次玩家触摸屏幕时，我们可以验证触摸的位置并与每个炸弹的位置进行比较。如果发现任何交集，那么被触摸的炸弹将会消失。目前，我们还不打算添加任何粒子系统，我们将在后面的章节中做这件事：

```java
bool HelloWorld::explodeBombs(cocos2d::Touch* touch, cocos2d::Event* event)
{
Vec2 touchLocation = touch->getLocation();
cocos2d::Vector<cocos2d::Sprite*> toErase;
for(auto bomb : _bombs){
  if(bomb->getBoundingBox().containsPoint(touchLocation)){
    bomb->setVisible(false);
    this->removeChild(bomb);
    toErase.pushBack(bomb);
  }
}

for(auto bomb : toErase){
  _bombs.eraseObject(bomb);
}
return true;
}
```

请注意，我们创建了一个另一个向量，用于添加所有被用户触摸的炸弹，然后在另一个循环中将它们从 `_bombs` 集合中移除。我们这样做而不是直接从第一个循环中移除对象的原因是，这将会导致运行时错误。这是因为我们不能在遍历集合的同时对单一集合进行并发修改，即我们不能在遍历集合时从中移除一个项目。如果我们这样做，那么我们将得到一个运行时错误。

### 注意

`Vector` 类是在 Cocos2d-x 3.0 中引入的。它替代了在 Cocos2d-x 2.x 中使用的 `CCArray` 类。我们可以使用 C++11 的 for each 特性遍历 `Vector` 实例；因此，在 Cocos2d-x 2.x 中用于遍历 Cocos2d-x 对象的 `CCARRAY_FOREACH` 宏不再需要。

现在，我们将在 `HelloWorldScene.cpp` 实现文件中的 `initTouch` 方法中通过以下更改向我们的触摸监听器添加一个回调到 `onTouchBegan` 属性：

```java
void HelloWorld::initTouch()
{
  auto listener = EventListenerTouchOneByOne::create();
  listener->onTouchBegan = CC_CALLBACK_2(HelloWorld::explodeBombs,this);
  listener->onTouchMoved = CC_CALLBACK_2(HelloWorld::movePlayerByTouch,this);
  listener->onTouchEnded = ={};
  _eventDispatcher->addEventListenerWithSceneGraphPriority(listener, this);
}
```

这样就完成了，现在当你触摸炸弹时，它们将会消失。在下一节中，我们将添加一个爆炸效果，以增强我们游戏的外观。

# 向我们的游戏中添加粒子系统

Cocos2d-x 有内置的类，允许你通过显示大量称为粒子的微小图形对象来渲染最常见的视觉效果，如爆炸、火焰、烟花、烟雾和雨等。

实现起来非常简单。让我们通过简单地向我们的 `explodeBombs` 方法中添加以下行来添加一个默认的爆炸效果：

```java
bool HelloWorld::explodeBombs(cocos2d::Touch* touch, cocos2d::Event* event){
  Vec2 touchLocation = touch->getLocation();
  cocos2d::Vector<cocos2d::Sprite*> toErase;
  for(auto bomb : _bombs){
    if(bomb->getBoundingBox().containsPoint(touchLocation)){
      auto explosion = ParticleExplosion::create();
      explosion->setPosition(bomb->getPosition());
      this->addChild(explosion);
      bomb->setVisible(false);
      this->removeChild(bomb);
      toErase.pushBack(bomb);
    }
  }
  for(auto bomb : toErase){
    _bombs.eraseObject(bomb);
  }
  return true;
}
```

![向我们的游戏中添加粒子系统](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_07_01.jpg)

你可以通过更改前一段代码中突出显示的第一行中的粒子类名称，尝试引擎中嵌入的其他粒子系统，可以使用以下类名称：`ParticleFireworks`、`ParticleFire`、`ParticleRain`、`ParticleSnow`、`ParticleSmoke`、`ParticleSpiral`、`ParticleMeteor` 和 `ParticleGalaxy`。

# 配置粒子系统

在上一节中，我们仅通过添加三行代码就创建了一个逼真的爆炸效果。我们可以自定义粒子系统的许多参数。例如，我们可以通过修改生命属性来调整我们希望粒子系统扩展的程度。

我们还可以通过设置`startSize`属性和`endSize`属性来调整粒子系统在开始时的大小以及我们希望它在结束时的大小。例如，如果我们想模拟火箭的涡轮，那么我们可以配置发射器从小尺寸开始，到大尺寸结束。

我们可以通过修改角度属性来调整粒子的移动角度。你可以为你的粒子系统分配随机角度，使其看起来更加真实。

粒子系统可以有两种模式，半径模式和重力模式。最常见的粒子系统使用重力模式，我们可以参数化重力、速度、径向和切向加速度。这意味着发射器创建的粒子会受到一个称为重力的力的吸引，我们可以自定义它们的水平和垂直分量。半径模式具有径向运动和旋转，因此这种模式的粒子系统将以螺旋形旋转。

通过`totalParticles`属性也可以改变粒子的总数。粒子数量越多，粒子系统看起来越浓密，但要注意，渲染的粒子数量也会影响运行性能。举个例子，默认的爆炸粒子系统有 700 个粒子，而烟雾效果有 200 个粒子。

### 注意事项

你可以通过调用发射器实例中的`set<属性名>`方法来修改本节中提到的属性。例如，如果你想修改系统的总粒子数，那么就调用`setTotalParticles`方法。

在下面的代码列表中，我们将修改粒子系统的总粒子数、速度和生命周期：

```java
bool HelloWorld::explodeBombs(cocos2d::Touch* touch, cocos2d::Event* event){
  Vec2 touchLocation = touch->getLocation();
  cocos2d::Vector<cocos2d::Sprite*> toErase;
  for(auto bomb : _bombs){
    if(bomb->getBoundingBox().containsPoint(touchLocation)){
      auto explosion = ParticleExplosion::create();
      explosion->setDuration(0.25f);
      AudioEngine::play2d("bomb.mp3");
      explosion->setPosition(bomb->getPosition());
      this->addChild(explosion);
      explosion->setTotalParticles(800);
      explosion->setSpeed(3.5f);
      explosion->setLife(300.0f);
      bomb->setVisible(false);
      this->removeChild(bomb);
      toErase.pushBack(bomb);
    }
  }

  for(auto bomb : toErase){
    _bombs.eraseObject(bomb);
  }
  return true;
}
```

![配置粒子系统](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_07_02.jpg)

# 创建自定义粒子系统

到目前为止，我们已经尝试了 Cocos2d-x 框架中捆绑的所有粒子系统，但在我们作为游戏开发者的旅程中，将有很多情况需要我们创建自己的粒子系统。

有一些工具允许我们以非常图形化的方式创建和调整粒子系统的属性。这使我们能够创建**所见即所得（WYSIWYG）**类型的粒子系统。

创建粒子系统最常用的应用程序，在 Cocos2d-x 官方文档中多次提到，名为 Particle Designer。目前它仅适用于 Mac OS，并且你需要购买许可证才能将粒子系统导出为 plist 文件。你可以从以下链接免费下载并试用：[`71squared.com/particledesigner`](https://71squared.com/particledesigner)。Particle Designer 如下截图所示：

![创建自定义粒子系统](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_07_03.jpg)

你也可以通过使用以下免费提供的网页应用程序，以图形化的方式创建你的粒子系统：[`www.particle2dx.com/`](http://www.particle2dx.com/)。

![创建自定义粒子系统](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_07_04.jpg)

你还可以使用 V-Play 粒子编辑器，它可以在 Windows、Android、iOS 和 Mac 平台上免费下载和使用。这些工具可以从以下链接获得：[`games.v-play.net/particleeditor`](http://games.v-play.net/particleeditor)。

![创建自定义粒子系统](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_07_05.jpg)

使用前面提到的任何工具，你可以调整粒子系统的属性，比如最大粒子数、持续时间、生命周期、发射速率和角度等，并将其保存为 plist 文件。

我们创建了自己的粒子系统，并将其导出为 plist 文件。这个 plist 文件包含在本章源代码的代码归档中。我们将这个 plist 文件放置在一个新建的文件夹中，该文件夹位于`Resources`目录下的`particles`目录。

由于我们的 plist 文件不在`Resources`目录的根目录下，我们需要在`AppDelegate`类的`applicationDidFinishLaunching`方法中添加`particles`目录到搜索路径，只需在添加`sounds`目录到`searchPaths`之后加入以下代码行：

```java
searchPaths.push_back("particles");
```

以下代码展示了如何使用`ParticleSystemQuad`类显示我们的自定义粒子系统，并通过其`create`静态方法传递由工具生成的 plist 文件的名称作为参数：

```java
bool HelloWorld::explodeBombs(cocos2d::Touch* touch, cocos2d::Event* event){
  Vec2 touchLocation = touch->getLocation();
  cocos2d::Vector<cocos2d::Sprite*> toErase;
  for(auto bomb : _bombs){
    if(bomb->getBoundingBox().containsPoint(touchLocation)){
      AudioEngine::play2d("bomb.mp3");
 auto explosion = ParticleSystemQuad::create("explosion.plist");
      explosion->setPosition(bomb->getPosition());
      this->addChild(explosion);
      bomb->setVisible(false);
      this->removeChild(bomb);
      toErase.pushBack(bomb);
    }
  }
  for(auto bomb : toErase){
    _bombs.eraseObject(bomb);
  }
  return true;
}
```

如你所见，我们还添加了一行代码，以便每次炸弹接触到玩家精灵时播放音效，从而增加更真实的效果。这个 MP3 文件已包含在本章提供的代码中。

![创建自定义粒子系统](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_07_06.jpg)

# 将所有内容整合到一起

在本章中，我们为游戏添加了粒子系统，使得玩家每次触碰炸弹都能产生逼真的爆炸效果。为了实现这一目标，我们对`HelloWorldScene.h`头文件和`HelloWorldScene.cpp`实现文件进行了修改。

在本章修改后，我们的`HelloWorldScene.h`头文件如下所示：

```java
#ifndef __HELLOWORLD_SCENE_H__
#define __HELLOWORLD_SCENE_H__
#include "cocos2d.h"
#include "PauseScene.h"
#include "GameOverScene.h"

class HelloWorld : public cocos2d::Layer{
public:
  static cocos2d::Scene* createScene();
  virtual bool init();
  CREATE_FUNC(HelloWorld);
private:
  cocos2d::Director *_director;
  cocos2d::Size _visibleSize;
  cocos2d::Sprite* _sprBomb;
  cocos2d::Sprite* _sprPlayer;
  cocos2d::Vector<cocos2d::Sprite*> _bombs;
  cocos2d::MenuItemImage* _muteItem;
  cocos2d::MenuItemImage* _unmuteItem;
  int _score;
  int _musicId;
  void initPhysics();
  void pauseCallback(cocos2d::Ref* pSender);
  void muteCallback(cocos2d::Ref* pSender);
  bool onCollision(cocos2d::PhysicsContact& contact);
  void setPhysicsBody(cocos2d::Sprite* sprite);
  void initTouch();
  void movePlayerByTouch(cocos2d::Touch* touch, cocos2d::Event* event);
  void movePlayerIfPossible(float newX);
  bool explodeBombs(cocos2d::Touch* touch, cocos2d::Event* event);
  void movePlayerByAccelerometer(cocos2d::Acceleration* acceleration, cocos2d::Event* event);
  void initAccelerometer();
  void initBackButtonListener();
  void onKeyPressed(cocos2d::EventKeyboard::KeyCode keyCode, cocos2d::Event* event);
  void updateScore(float dt);
  void addBombs(float dt);
  void initAudio();
  void initAudioNewEngine();
  void initMuteButton();
};

#endif // __HELLOWORLD_SCENE_H__
```

最后，以下代码展示了在本章中我们修改后的`HelloWorldScene.cpp`实现文件的样子：

```java
#include "HelloWorldScene.h"
#include "SimpleAudioEngine.h"
#include "audio/include/AudioEngine.h"
#include "../cocos2d/cocos/platform/android/jni/Java_org_cocos2dx_lib_Cocos2dxHelper.h"

USING_NS_CC;
using namespace CocosDenshion;
using namespace cocos2d::experimental;
//Create scene code …
//User input event handling code
```

在以下方法中，我们首先验证用户是否触摸到了炸弹，如果用户触摸到了，那么将在触摸时刻炸弹所在位置渲染一个爆炸粒子系统。

```java
bool HelloWorld::explodeBombs(cocos2d::Touch* touch, cocos2d::Event* event){
  Vec2 touchLocation = touch->getLocation();
  cocos2d::Vector<cocos2d::Sprite*> toErase;
  for(auto bomb : _bombs){
    if(bomb->getBoundingBox().containsPoint(touchLocation)){
      AudioEngine::play2d("bomb.mp3");
      auto explosion = ParticleSystemQuad::create("explosion.plist");
      explosion->setPosition(bomb->getPosition());
      this->addChild(explosion);
      bomb->setVisible(false);
      this->removeChild(bomb);
      toErase.pushBack(bomb);
    }
  }
  for(auto bomb : toErase){
    _bombs.eraseObject(bomb);
  }
  return true;
}
```

在以下方法中，我们添加了一个事件监听器，每次用户触摸屏幕时都会触发，以验证是否触摸到了炸弹：

```java
void HelloWorld::initTouch(){
  auto listener = EventListenerTouchOneByOne::create();
  listener->onTouchBegan = CC_CALLBACK_2(HelloWorld::explodeBombs,this);
  listener->onTouchMoved = CC_CALLBACK_2(HelloWorld::movePlayerByTouch,this);
  listener->onTouchEnded = ={};
  _eventDispatcher->addEventListenerWithSceneGraphPriority(listener, this);
}
```

在以下方法中，我们通过使用其`pushBack`方法，将新产生的炸弹添加到我们的新的`cocos2d:Vector`集合中：

```java
void HelloWorld::addBombs(float dt)
{
  Sprite* bomb = nullptr;
  for(int i = 0; i < 3; i++){
    bomb = Sprite::create("bomb.png");
    bomb->setPosition(CCRANDOM_0_1() * visibleSize.width, visibleSize.height + bomb->getContentSize().height/2);
    this->addChild(bomb,1);
    setPhysicsBody(bomb);
    bomb->getPhysicsBody()->setVelocity(Vect(0, ( (CCRANDOM_0_1() + 0.2f) * -250) ));
    _bombs.pushBack(bomb);
  }
}
```

现在我们来看看在本章修改后，我们的`init`方法长什么样子。注意，我们已经将初始化阶段创建的第一个炸弹添加到了新的`cocos2d:Vector _bombs`集合中。

```java
bool HelloWorld::init()
{
  if ( !Layer::init() ){
    return false;
  }
  _score = 0;
  _director = Director::getInstance();
  _visibleSize = _director->getVisibleSize();
  auto origin = _director->getVisibleOrigin();
  auto closeItem = MenuItemImage::create("pause.png", "pause_pressed.png", CC_CALLBACK_1(HelloWorld::pauseCallback, this));
  closeItem->setPosition(Vec2(_visibleSize.width - closeItem->getContentSize().width/2 , closeItem->getContentSize().height/2));
  auto menu = Menu::create(closeItem, nullptr);
  menu->setPosition(Vec2::ZERO);
  this->addChild(menu, 1);
  _sprBomb = Sprite::create("bomb.png");
  _sprBomb->setPosition(_visibleSize.width/2, _visibleSize.height + _sprBomb->getContentSize().height/2);
  this->addChild(_sprBomb,1);
  auto bg = Sprite::create("background.png");
  bg->setAnchorPoint(Vec2());
  bg->setPosition(0,0);
  this->addChild(bg, -1);
  _sprPlayer = Sprite::create("player.png");
  _sprPlayer->setPosition(_visibleSize.width/2, _visibleSize.height * 0.23);
  setPhysicsBody(_sprPlayer);

  this->addChild(_sprPlayer, 0);
  //Animations
  Vector<SpriteFrame*> frames;
  Size playerSize = _sprPlayer->getContentSize();
  frames.pushBack(SpriteFrame::create("player.png", Rect(0, 0, playerSize.width, playerSize.height)));
  frames.pushBack(SpriteFrame::create("player2.png", Rect(0, 0, playerSize.width, playerSize.height)));
  auto animation = Animation::createWithSpriteFrames(frames,0.2f);
  auto animate = Animate::create(animation);
  _sprPlayer->runAction(RepeatForever::create(animate));
  setPhysicsBody(_sprBomb);
  initPhysics();
  _sprBomb->getPhysicsBody()->setVelocity(Vect(0,-100));
  initTouch();
  initAccelerometer();
  #if (CC_TARGET_PLATFORM == CC_PLATFORM_ANDROID)
  setKeepScreenOnJni(true);
  #endif
  initBackButtonListener();
  schedule(CC_SCHEDULE_SELECTOR(HelloWorld::updateScore), 3.0f);
  schedule(CC_SCHEDULE_SELECTOR(HelloWorld::addBombs), 8.0f);
  initAudioNewEngine();
  initMuteButton();
  _bombs.pushBack(_sprBomb);
  return true;
}
```

# 总结

在本章中，我们学习了如何在游戏中使用粒子系统模拟真实的火焰、爆炸、雨雪，如何自定义它们，以及如何从零开始创建它们。我们还学习了如何使用 Cocos2d-x API 中捆绑的`Vector`类来创建 Cocos2d-x 对象的集合。

在下一章，我们将向您展示如何使用 Java Native Interface (JNI)向我们的游戏中添加 Android 原生代码。


# 第八章：添加原生 Java 代码

到目前为止，我们一直在使用 Cocos2d-x 游戏框架编写的编程语言（C++）来创建我们的游戏；然而，由 Google 编写的 Android API 仅在应用程序的 Java 层可用。在本章中，你将学习如何使用**Java Native Interface** (**JNI**)的能力，将我们的原生 C++代码与高端的 Java 核心进行通信。

本章节将涵盖以下主题：

+   理解 Cocos2d-x 在 Android 平台的架构

+   理解 JNI 的能力

+   向 Cocos2d-x 游戏中添加 Java 代码

+   通过插入 Java 代码向游戏中添加广告

# 理解 Cocos2d-x 在 Android 平台的架构（再次注意原文重复，不重复翻译）

在第一章，*设置你的开发环境*中，我们在安装构建 Cocos2d-x 框架所需的所有组件时，告诉你要下载并安装 Android **原生开发工具包** (**NDK**)，它允许我们使用 C++语言而非主流的 Java 技术核心来构建 Android 应用程序，Android API 就是用这种技术核心编写的。

当一个 Android 应用程序启动时，它会查看其`AndroidManisfest.xml`文件，寻找带有意图过滤器`android.intent.action.MAIN`的活动定义，然后运行 Java 类。以下列表展示了由 Cocos 新脚本生成的`AndroidManifest.xml`文件片段，其中指定了当 Android 应用程序启动时要启动的活动：

```java
<activity
   android:name="org.cocos2dx.cpp.AppActivity"
   android:configChanges="orientation"
   android:label="@string/app_name"
   android:screenOrientation="portrait"
   android:theme="@android:style/Theme.NoTitleBar.Fullscreen" >
   <intent-filter>
      <action android:name="android.intent.action.MAIN" />
      <category android:name="android.intent.category.LAUNCHER" />
   </intent-filter>
</activity>
```

Cocos2d-x 项目创建脚本已经创建了一个名为`AppActivity`的 Java 类，它位于`proj.android`目录下的`src`文件夹中的`org.cocos2dx.cpp` Java 包名中。这个类没有主体，并继承自`Cocos2dxActivity`类，正如我们可以在以下代码列表中欣赏到的那样：

```java
package org.cocos2dx.cpp;

import org.cocos2dx.lib.Cocos2dxActivity;

public class AppActivity extends Cocos2dxActivity {
}
```

`Cocos2dxActivity`类在其`onCreate`方法中加载原生 C++框架核心。

# 理解 JNI 的能力（请注意，这里原文有重复，根据注意事项，我不会重复翻译）

JNI 提供了 C++代码和 Java 代码之间的桥梁。Cocos2d-x 框架为我们提供了 JNI 助手，这使得集成 C++代码和 Java 代码变得更加容易。

`JniHelper` C++类有一个名为`getStaticMethodInfo`的方法。这个方法接收以下参数：一个`JniMethodInfo`对象来存储调用相应 Java 代码所需的所有数据，静态方法所在的类名，方法名以及它的签名。

为了找出 JNI 的方法签名，你可以使用`javap`命令：例如，如果我们想知道`AppActivity`类中包含的方法的签名，那么我们只需要打开一个控制台窗口，前往你的`proj.android\bin\classes`目录，并输入以下命令：

```java
SET CLASSPATH=.
javap -s org.cocos2dx.cpp.AppActivity

```

在这个特定情况下，你将收到如下自动为类创建的`null`构造函数的签名：

```java
Compiled from "AppActivity.java"
public class org.cocos2dx.cpp.AppActivity extends org.cocos2dx.lib.Cocos2dxActivity {
  public org.cocos2dx.cpp.AppActivity();
    Signature: ()V
}
```

然后，通过`JniMethodInfo`实例附加的`env`属性，我们可以调用一系列以`Call…`开头的对象方法来调用 Java 方法。在下一节我们将编写的代码中，我们将使用`CallStaticVoid`方法来调用一个不返回任何值的静态方法，顾名思义。请注意，如果你想传递一个 Java 字符串作为参数，那么你需要调用`env`属性的`NewStringUTF`方法，传递`const char*`，它将返回一个`jstring`实例，你可以用它来传递给一个接收字符串的 Java 方法，如下面的代码清单所示：

```java
JniMethodInfo method;
JniHelper::getStaticMethodInfo(method, CLASS_NAME,"showToast","(Ljava/lang/String;)V");
jstring stringMessage = method.env->NewStringUTF(message);
method.env->CallStaticVoidMethod(method.classID,  method.methodID, stringMessage);
```

最后，如果你在 C++代码中创建了`jstring`或其他任何 Java 抽象类的实例，那么在将值传递给 Java 核心之后，请确保删除这些实例，这样我们就不必在内存中保留不必要的引用。可以通过调用`JniMethodInfo`实例的`env`属性中的`DeleteLocalRef`方法，并传递你想移除的 Java 抽象引用来实现这一点：

```java
method.env->DeleteLocalRef(stringMessage);
```

本节介绍的概念将应用于下一节的代码清单。

# 将 Java 代码添加到 Cocos2d-x 游戏

现在，我们将创建一个简单的集成，将这两项技术结合起来，使我们的 Cocos2d-x C++游戏能够使用 Android Java API 显示提示框消息。

### 注意

安卓中的提示框（Toast）是一种弹出的消息，它会显示一段指定的时间，在这段时间内无法被隐藏。本节的最后附有提示框消息的截图，以供参考。

Cocos2d-x 运行在一个 Java 活动中，为了显示原生的 Android 提示框消息，我们将创建一个 Java 类，它将有一个名为`showToast`的静态方法。这个方法将接收一个字符串，并在提示框中显示它。为了访问 Cocos2d-x 游戏活动，我们将在该类中添加一个类型为`Activity`的静态属性，并在重写的`onCreate`方法中初始化它。然后，我们将创建一个公共的静态方法，这将允许我们从 Java 代码的任何地方访问这个实例。在这些修改之后，我们的`AppActivity` Java 类代码将如下所示：

```java
package org.cocos2dx.cpp;

import org.cocos2dx.lib.Cocos2dxActivity;
import android.app.Activity;
import android.os.Bundle;

public class AppActivity extends Cocos2dxActivity {
   private static Activity instance;
    @Override
    protected void onCreate(final Bundle savedInstanceState) {
       instance = this;
        super.onCreate(savedInstanceState);

    }
    public static Activity getInstance(){
       return instance;
    }
}
```

现在，让我们在`com.packtpub.jni`包内创建所提到的`JniFacade` Java 类，该类体内将只有一个接收字符串作为参数的静态 void 方法，然后如下所示在 UI 线程中以接收到的消息显示提示框：

```java
package com.packtpub.jni;

import org.cocos2dx.cpp.AppActivity;
import android.app.Activity;
import android.widget.Toast;

public class JniFacade {
   private static Activity activity = AppActivity.getInstance();

   public static void showToast(final String message) {
      activity.runOnUiThread(new Runnable() {         
         @Override
         public void run() {
            Toast.makeText(activity.getBaseContext(), message, Toast.   LENGTH_SHORT).show();   
         }
      });      
   }
}
```

既然我们已经有了 Java 端的代码，让我们将`JniBridge` C++类添加到我们的`classes`文件夹中。

在`JniBridge.h`头文件中，我们将编写以下内容：

```java
#ifndef __JNI_BRIDGE_H__
#define __JNI_BRIDGE_H__
#include "cocos2d.h"

class JniBridge
{
public:
   static void showToast(const char* message);
};

#endif
```

现在让我们创建实现文件`JniBridge.cpp`，在这里我们将调用名为`showToast`的静态 Java 方法，该方法接收一个字符串作为参数：

```java
#include "JniBridge.h"
#define CLASS_NAME "com/packtpub/jni/JniFacade"
#define METHOD_NAME "showToast"
#define PARAM_CODE "(Ljava/lang/String;)V"

USING_NS_CC;

void JniBridge::showToast(const char* message)
{
   JniMethodInfo method;
   JniHelper::getStaticMethodInfo(method, CLASS_NAME, METHOD_NAME, PARAM_CODE);
   jstring stringMessage = method.env->NewStringUTF(message);
    method.env->CallStaticVoidMethod(method.classID, method.methodID, stringMessage);
    method.env->DeleteLocalRef(stringMessage);
}
```

如我们所见，这里我们使用了 Cocos2d-x 框架中捆绑的`JniMethodInfo`结构和`JniHelper`类，以调用`showToast`方法，并向它发送 C++代码中的 c 字符串，该字符串被转换成了 Java 字符串。

现在让我们在我们的`HelloWorldScene.cpp`实现文件中包含`JniBridge.h`头文件，这样我们就可以从主场景类内部访问到 Java 代码的桥梁：

```java
#include "JniBridge.h"
```

现在在位于`HelloWorld.cpp`实现文件中的`init`方法末尾，我们将调用`showToast`静态方法，以便使用 Android Java API 显示一个原生提示消息，显示从我们的 C++代码发送的文本，如下所示：

```java
JniBridge::showToast("Hello Java");
```

这将产生以下结果：

![将 Java 代码添加到 Cocos2d-x 游戏](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_08_01.jpg)

正如我们从之前的截图中可以看出的，我们已经实现了从 C++游戏逻辑代码中显示原生 Java 提示消息的目标。

# 通过插入 Java 代码将广告添加到游戏中

在上一节中，我们通过使用 JNI，在我们的 C++游戏逻辑代码和 Android 应用的 Java 层之间创建了一个交互。在本节中，我们将修改我们的 Android 特定代码，以便在 Android 游戏中显示谷歌**AdMob**横幅。

### 注意

AdMob 是谷歌的一个平台，通过展示广告，它可以让你的应用实现盈利，同时它还具备分析工具和应用程序内购买的工具。

# 配置环境

为了显示谷歌 AdMob 横幅，我们需要将`Google Play Services`库添加到我们的项目中。为此，我们首先需要通过使用 Android SDK 管理器下载它及其依赖项，即 Android 支持库：

![配置环境](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_08_02.jpg)

成功下载**Google Play Services**及其依赖项后，你需要将 Android.support.v4 添加到你的项目中，因为 Google Play Services 库需要它。为此，我们将复制位于以下路径的`android-support-v4.jar`文件：`<ADT PATH>\sdk\extras\android\support\v4`到 Android 项目中的`libs`文件夹，然后我们通过在 Eclipse 的包资源管理器中右键点击项目，选择**构建路径**，然后点击**配置构建路径**，将其添加到我们的构建路径中。**Java 构建路径**配置窗口将出现，点击**添加 JARS…**按钮并在`libs`文件夹中添加`android-support-v4.jar`文件。

现在，我们将复制我们刚刚下载的 Google Play Services 代码。该代码现在位于`<ADT PATH>\sdk\extras\google\google_play_services`到我们的工作空间路径。您可以通过右键点击您的 Eclipse Java 项目，然后点击**属性**，最后选择左侧的**资源**选项来找出您的工作空间路径；在那里您将看到**位置**信息，如下面的截图所示：

![配置环境](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_08_03.jpg)

我们已经设置了依赖项，现在让我们通过导航到**文件** | **导入** | **Android** | **将现有 Android 代码导入工作空间** | **浏览…**来添加 Google Play Services 库。然后，浏览到您在上一步中复制 Google Play Services 的位置。取消选择除`google-play-services_lib`之外的所有项目，并点击**完成**：

![配置环境](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_08_04.jpg)

既然我们的工作空间中已经有了`google-play-services_lib`项目，让我们将其配置为 Cocos2d-x 游戏项目的库。为此，我们再次在包资源管理器中右键点击我们的项目，点击**属性**，在左侧窗格中选择**Android**部分，然后在屏幕底部的下方，我们将点击**添加…**按钮，以便将`google-play-services_lib`库添加到我们的 Eclipse 项目中，如下面的截图所示：

![配置环境](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_08_05.jpg)

现在我们已经准备就绪，可以进入下一部分，我们将使用刚刚添加的库来显示 Google AdMob 广告。

既然我们的 AdMob 横幅将显示在屏幕顶部，我们现在将把静音按钮移动到底部，这样就不会被横幅覆盖。我们将通过更改静音和取消静音按钮的位置来实现这一点。不再将屏幕高度减去静音精灵高度的一半作为其垂直位置，我们现在将其*y*组件设置为屏幕高度减去静音按钮高度的两倍，如下面的代码行所示，在`initMuteButton`方法中：

```java
   _muteItem->setPosition(Vec2(_visibleSize.width -  _muteItem->getContentSize().width/2 ,_visibleSize.height -  _muteItem->getContentSize().height * 2));
```

# 修改 Android 清单

在本节中，我们将修改 Android 清单，以便插入使用 Google Play Services 库所需的配置。

我们只需要添加两个代码片段，其中之一将紧邻打开的应用程序标签，指示正在使用的 Google Play Services 版本，如下面的代码列表所示：

```java
        <meta-data
            android:name="com.google.android.gms.version"
            android:value="@integer/google_play_services_version" />
```

我们将要添加的第二个代码片段是`AdActivity`声明，它将紧邻我们游戏活动的声明添加，以便我们的游戏能够识别 Google Play Services 库中的这个内置活动：

```java
       <activity
            android:name="com.google.android.gms.ads.AdActivity"
            android:configChanges="keyboard|keyboardHidden|orientation| screenLayout|uiMode|screenSize|smallestScreenSize" />
```

## 添加 Java 代码

既然我们已经配置了库并且修改了 Android 清单，广告库就可以使用了。我们将在`AppActivity`类中添加一个广告初始化方法，并在调用其超类的实现之后调用它。

为了以下示例，我们将使用一个示例 AdMob ID，您可以将其替换为自己的 ID。您可以在[`www.google.com/admob`](http://www.google.com/admob)找到有关如何创建自己的 AdMob ID 的更多信息。

```java
   private void initAdMob() {
      final String ADMOB_ID = "ca-app-pub-7870675803288590/4907722461";
      final AdView adView;
      final FrameLayout adViewLayout;

      FrameLayout.LayoutParams adParams = new FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT,
            FrameLayout.LayoutParams.WRAP_CONTENT);
      adParams.gravity = Gravity.TOP | Gravity.CENTER_HORIZONTAL;      

      AdRequest adRequest = new AdRequest.Builder().
            addTestDevice(AdRequest.DEVICE_ID_EMULATOR).
            addTestDevice("E8B4B73DC4CAD78DFCB44AF69E7B9EC4").build();

      adView = new AdView(this);
      adView.setAdSize(AdSize.SMART_BANNER);
      adView.setAdUnitId(ADMOB_ID);
      adView.setLayoutParams(adParams);
      adView.loadAd(adRequest);
      adViewLayout = new FrameLayout(this);
      adViewLayout.setLayoutParams(adParams);
      adView.setAdListener(new AdListener() {
            @Override
            public void onAdLoaded() {
              adViewLayout.addView(adView);
            }         
      });      
      this.addContentView(adViewLayout, adParams);
   }
```

与上一节相比，我们不使用 JNI，因为我们根本不与 C++代码交互；相反，我们修改了由`cocos`命令创建的 Android 活动，以便添加更多图形元素以查看在模板中定义的 OpenGL E 视图的另一侧。

我们只是以编程方式创建了一个帧布局，并向其中添加了一个`adView`实例；最后，我们将这个帧布局作为内容视图添加到游戏活动中，然后通过使用重力布局参数指定其期望的位置，这样我们就能够在屏幕顶部显示 Google 广告。请注意，您可以修改广告的位置，即您希望它显示的位置，只需修改布局参数即可。

请注意，在广告成功加载后，我们将`adView`添加到了我们的帧布局中。使用`AdListener`，如果您在广告完成启动之前添加`adView`实例，那么它将不会显示。

在将所有内容整合之后，这是我们的 Google AdMob 的样子：

![添加 Java 代码](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/bd-andr-gm-c2dx/img/B04193_08_06.jpg)

# 将所有内容整合在一起

我们已经实现了将核心 Java 代码嵌入到我们的 Cocos2d-x 游戏中的目标。现在我们将展示本章中所有修改过的游戏部分。

在这里，我们展示了从零开始创建的 C++ JNI 桥（`JniBridge.h`）的头文件：

```java
#ifndef __JNI_BRIDGE_H__
#define __JNI_BRIDGE_H__
#include "cocos2d.h"

class JniBridge
{
public:
   static void showToast(const char* message);
};

#endif
```

既然我们已经定义了我们的`JniBridge`的头文件，让我们编写实现文件（`JniBridge.cpp`）：

```java
#include "JniBridge.h"
#include "platform/android/jni/JniHelper.h"
#define CLASS_NAME "com/packtpub/jni/JniFacade"
#define METHOD_NAME "showToast"
#define PARAM_CODE "(Ljava/lang/String;)V"

USING_NS_CC;

void JniBridge::showToast(const char* message)
{
   JniMethodInfo method;
   JniHelper::getStaticMethodInfo(method, CLASS_NAME, METHOD_ NAME,PARAM_CODE);
   jstring stringMessage = method.env->NewStringUTF(message);
   method.env->CallStaticVoidMethod(method.classID, method.methodID, stringMessage);
   method.env->DeleteLocalRef(stringMessage);
}
```

现在让我们看看在包含了我们的`JniBridge`之后，我们的游戏玩法类头文件（`HelloWorldScene.h`）的样子：

```java
#ifndef __HELLOWORLD_SCENE_H__
#define __HELLOWORLD_SCENE_H__

#include "cocos2d.h"
#include "PauseScene.h"
#include "GameOverScene.h"
#include "JniBridge.h"

class HelloWorld : public cocos2d::Layer
{
public:
    static cocos2d::Scene* createScene();
    virtual bool init();
    void pauseCallback(cocos2d::Ref* pSender);
    CREATE_FUNC(HelloWorld);
private:
   cocos2d::Director *_director;
   cocos2d::Size visibleSize;   
   cocos2d::Sprite* _sprBomb;
   cocos2d::Sprite* _sprPlayer;   
   cocos2d::Vector<cocos2d::Sprite*> _bombs;
   cocos2d::MenuItemImage* _muteItem;
   cocos2d::MenuItemImage* _unmuteItem;
   int _score;   
   int _musicId;
   void initPhysics();
   bool onCollision(cocos2d::PhysicsContact& contact);
   void setPhysicsBody(cocos2d::Sprite* sprite);
   void initTouch();
   void movePlayerByTouch(cocos2d::Touch* touch,  cocos2d::Event* event);
   bool explodeBombs(cocos2d::Touch* touch,  cocos2d::Event* event);
   void movePlayerIfPossible(float newX);
   void movePlayerByAccelerometer(cocos2d::Acceleration*  acceleration, cocos2d::Event* event);
   void initAccelerometer();
   void initBackButtonListener();
   void onKeyPressed(cocos2d::EventKeyboard::KeyCode keyCode, cocos2d::Event* event);
   void updateScore(float dt);
   void addBombs(float dt);   
   void initAudio();
   void initAudioNewEngine();
   void initMuteButton();
};

#endif // __HELLOWORLD_SCENE_H__
```

现在我们将向您展示在本书的最后一章末尾，`HelloWorldScene.cpp`方法的样子：

```java
#include "HelloWorldScene.h"
USING_NS_CC;
using namespace CocosDenshion;
using namespace cocos2d::experimental;

// User input handling code …
void HelloWorld::initMuteButton()
{
   _muteItem = MenuItemImage::create("mute.png", "mute.png", CC_CALLBACK_1(HelloWorld::muteCallback, this));

   _muteItem->setPosition(Vec2(_visibleSize.width -  _muteItem->getContentSize().width/2 ,
   _visibleSize.height -  _muteItem->getContentSize().height * 2));
```

我们在代码中更改了静音按钮的位置，使其不被广告覆盖：

```java
    _unmuteItem = MenuItemImage::create("unmute.png", "unmute.png", CC_CALLBACK_1(HelloWorld::muteCallback, this));

   _unmuteItem->setPosition(Vec2(_visibleSize.width -  _unmuteItem->getContentSize().width/2 ,
   _visibleSize.height -  _unmuteItem->getContentSize().height *2));
   _unmuteItem -> setVisible(false);

   auto menu = Menu::create(_muteItem, _unmuteItem , nullptr);
   menu->setPosition(Vec2::ZERO);
   this->addChild(menu, 2);
}
// on "init" you need to initialize your instance
bool HelloWorld::init()
{
  if ( !Layer::init() )
  {
     return false;
  }
  _score = 0;
  _director = Director::getInstance();
  visibleSize = _director->getVisibleSize();
  auto origin = _director->getVisibleOrigin();
  auto closeItem = MenuItemImage::create("CloseNormal.png", "CloseSelected.png", CC_CALLBACK_1(HelloWorld::pauseCallback, this));
  closeItem->setPosition(Vec2(visibleSize.width -  closeItem->getContentSize().width/2 , closeItem->getContentSize().height/2));

  auto menu = Menu::create(closeItem, nullptr);
  menu->setPosition(Vec2::ZERO);
  this->addChild(menu, 1);
  _sprBomb = Sprite::create("bomb.png");   
  _sprBomb->setPosition(visibleSize.width / 2,  visibleSize.height + _sprBomb->getContentSize().height/2);
  this->addChild(_sprBomb,1);
  auto bg = Sprite::create("background.png");
  bg->setAnchorPoint(Vec2());
  bg->setPosition(0,0);
  this->addChild(bg, -1);
  _sprPlayer = Sprite::create("player.png");   
  _sprPlayer->setPosition(visibleSize.width / 2, visibleSize.height *   0.23);
  setPhysicsBody(_sprPlayer);
  this->addChild(_sprPlayer, 0);
  //Animations
  Vector<SpriteFrame*> frames;
  Size playerSize = _sprPlayer->getContentSize();
  frames.pushBack(SpriteFrame::create("player.png",  Rect(0, 0, playerSize.width, playerSize.height)));
  frames.pushBack(SpriteFrame::create("player2.png",  Rect(0, 0, playerSize.width, playerSize.height)));
  auto animation = Animation::createWithSpriteFrames(frames,0.2f);
  auto animate = Animate::create(animation);
  _sprPlayer->runAction(RepeatForever::create(animate));   
  setPhysicsBody(_sprBomb);   
  initPhysics();   
  _sprBomb->getPhysicsBody()->setVelocity(Vect(0,-100));   
  initTouch();
  initAccelerometer();   
  #if (CC_TARGET_PLATFORM == CC_PLATFORM_ANDROID)
  setKeepScreenOnJni(true);
  #endif
  initBackButtonListener();
  schedule(schedule_selector(HelloWorld::updateScore), 3.0f);
  schedule(schedule_selector(HelloWorld::addBombs), 8.0f);
  initAudioNewEngine();
  initMuteButton();
  _bombs.pushBack(_sprBomb);
 JniBridge::showToast("Hello Java");
  return true;
}
```

在我们所有的修改之后，这是我们的`AppActivity.java`类的样子：

```java
package org.cocos2dx.cpp;

import org.cocos2dx.lib.Cocos2dxActivity;
import android.app.Activity;
import android.os.Bundle;
import android.view.Gravity;
import android.widget.FrameLayout;
import com.google.android.gms.ads.AdListener;
import com.google.android.gms.ads.AdRequest;
import com.google.android.gms.ads.AdSize;
import com.google.android.gms.ads.AdView;

public class AppActivity extends Cocos2dxActivity {
   private static Activity instance;

   private void initAdMob() {
      final String ADMOB_ID = "ca-app-pub-7870675803288590/4907722461";
      final AdView adView;
      final FrameLayout adViewLayout;

      FrameLayout.LayoutParams adParams = new FrameLayout. LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT,FrameLayout.LayoutParams.WRAP_CONTENT);
      adParams.gravity = Gravity.TOP | Gravity.CENTER_HORIZONTAL;      
      AdRequest adRequest = new AdRequest.Builder().
      addTestDevice(AdRequest.DEVICE_ID_EMULATOR).
      addTestDevice("E8B4B73DC4CAD78DFCB44AF69E7B9EC4").build();

      adView = new AdView(this);
      adView.setAdSize(AdSize.SMART_BANNER);
      adView.setAdUnitId(ADMOB_ID);
      adView.setLayoutParams(adParams);
      adView.loadAd(adRequest);
      adViewLayout = new FrameLayout(this);
      adViewLayout.setLayoutParams(adParams);
      adView.setAdListener(new AdListener() {
            @Override
            public void onAdLoaded() {
            adViewLayout.addView(adView);
            }         
      });      
      this.addContentView(adViewLayout, adParams);
   }

   @Override
   protected void onCreate(final Bundle savedInstanceState) {
      instance = this;      
      super.onCreate(savedInstanceState);
      initAdMob();
   }

   public static Activity getInstance() {
      return instance;
   }
}
```

这是我们本章末尾的`JniFacade.java`类文件的样子：包`com.packtpub.jni`：

```java
import org.cocos2dx.cpp.AppActivity;
import android.app.Activity;
import android.widget.Toast;

public class JniFacade {
   private static Activity activity = AppActivity.getInstance();

   public static void showToast(final String message) {
      activity.runOnUiThread(new Runnable() {         
         @Override
         public void run() {
            Toast.makeText(activity.getBaseContext(), message, Toast.   LENGTH_SHORT).show();   
         }
      }      
   }
}
```

在本章中添加了我们的`JniBridge.cpp`文件后，这是我们位于`proj.android\jni`的`Android.mk`文件的样子：

```java
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

$(call import-add-path,$(LOCAL_PATH)/../../cocos2d)
$(call import-add-path,$(LOCAL_PATH)/../../cocos2d/external)
$(call import-add-path,$(LOCAL_PATH)/../../cocos2d/cocos)

LOCAL_MODULE := cocos2dcpp_shared

LOCAL_MODULE_FILENAME := libcocos2dcpp

LOCAL_SRC_FILES := hellocpp/main.cpp \
         ../../Classes/JniBridge.cpp \
         ../../Classes/AppDelegate.cpp \
         ../../Classes/PauseScene.cpp \
         ../../Classes/GameOverScene.cpp \
                   ../../Classes/HelloWorldScene.cpp

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../Classes

LOCAL_STATIC_LIBRARIES := cocos2dx_static

include $(BUILD_SHARED_LIBRARY)

$(call import-module,.)
```

最后，这是本书末尾的`AndroidManifest.xml`文件的样子：

```java
<?xml version="1.0" encoding="utf-8"?>
<manifest 
    package="com.packt.happybunny"
    android:installLocation="auto"
    android:versionCode="1"
    android:versionName="1.0" >

    <uses-sdk android:minSdkVersion="9" />

    <uses-feature android:glEsVersion="0x00020000" />

    <application
        android:icon="@drawable/icon"
        android:label="@string/app_name" >
        <meta-data
           android:name="com.google.android.gms.version"
           android:value="@integer/google_play_services_version" />

        <!-- Tell Cocos2dxActivity the name of our .so -->
        <meta-data
           android:name="android.app.lib_name"
           android:value="cocos2dcpp" />

        <activity
           android:name="org.cocos2dx.cpp.AppActivity"
           android:configChanges="orientation"
           android:label="@string/app_name"
           android:screenOrientation="portrait"
           android:theme="@android:style/Theme.NoTitleBar.Fullscreen">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />

                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        <activity
            android:name="com.google.android.gms.ads.AdActivity"
            android:configChanges="keyboard|keyboardHidden|orientation| screenLayout|uiMode|screenSize|smallestScreenSize" />
    </application>

    <supports-screens
        android:anyDensity="true"
        android:largeScreens="true"
        android:normalScreens="true"
        android:smallScreens="true"
        android:xlargeScreens="true" />

    <uses-permission android:name="android.permission.INTERNET" />
</manifest>
```

# 概括

在本章中，我们学习了如何通过使用 JNI，在 C++游戏逻辑代码与 Android 的核心 Java 层之间添加交互，我们还通过直接修改在执行`cocos`命令时创建的 Java `Activity`类代码，在游戏中展示了 Google AdMob 横幅广告。
