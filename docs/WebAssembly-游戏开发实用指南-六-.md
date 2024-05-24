# WebAssembly 游戏开发实用指南（六）

> 原文：[`annas-archive.org/md5/2bc11e3fb2b816b3a221f95dafc6aa63`](https://annas-archive.org/md5/2bc11e3fb2b816b3a221f95dafc6aa63)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：设计 2D 相机

相机设计是新手游戏设计师经常忽视的事情之一。到目前为止，我们一直使用的是所谓的*固定位置相机*。屏幕上没有透视变化。在 20 世纪 70 年代，几乎所有早期的街机游戏都是这样设计的。我发现的最古老的带有相机的游戏是 Atari 的*Lunar Lander*，它于 1979 年 8 月发布。*Lunar Lander*是一个早期的基于矢量的游戏，当着陆器接近月球表面时，相机会放大，然后在着陆器接近表面时移动相机。

在 20 世纪 80 年代初，更多的游戏开始尝试一个比单个游戏屏幕更大的游戏世界的想法。*Rally X*是 Namco 于 1980 年发布的类似*Pac-Man*的迷宫游戏，其中迷宫比单个显示更大。*Rally X*使用了一个*位置捕捉相机*（有时称为*锁定相机*），无论如何都会将玩家的汽车保持在游戏屏幕的中心。这是你可以实现的最简单的 2D 滚动相机形式，许多新手游戏设计师会创建一个*2D 位置捕捉相机*然后就此结束，但是你可能希望在游戏中实现更复杂的相机，这是有原因的。

1981 年，Midway 发布了游戏*Defender*。这是一个横向卷轴射击游戏，允许玩家在任何方向移动他们的太空飞船。意识到玩家需要看到太空飞船面对的方向更多的关卡内容，*Defender*使用了第一个*双向前置焦点相机*。这个相机会移动视野区域，使得屏幕的三分之二在玩家太空飞船面对的方向前面，三分之一在后面。这更加关注了玩家当前面对的内容。相机不会在两个位置之间突然切换，那样会很令人不适。相反，当玩家改变方向时，相机位置会平稳过渡到新的位置（对于 1981 年来说相当酷）。

在 20 世纪 80 年代，许多新的相机设计开始被使用。Konami 开始在许多射击游戏中使用自动滚动相机，包括*Scramble*、*Gradius*和*1942*。1985 年，Atari 发布了*Gauntlet*，这是一个早期的多人游戏，允许四名玩家同时参与游戏。*Gauntlet*中的相机定位在所有玩家位置的平均值处。像*Super Mario Bros.*这样的平台游戏允许用户的位置推动相机向前移动。

你需要在构建中包含几个图像才能使这个项目工作。确保你从项目的 GitHub 中包含了`/Chapter11/sprites/`文件夹。如果你还没有下载 GitHub 项目，你可以在[`github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly`](https://github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly)上获取它。

如果你花时间寻找，会发现很多出色的 2D 相机示例。我们将专注（无意冒犯）于一些对我们的游戏有帮助的 2D 相机特性。

# 为我们的游戏创建相机

我们将分几个不同的阶段构建我们的摄像机。我们将从一个基本的**锁定摄像机**实现开始。这将为我们提供一个很好的起点，我们可以在此基础上添加新的摄像机功能。稍后，我们将修改这个摄像机，使其成为一个**投影焦点摄像机**。投影焦点摄像机会关注玩家飞船的速度，并调整摄像机，以便在玩家前方显示更多的游戏区域。这种技术基于这样的假设，即在这个游戏中，玩家通常更关注玩家飞船移动的方向上的游戏内容。对于我们摄像机的最终版本，我们将在我们的抛射物上添加*摄像机吸引器*。这种修改的想法是，当游戏中有射击时，摄像机应该吸引注意力到游戏的那个区域。

# 用于跟踪玩家移动的摄像机

我们摄像机的第一个实现将是一个锁定摄像机，它将锁定我们的玩家，并随着他们在关卡中移动而跟随。现在，我们的关卡和该关卡上的*固定摄像机*大小相同。我们不仅需要使我们的关卡更大，还需要修改我们的对象包裹，以使其与我们的摄像机配合。我们需要做的第一件事是修改我们的`game.hpp`文件以实现我们的锁定摄像机。我们将创建一个`Camera`类和一个`RenderManager`类，在其中移动所有我们特定于渲染的代码。我们还需要添加一些`#define`宏来定义我们关卡的高度和宽度，因为这将与我们已经定义的画布高度和宽度不同。我们还将向我们的`Vector2D`类添加一些额外的重载运算符。

# 投影焦点和摄像机吸引器

锁定摄像机并不是一件糟糕的事情，但更好的摄像机会显示玩家需要看到的更多内容。在我们的游戏中，玩家更有可能对他们移动方向前方的内容感兴趣。有时被称为投影焦点摄像机的摄像机会关注我们飞船当前移动的速度，并相应地调整我们的摄像机位置。

我们将采用的另一种摄像机技术称为**摄像机吸引器**。有时在游戏中，有一些感兴趣的对象可以用来吸引摄像机的焦点。这些对象会产生一种吸引力，会把我们的摄像机朝着那个方向拉动。我们摄像机的一个吸引力是敌人的飞船。另一个吸引力是抛射物。敌人的飞船代表潜在的行动，而抛射物代表对我们玩家的潜在威胁。在本节中，我们将结合投影焦点和摄像机吸引器来改善我们的摄像机定位。

我想要添加的最后一件事是一个指向敌人飞船的箭头。因为游戏区域现在比画布大，我们需要一个提示来帮助我们找到敌人。如果没有这个，我们可能会发现自己毫无目的地四处游荡，这并不好玩。我们还可以用小地图来实现这一点，但是因为只有一个敌人，我觉得箭头会更容易实现。让我们逐步了解我们需要添加的代码，以改善我们的摄像机并添加我们的定位箭头。

# 修改我们的代码

我们将需要为本章添加几个新的类。显然，如果我们想在游戏中有一个摄像头，我们将需要添加一个`Camera`类。在代码的先前版本中，渲染是通过直接调用 SDL 完成的。因为 SDL 没有摄像头作为 API 的一部分，我们将需要添加一个`RenderManager`类，作为我们渲染过程中的中间步骤。这个类将使用摄像机的位置来确定我们在画布上渲染游戏对象的位置。我们将扩大我们的游戏区域，使其为画布的四倍宽和四倍高。这会产生一个游戏问题，因为现在我们需要能够找到敌人飞船。为了解决这个问题，我们需要创建一个指向敌人飞船方向的定位器**用户界面**（**UI**）元素。

# 修改 game.hpp 文件

让我们来看看我们将对`game.hpp`文件进行的更改。我们首先添加了一些`#define`宏：

```cpp
#define LEVEL_WIDTH CANVAS_WIDTH*4
#define LEVEL_HEIGHT CANVAS_HEIGHT*4
```

这将定义我们的关卡的宽度和高度是画布宽度和高度的四倍。在我们的类列表的末尾，我们应该添加一个`Camera`类，一个`Locator`类和`RenderManager`类，如下所示：

```cpp
class Ship;
class Particle;
class Emitter;
class Collider;
class Asteroid;
class Star;
class PlayerShip;
class EnemyShip;
class Projectile;
class ProjectilePool;
class FiniteStateMachine;
class Camera;
class RenderManager;
class Locator;
```

您会注意到最后三行声明了一个名为`Camera`的类，一个名为`Locator`的类，以及一个名为`RenderManager`的类将在代码中稍后定义。

# Vector2D 类定义

我们将扩展我们的`Vector2D`类定义，为`Vector2D`类中的`+`和`-`运算符添加`operator+`和`operator-`重载。

如果您不熟悉运算符重载，这是允许类使用 C++运算符而不是函数的便捷方式。有一个很好的教程可以帮助您获取更多信息，可在[`www.tutorialspoint.com/cplusplus/cpp_overloading.htm`](https://www.tutorialspoint.com/cplusplus/cpp_overloading.htm)找到。

以下是`Vector2D`类的新定义：

```cpp
class Vector2D {
    public:
        float x;
        float y;

        Vector2D();
        Vector2D( float X, float Y );

        void Rotate( float radians );
        void Normalize();
        float MagSQ();
        float Magnitude();
        Vector2D Project( Vector2D &onto );
        float Dot(Vector2D &vec);
        float FindAngle();

        Vector2D operator=(const Vector2D &vec);
        Vector2D operator*(const float &scalar);
        void operator+=(const Vector2D &vec);
        void operator-=(const Vector2D &vec);
        void operator*=(const float &scalar);
        void operator/=(const float &scalar);
 Vector2D operator-(const Vector2D &vec);
 Vector2D operator+(const Vector2D &vec);
};
```

您会注意到定义的最后两行是新的：

```cpp
Vector2D operator-(const Vector2D &vec);
Vector2D operator+(const Vector2D &vec);
```

# Locator 类定义

`Locator`类是一个新的 UI 元素类，将指向玩家指向敌人飞船的箭头。当敌人飞船不出现在画布上时，我们需要一个 UI 元素来帮助玩家找到敌人飞船。以下是类定义的样子：

```cpp
class Locator {
    public:
        bool m_Active = false;
        bool m_LastActive = false;
        SDL_Texture *m_SpriteTexture;
        SDL_Rect m_dest = {.x = 0, .y = 0, .w = 32, .h = 32 };
        Vector2D m_Position;
        int m_ColorFlux;
        float m_Rotation;

        Locator();
        void SetActive();
        void Move();
        void Render();
};
```

前两个属性是布尔标志，与定位器的活动状态有关。`m_Active`属性告诉我们定位器当前是否活动并应该被渲染。`m_LastActive`属性是一个布尔标志，告诉我们上一帧渲染时定位器是否活动。接下来的两行是精灵纹理和目标矩形，这将由渲染管理器用于渲染游戏对象：

```cpp
        SDL_Texture *m_SpriteTexture;
        SDL_Rect m_dest = {.x = 0, .y = 0, .w = 32, .h = 32 };
```

之后，在`m_Position`属性中有一个`x`和`y`位置值，`m_ColorFlux`中有一个表示 RGB 颜色值的整数，以及`m_Rotation`属性中的精灵旋转值。我们将使用`m_ColorFlux`属性使箭头的颜色在敌人靠近时更红，敌人远离时更白。

这个类定义的最后四行是类函数。有一个构造函数，一个将定位器状态设置为活动的函数，以及`Move`和`Render`函数：

```cpp
        Locator();
        void SetActive();
        void Move();
        void Render();
```

# Camera 类定义

现在我们需要添加新的`Camera`类定义。这个类将用于定义我们的`viewport`和摄像机的位置。`Move`函数将在每一帧中调用。最初，`Move`将锁定到我们玩家的位置并跟随其在关卡中移动。稍后，我们将改变这个功能以创建一个更动态的摄像机。`Camera`类将如下所示：

```cpp
class Camera {
    public:
        Vector2D m_Position;
        float m_HalfWidth;
        float m_HalfHeight;

        Camera( float width, float height );
        void Move();
};
```

# RenderManager 类定义

在这段时间里，我们一直在没有背景的情况下移动我们的关卡。在以前的章节中，我们的关卡恰好适合画布元素。然而，现在我们正在用相机在我们的关卡周围滚动。如果背景中没有任何东西在移动，很难判断你的飞船是否在移动。为了在我们的游戏中创造移动的幻觉，我们需要添加一个背景渲染器。除此之外，我们希望我们游戏中的所有渲染都是使用我们刚刚创建的相机作为偏移量来完成的。因此，我们不再希望我们的游戏对象直接调用`SDL_RenderCopy`或`SDL_RenderCopyEx`。相反，我们创建了一个`RenderManager`类，它将负责在我们的游戏内部执行渲染。我们有一个`RenderBackground`函数，它将渲染星空作为背景，并且我们创建了一个`Render`函数，它将使用相机作为偏移量来渲染我们的精灵纹理。这就是`RenderManager`类定义的样子：

```cpp
class RenderManager {
    public:
        const int c_BackgroundWidth = 800;
        const int c_BackgroundHeight = 600;
        SDL_Texture *m_BackgroundTexture;
        SDL_Rect m_BackgroundDest = {.x = 0, .y = 0, .w = 
        c_BackgroundWidth, .h = c_BackgroundHeight };

        RenderManager();
        void RenderBackground();
        void Render( SDL_Texture *tex, SDL_Rect *src, SDL_Rect *dest, float 
        rad_rotation = 0.0, int alpha = 255, int red = 255, int green = 
        255, int blue = 255 );
};
```

在`game.hpp`文件中我们需要做的最后一件事是创建`Camera`和`RenderManager`类型的两个新对象指针的外部链接。这些将是我们在这个版本的游戏引擎中使用的相机和渲染管理器对象，并且是我们将在`main.cpp`文件中定义的变量的外部引用：

```cpp
extern Camera* camera;
extern RenderManager* render_manager;
extern Locator* locator;
```

# camera.cpp 文件

在我们的`Camera`类中我们定义了两个函数；一个是用于我们的`camera`对象的构造函数，另一个是`Move`函数，我们将用它来跟随我们的`player`对象。以下是我们在`camera.cpp`文件中的内容：

```cpp
#include "game.hpp"
Camera::Camera( float width, float height ) {
    m_HalfWidth = width / 2;
    m_HalfHeight = height / 2;
}

void Camera::Move() {
    m_Position = player->m_Position;
    m_Position.x -= CANVAS_WIDTH / 2;
    m_Position.y -= CANVAS_HEIGHT / 2;
}
```

在这个实现中，`Camera`构造函数和`Move`函数非常简单。构造函数根据传入的宽度和高度设置相机的半宽和半高。`Move`函数将相机的位置设置为玩家的位置，然后将相机的位置移动画布宽度和画布高度的一半来使玩家居中。我们刚刚建立了一个起始相机，并将在本章后面添加更多功能。

# render_manager.cpp 文件

我们将把我们在对象内部进行的所有呼叫渲染精灵的操作移动到`RenderManager`类中。我们需要这样做是因为我们将使用我们相机的位置来决定我们在画布上渲染精灵的位置。我们还需要一个函数来渲染我们的背景星空。我们`render_manager.cpp`文件的前几行将包括`game.hpp`文件，并定义我们背景图像的虚拟文件系统位置：

```cpp
#include "game.hpp"
#define BACKGROUND_SPRITE_FILE (char*)"/sprites/starfield.png"
```

之后，我们将定义我们的构造函数。构造函数将用于将我们的`starfield.png`文件加载为一个`SDL_Surface`对象，然后使用该表面创建一个`SDL_Texture`对象，我们将使用它来渲染我们的背景：

```cpp
RenderManager::RenderManager() {
    SDL_Surface *temp_surface = IMG_Load( BACKGROUND_SPRITE_FILE );

    if( !temp_surface ) {
        printf("failed to load image: %s\n", IMG_GetError() );
        return;
    }

    m_BackgroundTexture = SDL_CreateTextureFromSurface( renderer, 
    temp_surface );

    if( !m_BackgroundTexture ) {
        printf("failed to create texture: %s\n", IMG_GetError() );
        return;
    }
    SDL_FreeSurface( temp_surface );
}
```

`RenderBackground`函数将需要在我们在`main`循环中定义的`render()`函数的开头被调用。因此，`RenderBackground`的前两行将有两个函数，我们将使用它们来清除之前在`main.cpp`中从`render()`函数调用的渲染器到黑色：

```cpp
SDL_SetRenderDrawColor( renderer, 0, 0, 0, 255 );
SDL_RenderClear( renderer );
```

之后，我们将设置一个背景矩形作为我们的渲染目标。`starfield.png`的大小与我们的画布大小（800 x 600）相匹配，因此我们需要根据摄像头的位置渲染四次。因为这是一个重复的纹理，我们可以使用模运算符（`%`）在摄像头的位置上来确定我们想要如何偏移星空。举个例子，如果我们将摄像头定位在`*x* = 100`，`*y* = 200`，我们希望将我们的星空背景的第一份拷贝渲染在`-100`，`-200`。如果我们停在这里，我们会在画布的右侧有 100 像素的黑色空间，在画布的底部有 200 像素的黑色空间。因为我们希望在这些区域有一个背景，我们需要额外渲染三次我们的背景。如果我们在`700`，`-200`处再次渲染我们的背景（在原始渲染的*x*值上添加画布宽度），我们现在在画布底部有一个 200 像素的黑色条。然后我们可以在`-100`，`400`处渲染我们的星空（在原始渲染的*y*值上添加画布高度）。这样会在底角留下一个 100 x 200 像素的黑色。第四次渲染需要在原始渲染的*x*和*y*值上添加画布宽度和画布高度来填补那个角落。这就是我们在`RenderBackground`函数中所做的，我们用它来根据摄像头的位置将重复的背景渲染到画布上：

```cpp
void RenderManager::RenderBackground() {
    SDL_SetRenderDrawColor( renderer, 0, 0, 0, 255 );
    SDL_RenderClear( renderer );
    SDL_Rect background_rect = {.x = 0, .y=0, .w=CANVAS_WIDTH, 
                                .h=CANVAS_HEIGHT};
    int start_x = (int)(camera->m_Position.x) % CANVAS_WIDTH;
    int start_y = (int)(camera->m_Position.y) % CANVAS_HEIGHT;
    background_rect.x -= start_x;
    background_rect.y -= start_y;
    SDL_RenderCopy( renderer, m_BackgroundTexture, NULL, 
                    &background_rect );
    background_rect.x += CANVAS_WIDTH;
    SDL_RenderCopy( renderer, m_BackgroundTexture, NULL, 
                    &background_rect );
    background_rect.x -= CANVAS_WIDTH;
    background_rect.y += CANVAS_HEIGHT;
    SDL_RenderCopy( renderer, m_BackgroundTexture, NULL, 
                    &background_rect );
    background_rect.x += CANVAS_WIDTH;
    SDL_RenderCopy( renderer, m_BackgroundTexture, NULL, 
                    &background_rect );
 }
```

我们在`render_manager.cpp`中定义的最后一个函数是我们的`Render`函数。在定义完这个函数之后，我们需要找到我们之前在代码中调用`SDL_RenderCopy`和`SDL_RenderCopyEx`的每个地方，并将这些调用替换为对我们渲染管理器的`Render`函数的调用。这个函数不仅会根据我们摄像头的位置来渲染我们的精灵，还会用于设置颜色和 alpha 通道的修改。以下是`Render`函数的完整代码：

```cpp

void RenderManager::Render( SDL_Texture *tex, SDL_Rect *src, SDL_Rect *dest, float rad_rotation,int alpha, int red, int green, int blue ) {

    SDL_Rect camera_dest = *dest;
    if( camera_dest.x <= CANVAS_WIDTH &&
        camera->m_Position.x >= LEVEL_WIDTH - CANVAS_WIDTH ) {
        camera_dest.x += (float)LEVEL_WIDTH;
    }
    else if( camera_dest.x >= LEVEL_WIDTH - CANVAS_WIDTH &&
             camera->m_Position.x <= CANVAS_WIDTH ) {
             camera_dest.x -= (float)LEVEL_WIDTH;
    }
    if( camera_dest.y <= CANVAS_HEIGHT &&
        camera->m_Position.y >= LEVEL_HEIGHT - CANVAS_HEIGHT ) {
        camera_dest.y += (float)LEVEL_HEIGHT;
    }
    else if( camera_dest.y >= LEVEL_HEIGHT - CANVAS_HEIGHT &&
             camera->m_Position.y <= CANVAS_HEIGHT ) {
             camera_dest.y -= (float)LEVEL_HEIGHT;
    }
    camera_dest.x -= (int)camera->m_Position.x;
    camera_dest.y -= (int)camera->m_Position.y;

    SDL_SetTextureAlphaMod(tex,
                           (Uint8)alpha );

    SDL_SetTextureColorMod(tex,
                            (Uint8)red,
                            (Uint8)green,
                            (Uint8)blue );

    if( rad_rotation != 0.0 ) {
        float degree_rotation = RAD_TO_DEG(rad_rotation);
        SDL_RenderCopyEx( renderer, tex, src, &camera_dest,
                          degree_rotation, NULL, SDL_FLIP_NONE );
    }
    else {
        SDL_RenderCopy( renderer, tex, src, &camera_dest );
    }
}
```

这个函数的第一步是创建一个新的`SDL_Rect`对象，我们将用它来修改传递给`Render`函数的`dest`变量中的值。因为我们有一个包裹*x*和*y*坐标的级别，所以我们希望在级别的最左边渲染对象时，如果我们在级别的最右边，我们将希望将对象渲染到右边。同样，如果我们在级别的最左边，我们将希望将位于级别最右边的对象渲染到右边。这样可以使我们的飞船从级别的左侧环绕到级别的右侧，反之亦然。以下是调整摄像头位置以包裹级别左右对象的代码：

```cpp
if( camera_dest.x <= CANVAS_WIDTH &&
    camera->m_Position.x >= LEVEL_WIDTH - CANVAS_WIDTH ) {
    camera_dest.x += (float)LEVEL_WIDTH;
}
else if( camera_dest.x >= LEVEL_WIDTH - CANVAS_WIDTH &&
         camera->m_Position.x <= CANVAS_WIDTH ) {
    camera_dest.x -= (float)LEVEL_WIDTH;
}
```

完成这些之后，我们将做类似的事情，以便在级别的顶部和底部包裹对象的位置：

```cpp
if( camera_dest.y <= CANVAS_HEIGHT &&
    camera->m_Position.y >= LEVEL_HEIGHT - CANVAS_HEIGHT ) {
    camera_dest.y += (float)LEVEL_HEIGHT;
}
else if( camera_dest.y >= LEVEL_HEIGHT - CANVAS_HEIGHT &&
         camera->m_Position.y <= CANVAS_HEIGHT ) {
    camera_dest.y -= (float)LEVEL_HEIGHT;
}
```

接下来，我们需要从`camera_dest`的*x*和*y*坐标中减去摄像头的位置，并设置我们的`alpha`和`color`修改的值：

```cpp
camera_dest.x -= (int)camera->m_Position.x;
camera_dest.y -= (int)camera->m_Position.y;
SDL_SetTextureAlphaMod(tex,
                        (Uint8)alpha );

SDL_SetTextureColorMod(tex,
                       (Uint8)red,
                       (Uint8)green,
                       (Uint8)blue );
```

在函数的结尾，如果我们的精灵被旋转，我们将调用`SDL_RenderCopyEx`，如果没有旋转，我们将调用`SDL_RenderCopy`：

```cpp
if( rad_rotation != 0.0 ) {
    float degree_rotation = RAD_TO_DEG(rad_rotation);
    SDL_RenderCopyEx( renderer, tex, src, &camera_dest,
                      degree_rotation, NULL, SDL_FLIP_NONE );
}
else {
    SDL_RenderCopy( renderer, tex, src, &camera_dest );
}
```

# 修改 main.cpp

为了实现我们的摄像头，我们需要对`main.cpp`文件进行一些修改。我们需要为我们的摄像头、渲染管理器和定位器添加一些新的全局变量。我们需要修改我们的`move`函数，以包括移动我们的摄像头和定位器的调用。我们将修改我们的`render`函数来渲染我们的背景和定位器。最后，我们需要在我们的`main`函数中添加更多的初始化代码。

# 新的全局变量

我们需要在`main.cpp`文件的开头附近创建三个新的全局变量。我们将需要指向`RenderManager`、`Camera`和`Locator`的对象指针。这是这些声明的样子：

```cpp
Camera* camera;
RenderManager* render_manager;
Locator* locator;
```

# 修改 move 函数

我们需要修改我们的`move`函数来移动我们的摄像头和我们的定位器对象。我们需要在我们的`move`函数的结尾添加以下两行：

```cpp
 camera->Move();
 locator->Move();
```

以下是`move`函数的全部内容：

```cpp
void move() {
    player->Move();
    enemy->Move();
    projectile_pool->MoveProjectiles();
    Asteroid* asteroid;
    std::vector<Asteroid*>::iterator it;
    int i = 0;

    for( it = asteroid_list.begin(); it != asteroid_list.end(); it++ ) {
        asteroid = *it;
        if( asteroid->m_Active ) {
            asteroid->Move();
        }
    }
    star->Move();
    camera->Move();
    locator->Move();
}
```

# 修改渲染函数

我们将在`render`函数的开头添加一行新代码。这行代码将渲染背景星空，并根据摄像机位置移动它：

```cpp
 render_manager->RenderBackground();
```

之后，我们需要在`render`函数的末尾添加一行代码。这行代码需要立即出现在`SDL_RenderPresent`调用之前，而`SDL_RenderPresent`调用仍然需要是该函数中的最后一行：

```cpp
 locator->Render();
```

以下是`render()`函数的全部内容：

```cpp
void render() {
 render_manager->RenderBackground();
    player->Render();
    enemy->Render();
    projectile_pool->RenderProjectiles();

    Asteroid* asteroid;
    std::vector<Asteroid*>::iterator it;
    for( it = asteroid_list.begin(); it != asteroid_list.end(); it++ ) {
        asteroid = *it;
        asteroid->Render();
    }
    star->Render();
 locator->Render();

    SDL_RenderPresent( renderer );
}
```

# 修改主函数

最后的修改将是在`main`函数中发生的初始化。我们需要为之前定义的`camera`、`render_manager`和`locator`指针创建新对象：

```cpp
camera = new Camera(CANVAS_WIDTH, CANVAS_HEIGHT);
render_manager = new RenderManager();
locator = new Locator();
```

在我们的代码的先前版本中，我们有七个调用`new Asteroid`并使用`asteroid_list.push_back`将这七个新小行星推入我们的小行星列表中。现在我们需要创建比七个更多的小行星，所以我们将使用双重`for`循环来创建并分散我们的小行星遍布整个游戏区域。为此，我们首先需要删除所有那些早期的调用来创建和推入小行星：

```cpp
asteroid_list.push_back( new Asteroid(
                            200, 50, 0.05, 
                            DEG_TO_RAD(10) ) );
asteroid_list.push_back( new Asteroid(
                            600, 150, 0.03, 
                            DEG_TO_RAD(350) ) );
asteroid_list.push_back( new Asteroid(
                            150, 500, 0.05, 
                            DEG_TO_RAD(260) ) );
asteroid_list.push_back( new Asteroid(
                            450, 350, 0.01, 
                            DEG_TO_RAD(295) ) );
asteroid_list.push_back( new Asteroid(
                            350, 300, 0.08, 
                            DEG_TO_RAD(245) ) );
asteroid_list.push_back( new Asteroid(
                            700, 300, 0.09, 
                            DEG_TO_RAD(280) ) );
asteroid_list.push_back( new Asteroid(
                            200, 450, 0.03, 
                            DEG_TO_RAD(40) ) );
```

一旦您删除了所有前面的代码，我们将添加以下代码来创建新的小行星，并在整个游戏区域中将它们半随机地分布：

```cpp
int asteroid_x = 0;
int asteroid_y = 0;
int angle = 0;

// SCREEN 1
for( int i_y = 0; i_y < 8; i_y++ ) {
    asteroid_y += 100;
    asteroid_y += rand() % 400;
    asteroid_x = 0;

    for( int i_x = 0; i_x < 12; i_x++ ) {
        asteroid_x += 66;
        asteroid_x += rand() % 400;
        int y_save = asteroid_y;
        asteroid_y += rand() % 400 - 200;
        angle = rand() % 359;
        asteroid_list.push_back( new Asteroid(
                        asteroid_x, asteroid_y,
                        get_random_float(0.5, 1.0),
                        DEG_TO_RAD(angle) ) );
        asteroid_y = y_save;
    }
}
```

# 修改 asteroid.cpp

现在我们正在使用渲染管理器来渲染所有游戏对象，我们需要遍历各种游戏对象并修改它们以通过渲染管理器而不是直接渲染。我们将首先修改`asteroid.cpp`文件。在`asteroid.cpp`中，我们有`Asteroid::Render()`函数。在之前的章节中，这个函数会直接通过 SDL 渲染小行星精灵，使用`SDL_RenderCopyEx`调用。现在我们有了在`main.cpp`文件中定义的`render_manager`对象，我们将使用该渲染管理器间接地渲染我们的精灵。`RenderManager::Render`函数将使用摄像机来调整在画布上渲染精灵的位置。我们需要对`Asteroid::Render()`函数进行的第一个修改是删除以下行：

```cpp
 SDL_RenderCopyEx( renderer, m_SpriteTexture, 
                   &m_src, &m_dest, 
                   RAD_TO_DEG(m_Rotation), NULL, SDL_FLIP_NONE );
```

删除对`SDL_RenderCopyEX`的调用后，我们需要在`render_manager`对象的`Render`函数中添加以下调用：

```cpp
 render_manager->Render( m_SpriteTexture, &m_src, &m_dest, m_Rotation );
```

`Asteroid::Render`函数的新版本现在看起来像这样：

```cpp
void Asteroid::Render() {
    m_Explode->Move();
    m_Chunks->Move();
    if( m_Active == false ) {
        return;
    }
    m_src.x = m_dest.w * m_CurrentFrame;
    m_dest.x = m_Position.x + m_Radius / 2;
    m_dest.y = m_Position.y + m_Radius / 2;
    render_manager->Render( m_SpriteTexture, &m_src, &m_dest, m_Rotation );
}
```

# 修改 collider.cpp

我们需要修改`collider.cpp`文件中的一个函数。`WrapPosition`函数的先前版本检查`Collider`对象是否移出画布的一侧，如果是，则该函数将移动碰撞器到相反的一侧。这模仿了经典的 Atari 街机游戏*Asteroids*的行为。在 Atari *Asteroids*中，如果一个小行星或玩家的太空船从屏幕的一侧移出，那个小行星（或太空船）将出现在游戏屏幕的对面。这是我们`wrap`代码的先前版本：

```cpp
void Collider::WrapPosition() {
    if( m_Position.x > CANVAS_WIDTH + m_Radius ) {
        m_Position.x = -m_Radius;
    }
    else if( m_Position.x < -m_Radius ) {
        m_Position.x = CANVAS_WIDTH;
    }

    if( m_Position.y > CANVAS_HEIGHT + m_Radius ) {
        m_Position.y = -m_Radius;
    }
    else if( m_Position.y < -m_Radius ) {
        m_Position.y = CANVAS_HEIGHT;
    }
}
```

因为我们的游戏现在扩展到超出单个画布，所以我们不再希望在对象移出画布时进行包装。相反，我们希望在对象超出级别的边界时将其包装。这是`WrapPosition`函数的新版本：

```cpp
void Collider::WrapPosition() {
    if( m_Position.x > LEVEL_WIDTH ) {
        m_Position.x -= LEVEL_WIDTH;
    }
    else if( m_Position.x < 0 ) {
        m_Position.x += LEVEL_WIDTH;
    }

    if( m_Position.y > LEVEL_HEIGHT ) {
        m_Position.y -= LEVEL_HEIGHT;
    }
    else if( m_Position.y < 0 ) {
        m_Position.y += LEVEL_HEIGHT;
    }
}
```

# 修改 enemy_ship.cpp

需要对`enemy_ship.cpp`文件进行一些小修改。`EnemyShip`构造函数现在将设置`m_Position`属性上的`x`和`y`值。我们需要将位置设置为`810`和`800`，因为级别现在比画布大小大得多。我们将在`EnemyShip`构造函数的最顶部设置`m_Position`属性。在更改后，构造函数的开头将如下所示：

```cpp
EnemyShip::EnemyShip() {
    m_Position.x = 810.0;
    m_Position.y = 800.0;
```

# 修改 finite_state_machine.cpp

我们需要对`finite_state_machine.cpp`文件进行小的修改。在`FiniteStateMachine::AvoidForce()`函数内部，有几个引用画布尺寸的地方必须更改为引用级别尺寸，因为我们的级别尺寸和画布尺寸不同。以前，我们将`star_avoid`变量的`x`和`y`属性设置为以下基于画布的值：

```cpp
star_avoid.x = CANVAS_WIDTH / 2;
star_avoid.y = CANVAS_HEIGHT / 2;
```

这些行必须更改为引用`LEVEL_WIDTH`和`LEVEL_HEIGHT`：

```cpp
star_avoid.x = LEVEL_WIDTH / 2;
star_avoid.y = LEVEL_HEIGHT / 2;
```

我们必须对`avoid_vec`变量做同样的事情。这是我们以前的内容：

```cpp
avoid_vec.x = CANVAS_WIDTH / 2;
avoid_vec.y = CANVAS_HEIGHT / 2;
```

这也必须更改为引用`LEVEL_WIDTH`和`LEVEL_HEIGHT`：

```cpp
avoid_vec.x = LEVEL_WIDTH / 2;
avoid_vec.y = LEVEL_HEIGHT / 2;
```

`FiniteState::AvoidForce`函数的新版本完整内容如下：

```cpp
void FiniteStateMachine::AvoidForce() {
    Vector2D start_corner;
    Vector2D end_corner;
    Vector2D avoid_vec;
    Vector2D dist;
    float closest_square = 999999999999.0;
    float msq;
    Vector2D star_avoid;
 star_avoid.x = LEVEL_WIDTH / 2;
 star_avoid.y = LEVEL_HEIGHT / 2;
    star_avoid -= m_Ship->m_Position;
    msq = star_avoid.MagSQ();

    if( msq >= c_StarAvoidDistSQ ) {
        start_corner = m_Ship->m_Position;
        start_corner.x -= c_AvoidDist;
        start_corner.y -= c_AvoidDist;
        end_corner = m_Ship->m_Position;
        end_corner.x += c_AvoidDist;
        end_corner.y += c_AvoidDist;

        Asteroid* asteroid;
        std::vector<Asteroid*>::iterator it;

        int i = 0;
        for( it = asteroid_list.begin(); it != asteroid_list.end(); it++ ) {
            asteroid = *it;
            if( asteroid->m_Active == true &&
                asteroid->SteeringRectTest( start_corner, end_corner ) ) {
                dist = asteroid->m_Position;
                dist -= m_Ship->m_Position;
                msq = dist.MagSQ();

                if( msq <= closest_square ) {
                    closest_square = msq;
                    avoid_vec = asteroid->m_Position;
                }
            }
        }
        // LOOP OVER PROJECTILES
        Projectile* projectile;
        std::vector<Projectile*>::iterator proj_it;

        for( proj_it = projectile_pool->m_ProjectileList.begin(); 
             proj_it != projectile_pool->m_ProjectileList.end(); proj_it++ ) {
            projectile = *proj_it;
            if( projectile->m_Active == true &&
                projectile->SteeringRectTest( start_corner, end_corner ) ) {
                dist = projectile->m_Position;
                dist -= m_Ship->m_Position;
                msq = dist.MagSQ();

                if( msq <= closest_square ) {
                    closest_square = msq;
                    avoid_vec = projectile->m_Position;
                }
            }
        }
        if( closest_square != 999999999999.0 ) {
            avoid_vec -= m_Ship->m_Position;
            avoid_vec.Normalize();
            float rot_to_obj = avoid_vec.FindAngle();

            if( std::abs( rot_to_obj - m_Ship->m_Rotation ) < 0.75 ) {
                if( rot_to_obj >= m_Ship->m_Rotation ) {
                    m_Ship->RotateLeft();
                }
                else {
                    m_Ship->RotateRight();
                }
            }
            m_Ship->m_Velocity -= avoid_vec * delta_time * 
            c_ObstacleAvoidForce;
        }
    }
    else {
        avoid_vec.x = LEVEL_WIDTH / 2;
 avoid_vec.y = LEVEL_HEIGHT / 2;
        avoid_vec -= m_Ship->m_Position;
        avoid_vec.Normalize();
        float rot_to_obj = avoid_vec.FindAngle();
        if( std::abs( rot_to_obj - m_Ship->m_Rotation ) < 0.75 ) {
            if( rot_to_obj >= m_Ship->m_Rotation ) {
                m_Ship->RotateLeft();
            }
            else {
                m_Ship->RotateRight();
            }
        }
        m_Ship->m_Velocity -= avoid_vec * delta_time * c_StarAvoidForce; 
    }
}
```

# 修改 particle.cpp

我们需要修改`particle.cpp`文件中的`Render`函数，以便通过`render_manager`而不是直接通过调用 SDL 来渲染粒子。`Particle::Render`函数的旧版本如下：

```cpp
void Particle::Render() {
    SDL_SetTextureAlphaMod(m_sprite_texture,
                            (Uint8)m_alpha );

    if( m_color_mod == true ) {
        SDL_SetTextureColorMod(m_sprite_texture,
                                m_current_red,
                                m_current_green,
                                m_current_blue );
    }

    if( m_align_rotation == true ) {
        SDL_RenderCopyEx( renderer, m_sprite_texture, &m_src, &m_dest, 
                            m_rotation, NULL, SDL_FLIP_NONE );
    }
    else {
        SDL_RenderCopy( renderer, m_sprite_texture, &m_src, &m_dest );
    }
}
```

新的`Particle::Render`函数将通过`render_manager`对象对`Render`函数进行一次调用：

```cpp
void Particle::Render() {
 render_manager->Render( m_sprite_texture, &m_src, &m_dest, m_rotation,
 m_alpha, m_current_red, m_current_green, m_current_blue );
}
```

# 修改 player_ship.cpp

我们需要对`player_ship.cpp`文件进行一些小的修改。与我们对`enemy_ship.cpp`文件所做的更改一样，我们需要添加两行来设置`m_Position`属性中的`x`和`y`值。

我们需要删除`PlayerShip::PlayerShip()`构造函数的前两行：

```cpp
m_Position.x = CANVAS_WIDTH - 210.0;
m_Position.y = CANVAS_HEIGHT - 200.0;
```

这些是我们需要对`PlayerShip::PlayerShip()`构造函数进行的更改：

```cpp
PlayerShip::PlayerShip() {
 m_Position.x = LEVEL_WIDTH - 810.0;
 m_Position.y = LEVEL_HEIGHT - 800.0;
```

# 修改 projectile.cpp

我们需要对`projectile.cpp`文件进行一些小的修改。与其他游戏对象一样，`Render`函数以前直接调用 SDL 函数来渲染游戏对象。我们需要通过`render_manager`对象进行调用，而不是直接调用 SDL。我们需要从`Projectile::Render()`函数中删除以下行：

```cpp
int return_val = SDL_RenderCopy( renderer, m_SpriteTexture, 
                                 &src, &dest );
if( return_val != 0 ) {
    printf("SDL_Init failed: %s\n", SDL_GetError());
}
```

我们需要在`render_manager`对象上添加一个对`Render`函数的调用来替换这些行：

```cpp
 render_manager->Render( m_SpriteTexture, &src, &dest );
```

`Projectile::Render()`函数的新版本将如下所示：

```cpp
void Projectile::Render() {
    dest.x = m_Position.x + 8;
    dest.y = m_Position.y + 8;
    dest.w = c_Width;
    dest.h = c_Height;

    src.x = 16 * m_CurrentFrame;

 render_manager->Render( m_SpriteTexture, &src, &dest );
}
```

# 修改 shield.cpp

与许多其他游戏对象一样，`Shield::Render()`函数将需要修改，以便不再直接调用 SDL，而是调用`render_manager`对象的`Render`函数。在`Shield::Render()`函数内部，我们需要删除对 SDL 的以下调用：

```cpp
SDL_SetTextureColorMod(m_SpriteTexture,
                        color_red,
                        color_green,
                        0 );

SDL_RenderCopyEx( renderer, m_SpriteTexture, 
                    &m_src, &m_dest, 
                    RAD_TO_DEG(m_Ship->m_Rotation), 
                    NULL, SDL_FLIP_NONE );
```

我们将用一个对`Render`的单一调用来替换这些行：

```cpp
render_manager->Render( m_SpriteTexture, &m_src, &m_dest, m_Ship->m_Rotation,
                        255, color_red, color_green, 0 );
```

这是`Shield::Render`函数的新版本的完整内容：

```cpp
void Shield::Render() {
    if( m_Active ) {
        int color_green = m_ttl / 100 + 1;
        int color_red = 255 - color_green;

        m_src.x = m_CurrentFrame * m_dest.w;

        m_dest.x = m_Ship->m_Position.x;
        m_dest.y = m_Ship->m_Position.y;
 render_manager->Render( m_SpriteTexture, &m_src, &m_dest, m_Ship->m_Rotation,
 255, color_red, color_green, 0 );
    }
}
```

# 修改 ship.cpp

修改我们游戏对象内的`Render`函数变得相当常规。与我们修改了`Render`函数的其他对象一样，我们需要删除所有直接调用 SDL 的部分。这是我们需要从`Render`函数中删除的代码：

```cpp
float degrees = (m_Rotation / PI) * 180.0;
int return_code = SDL_RenderCopyEx( renderer, m_SpriteTexture, 
                                    &src, &dest, 
                                    degrees, NULL, SDL_FLIP_NONE );
if( return_code != 0 ) {
    printf("failed to render image: %s\n", IMG_GetError() );
}
```

删除这些行后，我们需要添加一行调用`render_manager->Render`函数：

```cpp
 render_manager->Render( m_SpriteTexture, &src, &dest, m_Rotation );
```

# 修改 star.cpp

我们需要修改`star.cpp`文件内的两个函数。首先，我们需要修改`Star::Star()`构造函数中星星的位置。在上一章的`Star`构造函数版本中，我们将星星的位置设置为画布的中间。现在，它必须设置为级别的中间。以下是原始版本构造函数中的行：

```cpp
m_Position.x = CANVAS_WIDTH / 2;
m_Position.y = CANVAS_HEIGHT / 2;
```

现在，我们将更改这些位置，使其相对于`LEVEL_WIDTH`和`LEVEL_HEIGHT`而不是`CANVAS_WIDTH`和`CANVAS_HEIGHT`：

```cpp
m_Position.x = LEVEL_WIDTH / 2;
m_Position.y = LEVEL_HEIGHT / 2;
```

在对`Star::Star`构造函数进行上述更改后，我们需要对`Star::Render`函数进行更改。我们需要删除对`SDL_RenderCopy`的调用，并将其替换为对`render_manager`对象上的`Render`函数的调用。这是以前版本的`Render`函数的样子：

```cpp
void Star::Render() {
    Emitter* flare;
    std::vector<Emitter*>::iterator it;
    for( it = m_FlareList.begin(); it != m_FlareList.end(); it++ ) {
        flare = *it;
        flare->Move();
    }
    m_src.x = m_dest.w * m_CurrentFrame;
    SDL_RenderCopy( renderer, m_SpriteTexture, 
                    &m_src, &m_dest );
}
```

我们将修改为以下内容：

```cpp
void Star::Render() {
    Emitter* flare;
    std::vector<Emitter*>::iterator it;
    for( it = m_FlareList.begin(); it != m_FlareList.end(); it++ ) {
        flare = *it;
        flare->Move();
    }
    m_src.x = m_dest.w * m_CurrentFrame;
    render_manager->Render( m_SpriteTexture, &m_src, &m_dest );
}
```

# 修改 vector.cpp

我们需要向我们的`Vector2D`类添加两个新的重载运算符。我们需要重载`operator-`和`operator+`。这段代码非常简单。它将使用已经重载的`operator-=`和`operator+=`来允许我们对彼此的向量进行加法和减法。以下是这些重载运算符的新代码：

```cpp
Vector2D Vector2D::operator-(const Vector2D &vec) {
 Vector2D return_vec = *this;
 return_vec -= vec;
 return return_vec;
}

Vector2D Vector2D::operator+(const Vector2D &vec) {
 Vector2D return_vec = *this;
 return_vec += vec;
 return return_vec;
}
```

# 编译并使用锁定摄像头进行游戏

如果我们现在编译和测试我们所拥有的东西，我们应该能够在我们的关卡中移动并看到一个直接跟踪玩家位置的摄像头。我们应该有一个定位箭头，帮助我们找到敌人的太空船。以下是我们可以用来构建项目的 Emscripten 的命令行调用：

```cpp
em++ asteroid.cpp camera.cpp collider.cpp emitter.cpp enemy_ship.cpp finite_state_machine.cpp locator.cpp main.cpp particle.cpp player_ship.cpp projectile_pool.cpp projectile.cpp range.cpp render_manager.cpp shield.cpp ship.cpp star.cpp vector.cpp -o index.html --preload-file sprites -std=c++17 -s USE_WEBGL2=1 -s USE_SDL=2 -s USE_SDL_IMAGE=2 -s SDL2_IMAGE_FORMATS=["png"] -s USE_SDL_IMAGE=2 -s SDL2_IMAGE_FORMATS=["png"] 
```

在 Windows 或 Linux 命令提示符上运行上述命令。运行后，从 Web 服务器提供`index.html`文件，并在 Chrome 或 Firefox 等浏览器中打开它。

# 更高级的摄像头

我们当前的摄像头是功能性的，但有点无聊。它专注于玩家，这样做还行，但可以显著改进。首先，正如*Defender*的设计者意识到的那样，将摄像头的焦点放在玩家移动的方向上更为重要，而不是直接对准玩家。为了实现这一点，我们将在我们的摄像头中添加*投影焦点*。它将查看玩家飞船的当前速度，并将摄像头向前移动到该速度的方向。然而，有时您可能仍希望摄像头的焦点在玩家后面。为了帮助解决这个问题，我们将添加一些摄像头吸引器。摄像头吸引器是吸引摄像头注意力的对象。如果敌人出现在玩家后面，将摄像头稍微移回以帮助保持敌人在屏幕上。如果敌人向你射击，将摄像头吸引到向你飞来的弹丸可能更为重要。

# 对 games.hpp 的更改

我们需要做的第一个更改是修改我们的`games.hpp`文件。让摄像头跟随我们的玩家很容易。摄像头没有任何抖动或突然移动，因为玩家的飞船不是那样移动的。如果我们要使用更高级的功能，比如吸引器和前置焦点，我们需要计算摄像头的期望位置，然后平稳过渡到该位置。为了支持这一点，我们需要在我们的`Camera`类中添加一个`m_DesiredPosition`属性。以下是我们必须添加的新行：

```cpp
 Vector2D m_DesiredPosition;
```

这是我们在添加了期望位置属性后`games.hpp`文件中的`Camera`类的样子：

```cpp
class Camera {
    public:
        Vector2D m_Position;
 Vector2D m_DesiredPosition;

        float m_HalfWidth;
        float m_HalfHeight;

        Camera( float width, float height );
        void Move();
};
```

# 对 camera.cpp 的更改

现在我们已经在类定义中添加了期望位置属性，我们需要更改我们的`camera.cpp`文件。我们需要修改构造函数，将摄像头的位置设置为玩家飞船的位置。以下是我们需要添加到构造函数的行：

```cpp
m_Position = player->m_Position;
m_Position.x -= CANVAS_WIDTH / 2;
m_Position.y -= CANVAS_HEIGHT / 2;
```

在我们添加了这些行之后，构造函数如下：

```cpp
Camera::Camera( float width, float height ) {
    m_HalfWidth = width / 2;
    m_HalfHeight = height / 2;

 m_Position = player->m_Position;
 m_Position.x -= CANVAS_WIDTH / 2;
 m_Position.y -= CANVAS_HEIGHT / 2;
}
```

我们的`Camera::Move`函数将完全不同。你可能要删除当前版本的`Camera::Move`中的所有代码行，因为它们都不再有用。我们的新期望位置属性将在`Move`函数的开头设置，就像之前设置位置一样。为此，请在您通过删除该函数中的所有内容创建的空版本的`Camera::Move`中添加以下行：

```cpp
m_DesiredPosition = player->m_Position;
m_DesiredPosition.x -= CANVAS_WIDTH / 2;
m_DesiredPosition.y -= CANVAS_HEIGHT / 2;
```

如果玩家死亡，我们希望我们的摄像头停留在这个位置。玩家死亡后，我们不希望任何吸引器影响摄像头的位置。在玩家死亡后过度移动玩家摄像头看起来有点奇怪，因此添加以下代码行，检查玩家飞船是否活跃，如果不活跃，则将摄像头的位置移向期望位置，然后从`Move`函数返回：

```cpp
if( player->m_Active == false ) {
    m_Position.x = m_Position.x + (m_DesiredPosition.x - m_Position.x) 
    * delta_time;
    m_Position.y = m_Position.y + (m_DesiredPosition.y - m_Position.y) 
    * delta_time;
    return;
}
```

我们将使游戏中的所有活动抛射物成为吸引器。如果敌人向我们射击，它对我们的飞船构成威胁，因此应该吸引摄像头的注意。如果我们射出抛射物，这也表明了我们的关注方向。我们将使用`for`循环来遍历游戏中的所有抛射物，如果该抛射物是活动的，我们将使用它的位置来移动摄像头的期望位置。以下是代码：

```cpp
Projectile* projectile;
std::vector<Projectile*>::iterator it;
Vector2D attractor;
for( it = projectile_pool->m_ProjectileList.begin(); it != projectile_pool->m_ProjectileList.end(); it++ ) {
    projectile = *it;
    if( projectile->m_Active ) {
        attractor = projectile->m_Position;
        attractor -= player->m_Position;
        attractor.Normalize();
        attractor *= 5;
        m_DesiredPosition += attractor;
    }
}
```

在使用吸引器来移动摄像头的期望位置后，我们将根据玩家飞船的速度修改`m_DesiredPosition`变量，使用以下代码行：

```cpp
m_DesiredPosition += player->m_Velocity * 2;
```

由于我们的关卡是环绕的，如果您从关卡的一侧退出，您会重新出现在另一侧，我们需要调整摄像头的期望位置以适应这一点。如果没有以下代码行，当玩家移出关卡边界并出现在另一侧时，摄像头会突然发生剧烈的转变：

```cpp
if( abs(m_DesiredPosition.x - m_Position.x) > CANVAS_WIDTH ) {
    if( m_DesiredPosition.x > m_Position.x ) {
        m_Position.x += LEVEL_WIDTH;
    }
    else {
        m_Position.x -= LEVEL_WIDTH;
    }
}
if( abs(m_DesiredPosition.y - m_Position.y) > CANVAS_HEIGHT ) {
    if( m_DesiredPosition.y > m_Position.y ) {
        m_Position.y += LEVEL_HEIGHT;
    }
    else {
        m_Position.y -= LEVEL_HEIGHT;
    }
}
```

最后，我们将添加几行代码，使摄像头的当前位置平稳过渡到期望的位置。我们使用`delta_time`使这个过渡大约需要一秒钟。直接设置摄像头位置而不使用期望位置和过渡会导致新吸引器进入游戏时出现抖动。以下是过渡代码：

```cpp
m_Position.x = m_Position.x + (m_DesiredPosition.x - m_Position.x) * 
delta_time;
m_Position.y = m_Position.y + (m_DesiredPosition.y - m_Position.y) * 
delta_time;
```

现在我们已经分别看到了`Move`函数的所有行，让我们来看一下函数的完成新版本：

```cpp
void Camera::Move() {
    m_DesiredPosition = player->m_Position;
    m_DesiredPosition.x -= CANVAS_WIDTH / 2;
    m_DesiredPosition.y -= CANVAS_HEIGHT / 2;

    if( player->m_Active == false ) {
        m_Position.x = m_Position.x + (m_DesiredPosition.x - m_Position.x) 
        * delta_time;
        m_Position.y = m_Position.y + (m_DesiredPosition.y - m_Position.y) 
        * delta_time;
        return;
    }

    Projectile* projectile;
    std::vector<Projectile*>::iterator it;
    Vector2D attractor;

    for( it = projectile_pool->m_ProjectileList.begin(); 
        it != projectile_pool->m_ProjectileList.end(); it++ ) {
        projectile = *it;
            if( projectile->m_Active ) {
            attractor = projectile->m_Position;
            attractor -= player->m_Position;
            attractor.Normalize();
            attractor *= 5;
            m_DesiredPosition += attractor;
        }
    }
    m_DesiredPosition += player->m_Velocity * 2;

    if( abs(m_DesiredPosition.x - m_Position.x) > CANVAS_WIDTH ) {
        if( m_DesiredPosition.x > m_Position.x ) {
            m_Position.x += LEVEL_WIDTH;
        }
        else {
            m_Position.x -= LEVEL_WIDTH;
        }
    }

    if( abs(m_DesiredPosition.y - m_Position.y) > CANVAS_HEIGHT ) {
        if( m_DesiredPosition.y > m_Position.y ) {
            m_Position.y += LEVEL_HEIGHT;
        }
        else {
            m_Position.y -= LEVEL_HEIGHT;
        }
    }

    m_Position.x = m_Position.x + (m_DesiredPosition.x - m_Position.x) * 
    delta_time;
    m_Position.y = m_Position.y + (m_DesiredPosition.y - m_Position.y) * 
    delta_time;
}
```

# 编译并玩弄高级摄像头

当您构建了这个版本后，您会注意到摄像头会朝着您的飞船移动的方向前进。如果您开始射击，它会进一步向前移动。当敌方飞船靠近并向您射击时，摄像头也应该朝着这些抛射物的方向漂移。与以前一样，您可以通过在 Windows 或 Linux 命令提示符中输入以下行来编译和测试代码：

```cpp
em++ asteroid.cpp camera.cpp collider.cpp emitter.cpp enemy_ship.cpp finite_state_machine.cpp locator.cpp main.cpp particle.cpp player_ship.cpp projectile_pool.cpp projectile.cpp range.cpp render_manager.cpp shield.cpp ship.cpp star.cpp vector.cpp -o camera.html --preload-file sprites -std=c++17 -s USE_WEBGL2=1 -s USE_SDL=2 -s USE_SDL_IMAGE=2 -s SDL2_IMAGE_FORMATS=["png"] -s USE_SDL_IMAGE=2 -s SDL2_IMAGE_FORMATS=["png"]
```

现在我们已经有了我们应用程序的编译版本，我们应该运行它。新版本应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/4e7f8642-ae56-40d6-ad9d-4c43bdb3f11c.png)

图 11.1：添加了分割屏幕的新摄像头版本

正如您所看到的，摄像头并没有将玩家的飞船置于中心。摄像头的焦点主要是根据玩家飞船的速度投影在前方，由于敌方飞船和抛射物的原因稍微向右上方拖动。

不要忘记，您必须使用 Web 服务器或`emrun`来运行 WebAssembly 应用程序。如果您想使用`emrun`运行 WebAssembly 应用程序，您必须使用`--emrun`标志进行编译。Web 浏览器需要一个 Web 服务器来流式传输 WebAssembly 模块。如果您尝试直接从硬盘驱动器上的浏览器打开使用 WebAssembly 的 HTML 页面，那么 WebAssembly 模块将无法加载。

# 总结

我们开始本章是通过了解视频游戏中摄像头的历史。我们讨论的第一个摄像头是最简单的摄像头类型，有时被称为锁定摄像头。这是一种精确跟踪玩家位置的摄像头。之后，我们了解了 2D 空间中锁定摄像头的替代方案，包括引导玩家的摄像头。我们谈到了投影焦点摄像头，以及它们如何预测玩家的移动并根据玩家移动的方向向前投影摄像头的位置。然后我们讨论了摄像头吸引器，以及它们如何吸引摄像头的焦点到感兴趣的对象。在讨论了摄像头类型之后，我们创建了一个摄像头对象，并设计它来实现投影焦点和摄像头吸引器。我们实现了一个渲染管理器，并修改了所有的游戏对象，使其通过`RenderManager`类进行渲染。然后我们创建了一个`locator`对象，以帮助我们在画布上找到敌方飞船。

在下一章中，我们将学习如何为我们的游戏添加音效。


# 第十二章：音效

网络上的音频当前处于一种混乱状态，而且已经有一段时间了。很长一段时间以来，根据您使用的浏览器的不同，加载 MP3 与 OGG 文件存在问题。最近，浏览器阻止自动播放声音以防止令人讨厌的音频垃圾的问题。Chrome 中的这一功能有时似乎会在我们的游戏中播放音频时出现问题。我注意到，如果 Chrome 最初没有播放音频，通常在重新加载页面后就会播放。我在 Firefox 上没有遇到这个问题。

您需要在构建中包含几个图像和音频文件才能使该项目正常工作。确保您从项目的 GitHub 中包含`/Chapter12/sprites/`文件夹以及`/Chapter12/audio/`文件夹。如果您还没有下载 GitHub 项目，可以在[`github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly`](https://github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly)上获取它。

Emscripten 对音频播放的支持并不如我所希望的那样好。在留言板上，Emscripten 的支持者很快就把音频的状态归咎于网络而不是 Emscripten 本身，这种评估有一定道理。Emscripten 的常见问题解答声称，Emscripten 支持使用 SDL1 音频、SDL2 音频和 OpenAL，但根据我的经验，我发现使用非常有限的 SDL2 音频提供了最佳的结果。我将尽量减少对 SDL2 音频的使用，使用音频队列而不是混合音效。您可能希望扩展或修改我在这里所做的工作。理论上，OpenAL 应该可以与 Emscripten 一起工作，尽管我在这方面并不太幸运。此外，您可能希望查看`SDL_MixAudio`（[`wiki.libsdl.org/SDL_MixAudio`](https://wiki.libsdl.org/SDL_MixAudio)）和`SDL_AudioStream`（[`wiki.libsdl.org/Tutorials/AudioStream`](https://wiki.libsdl.org/Tutorials/AudioStream)）来改进游戏中的音频系统，但请注意，网络上的音频流和混音的性能和支持可能还没有准备好投入实际使用。

本章将涵盖以下主题：

+   获取音效的地方

+   使用 Emscripten 制作简单音频

+   向我们的游戏添加声音

+   编译和运行

# 获取音效的地方

有很多很棒的地方可以在线获取音乐和音效。我使用 SFXR（[`www.drpetter.se/project_sfxr.html`](http://www.drpetter.se/project_sfxr.html)）生成了本章中使用的音效，这是一个用于生成类似 NES 游戏中听到的老式 8 位音效的工具。这种类型的音效可能不符合您的口味。OpenGameArt.org 还有大量的音效（[`opengameart.org/art-search-advanced?keys=&field_art_type_tid%5B%5D=13&sort_by=count&sort_order=DESC`](https://opengameart.org/art-search-advanced?keys=&field_art_type_tid%5B%5D=13&sort_by=count&sort_order=DESC)）和音乐（[`opengameart.org/art-search-advanced?keys=&field_art_type_tid%5B%5D=12&sort_by=count&sort_order=DESC`](https://opengameart.org/art-search-advanced?keys=&field_art_type_tid%5B%5D=12&sort_by=count&sort_order=DESC)）的大量开放许可，因此在使用该网站上的任何音频或艺术之前，请确保您仔细阅读许可证。

# 使用 Emscripten 制作简单音频

在我们将音效添加到主游戏之前，我将向您展示如何在`audio.c`文件中制作音频播放器，以演示**SDL 音频**如何在 WebAssembly 应用程序中用于播放音效。该应用程序将使用五种我们将在游戏中使用的音效，并允许用户按数字键 1 到 5 来播放所有选择的音效。我将首先向您展示代码分为两个部分，然后我将向您解释每一部分的功能。以下是`audio.c`中的所有代码，除了`main`函数： 

```cpp
#include <SDL2/SDL.h>
#include <emscripten.h>
#include <stdio.h>
#include <stdbool.h>

#define ENEMY_LASER "/audio/enemy-laser.wav"
#define PLAYER_LASER "/audio/player-laser.wav"
#define LARGE_EXPLOSION "/audio/large-explosion.wav"
#define SMALL_EXPLOSION "/audio/small-explosion.wav"
#define HIT "/audio/hit.wav"

SDL_AudioDeviceID device_id;
SDL_Window *window;
SDL_Renderer *renderer;
SDL_Event event;

struct audio_clip {
    char file_name[100];
    SDL_AudioSpec spec;
    Uint32 len;
    Uint8 *buf;
} enemy_laser_snd, player_laser_snd, small_explosion_snd, large_explosion_snd, hit_snd;

void play_audio( struct audio_clip* clip ) {
    int success = SDL_QueueAudio(device_id, clip->buf, clip->len);
    if( success < 0 ) {
        printf("SDL_QueueAudio %s failed: %s\n", clip->file_name, 
        SDL_GetError());
    }
}

void init_audio( char* file_name, struct audio_clip* clip ) {
    strcpy( clip->file_name, file_name );

    if( SDL_LoadWAV(file_name, &(clip->spec), &(clip->buf), &(clip->len)) 
    == NULL ) {
        printf("Failed to load wave file: %s\n", SDL_GetError());
    }
}

void input_loop() {
    if( SDL_PollEvent( &event ) ){
        if( event.type == SDL_KEYUP ) {
            switch( event.key.keysym.sym ){
                case SDLK_1:
                    printf("one key release\n");
                    play_audio(&enemy_laser_snd);
                    break;
                case SDLK_2:
                    printf("two key release\n");
                    play_audio(&player_laser_snd);
                    break;
                case SDLK_3:
                    printf("three key release\n");
                    play_audio(&small_explosion_snd);
                    break;
                case SDLK_4:
                    printf("four key release\n");
                    play_audio(&large_explosion_snd);
                    break;
                case SDLK_5:
                    printf("five key release\n");
                    play_audio(&hit_snd);
                    break;
                default:
                    printf("unknown key release\n");
                    break;
            }
        }
    }
}
```

在`audio.c`文件的末尾，我们有我们的`main`函数：

```cpp
int main() {
    if((SDL_Init(SDL_INIT_VIDEO|SDL_INIT_AUDIO)==-1)) {
        printf("Could not initialize SDL: %s.\n", SDL_GetError());
        return 0;
    }

    SDL_CreateWindowAndRenderer( 320, 200, 0, &window, &renderer );

    init_audio( ENEMY_LASER, &enemy_laser_snd );
    init_audio( PLAYER_LASER, &player_laser_snd );
    init_audio( SMALL_EXPLOSION, &small_explosion_snd );
    init_audio( LARGE_EXPLOSION, &large_explosion_snd );
    init_audio( HIT, &hit_snd );

    device_id = SDL_OpenAudioDevice(NULL, 0, &(enemy_laser_snd.spec), 
                                    NULL, 0);

    if (device_id == 0) {
        printf("Failed to open audio: %s\n", SDL_GetError());
    }

    SDL_PauseAudioDevice(device_id, 0);

    emscripten_set_main_loop(input_loop, 0, 0);

    return 1;
}
```

现在你已经看到了整个`audio.c`文件，让我们来看看它的所有部分。在这个文件的顶部，我们有我们的`#include`和`#define`宏：

```cpp
#include <SDL2/SDL.h>
#include <emscripten.h>
#include <stdio.h>
#include <stdbool.h>

#define ENEMY_LASER "/audio/enemy-laser.wav"
#define PLAYER_LASER "/audio/player-laser.wav"
#define LARGE_EXPLOSION "/audio/large-explosion.wav"
#define SMALL_EXPLOSION "/audio/small-explosion.wav"
#define HIT "/audio/hit.wav"
```

之后，我们有我们的 SDL 特定的全局变量。我们需要一个`SDL_AudioDeviceID`用于我们的音频输出。`SDL_Window`、`SDL_Renderer`和`SDL_Event`在大多数早期章节中都被使用过，现在应该很熟悉了：

```cpp
SDL_AudioDeviceID device_id;
SDL_Window *window;
SDL_Renderer *renderer;
SDL_Event event;
```

我们正在开发一个 C 程序，而不是 C++程序，所以我们将使用一个结构来保存我们的音频数据，而不是一个类。我们将创建一个名为`audio_clip`的 C 结构，它将保存我们应用程序中将要播放的音频的所有信息。这些信息包括一个包含文件名的字符串。它包含一个保存音频规格的`SDL_AudioSpec`对象。它还包含音频片段的长度和一个指向 8 位数据缓冲区的指针，该缓冲区保存了音频片段的波形数据。在定义了`audio_clip`结构之后，创建了五个该结构的实例，我们稍后将能够使用这些声音进行播放：

```cpp
struct audio_clip {
    char file_name[100];
    SDL_AudioSpec spec;
    Uint32 len;
    Uint8 *buf;
} enemy_laser_snd, player_laser_snd, small_explosion_snd, large_explosion_snd, hit_snd;
```

在我们定义了`audio_clip`结构之后，我们需要创建一个函数来播放该结构中的音频。这个函数调用`SDL_QueueAudio`，传入全局`device_id`、波形缓冲区的指针和片段的长度。`device_id`是对音频设备（声卡）的引用。`clip->buf`变量是一个指向包含我们将要加载的`.wav`文件的波形数据的缓冲区的指针。`clip->len`变量包含片段播放的时间长度：

```cpp
void play_audio( struct audio_clip* clip ) {
    int success = SDL_QueueAudio(device_id, clip->buf, clip->len);
    if( success < 0 ) {
        printf("SDL_QueueAudio %s failed: %s\n", clip->file_name, 
        SDL_GetError());
    }
}
```

我们需要的下一个函数是初始化我们的`audio_clip`，这样我们就可以将它传递到`play_audio`函数中。这个函数设置了我们的`audio_clip`的文件名，并加载了一个波形文件，设置了我们的`audio_clip`中的`spec`、`buf`和`len`值。如果调用`SDL_LoadWAV`失败，我们会打印出一个错误消息：

```cpp
void init_audio( char* file_name, struct audio_clip* clip ) {
    strcpy( clip->file_name, file_name );

    if( SDL_LoadWAV(file_name, &(clip->spec), &(clip->buf), &(clip-
        >len)) 
    == NULL ) {
        printf("Failed to load wave file: %s\n", SDL_GetError());
    }
}
```

`input_loop`现在应该看起来很熟悉了。该函数调用`SDL_PollEvent`并使用它返回的事件来检查键盘按键的释放。它检查释放了哪个键。如果该键是从一到五的数字键之一，那么使用 switch 语句调用`play_audio`函数，传入特定的`audio_clip`。我们使用按键释放而不是按键按下的原因是为了防止用户按住键时的按键重复。我们可以很容易地防止这种情况，但我正在尽量保持这个应用程序的代码尽可能简短。这是`input_loop`的代码：

```cpp
void input_loop() {
    if( SDL_PollEvent( &event ) ){
        if( event.type == SDL_KEYUP ) {
            switch( event.key.keysym.sym ){
                case SDLK_1:
                    printf("one key release\n");
                    play_audio(&enemy_laser_snd);
                    break;
                case SDLK_2:
                    printf("two key release\n");
                    play_audio(&player_laser_snd);
                    break;
                case SDLK_3:
                    printf("three key release\n");
                    play_audio(&small_explosion_snd);
                    break;
                case SDLK_4:
                    printf("four key release\n");
                    play_audio(&large_explosion_snd);
                    break;
                case SDLK_5:
                    printf("five key release\n");
                    play_audio(&hit_snd);
                    break;
                default:
                    printf("unknown key release\n");
                    break;
            }
        }
    }
}
```

和往常一样，`main`函数负责我们应用程序的所有初始化。除了我们在之前的应用程序中执行的初始化之外，我们还需要对我们的音频进行新的初始化。这就是`main`函数的新版本。

```cpp
int main() {
    if((SDL_Init(SDL_INIT_VIDEO|SDL_INIT_AUDIO)==-1)) {
        printf("Could not initialize SDL: %s.\n", SDL_GetError());
        return 0;
    }
    SDL_CreateWindowAndRenderer( 320, 200, 0, &window, &renderer );
    init_audio( ENEMY_LASER, &enemy_laser_snd );
    init_audio( PLAYER_LASER, &player_laser_snd );
    init_audio( SMALL_EXPLOSION, &small_explosion_snd );
    init_audio( LARGE_EXPLOSION, &large_explosion_snd );
    init_audio( HIT, &hit_snd );

    device_id = SDL_OpenAudioDevice(NULL, 0, &(enemy_laser_snd.spec), NULL, 
    0);

    if (device_id == 0) {
        printf("Failed to open audio: %s\n", SDL_GetError());
    }
    SDL_PauseAudioDevice(device_id, 0);
    emscripten_set_main_loop(input_loop, 0, 0);
    return 1;
}
```

我们改变的第一件事是我们对`SDL_Init`的调用。我们需要添加一个标志，告诉 SDL 初始化音频子系统。我们通过在传入的参数中添加`|SLD_INIT_AUDIO`来实现这一点，这将对参数进行位操作，并使用`SDL_INIT_AUDIO`标志。在新版本的`SDL_Init`之后，我们将创建窗口和渲染器，这在这一点上我们已经做了很多次。

`init_audio`调用都是新的，并初始化了我们的`audio_clip`结构：

```cpp
init_audio( ENEMY_LASER, &enemy_laser_snd );
init_audio( PLAYER_LASER, &player_laser_snd );
init_audio( SMALL_EXPLOSION, &small_explosion_snd );
init_audio( LARGE_EXPLOSION, &large_explosion_snd );
init_audio( HIT, &hit_snd );
```

接下来，我们需要调用`SDL_OpenAudioDevice`并检索设备 ID。打开音频设备需要一个默认规范，它通知音频设备您想要播放的声音剪辑的质量。确保选择一个声音文件，其质量水平是您想在游戏中播放的一个很好的例子。在我们的代码中，我们选择了`enemy_laser_snd`。我们还需要调用`SDL_PauseAudioDevice`。每当创建新的音频设备时，默认情况下会暂停。调用`SDL_PauseAudioDevice`并将`0`作为第二个参数传递进去会取消暂停我们刚刚创建的音频设备。起初我觉得有点困惑，但请记住，对`SDL_PauseAudioDevice`的后续调用实际上是取消暂停音频剪辑：

```cpp
device_id = SDL_OpenAudioDevice(NULL, 0, &(enemy_laser_snd.spec), NULL, 0);

if (device_id == 0) {
    printf("Failed to open audio: %s\n", SDL_GetError());
}

SDL_PauseAudioDevice(device_id, 0);
```

在返回之前，我们将做的最后一件事是将我们的循环设置为我们之前创建的`input_loop`函数：

```cpp
emscripten_set_main_loop(input_loop, 0, 0);
```

现在我们有了代码，我们应该编译和测试我们的`audio.c`文件：

```cpp
emcc audio.c --preload-file audio -s USE_SDL=2 -o audio.html
```

我们需要预加载音频文件夹，以便在虚拟文件系统中访问`.wav`文件。然后，在 Web 浏览器中加载`audio.html`，使用 emrun 提供文件，或者使用其他替代 Web 服务器。当您在 Chrome 中加载应用程序时，可能会遇到一些小困难。Chrome 的新版本已添加了检查，以防止未经请求的音频播放，以防止一些令人讨厌的垃圾邮件。有时，这种检查过于敏感，这可能会阻止我们游戏中的音频运行。如果发生这种情况，请尝试在 Chrome 浏览器中重新加载页面。有时，这可以解决问题。另一种防止这种情况发生的方法是切换到 Firefox。

# 向我们的游戏添加声音

现在我们了解了如何在 Web 上让 SDL 音频工作，我们可以开始向我们的游戏添加音效。我们的游戏中不会使用混音器，因此一次只会播放一个音效。因此，我们需要将一些声音分类为**优先**音效。如果触发了优先音效，声音队列将被清除，并且该音效将运行。我们还希望防止我们的声音队列变得太长，因此如果其中有两个以上的项目，我们将清除我们的声音队列。不要害怕！当我们到达代码的那部分时，我会重复所有这些。

# 更新 game.hpp

我们需要改变的第一件事是我们的`game.hpp`文件。我们需要添加一个新的`Audio`类，以及其他新代码来支持我们游戏中的音频。在`game.hpp`文件的顶部附近，我们将添加一系列`#define`宏来定义我们声音效果`.wav`文件的位置：

```cpp
#define ENEMY_LASER (char*)"/audio/enemy-laser.wav"
#define PLAYER_LASER (char*)"/audio/player-laser.wav"
#define LARGE_EXPLOSION (char*)"/audio/large-explosion.wav"
#define SMALL_EXPLOSION (char*)"/audio/small-explosion.wav"
#define HIT (char*)"/audio/hit.wav"
```

在我们的类声明列表的顶部，我们应该添加一个名为`Audio`的新类声明：

```cpp
class Audio;
class Ship;
class Particle;
class Emitter;
class Collider;
class Asteroid;
class Star;
class PlayerShip;
class EnemyShip;
class Projectile;
class ProjectilePool;
class FiniteStateMachine;
class Camera;
class RenderManager;
class Locator;
```

然后，我们将定义新的`Audio`类，它将与我们在`audio.c`文件中使用的`audio_clip`结构非常相似。这个类将有一个文件名，一个规范，一个长度（以运行时间为单位）和一个缓冲区。它还将有一个优先标志，当设置时，将优先于我们音频队列中当前的所有其他内容。最后，我们将在这个类中有两个函数；一个构造函数，用于初始化声音，和一个`Play`函数，用于实际播放声音。这就是类定义的样子：

```cpp
class Audio {
    public:
        char FileName[100];
        SDL_AudioSpec spec;
        Uint32 len;
        Uint8 *buf;
        bool priority = false;

        Audio( char* file_name, bool priority_value );
        void Play();
};
```

最后，我们需要定义一些外部与音频相关的全局变量。这些全局变量将是对将出现在我们的`main.cpp`文件中的变量的引用。其中大部分是`Audio`类的实例，将在我们的游戏中用于播放音频文件。最后一个变量是对我们的音频设备的引用：

```cpp
extern Audio* enemy_laser_snd;
extern Audio* player_laser_snd;
extern Audio* small_explosion_snd;
extern Audio* large_explosion_snd;
extern Audio* hit_snd;
extern SDL_AudioDeviceID device_id;
```

# 更新 main.cpp

在我们的`main.cpp`文件中要做的第一件事是定义我们在`game.hpp`文件的末尾定义为外部变量的与音频相关的全局变量：

```cpp
SDL_AudioDeviceID device_id;

Audio* enemy_laser_snd;
Audio* player_laser_snd;
Audio* small_explosion_snd;
Audio* large_explosion_snd;
Audio* hit_snd;
```

这些音效大多与我们游戏中发生碰撞时爆炸有关。因此，我们将在整个`collisions`函数中添加调用以播放这些音效。这是我们`collisions`函数的新版本：

```cpp
void collisions() {
 Asteroid* asteroid;
 std::vector<Asteroid*>::iterator ita;
    if( player->m_CurrentFrame == 0 && player->CompoundHitTest( star ) ) {
        player->m_CurrentFrame = 1;
        player->m_NextFrameTime = ms_per_frame;
        player->m_Explode->Run(); // added
        large_explosion_snd->Play();
    }
    if( enemy->m_CurrentFrame == 0 && enemy->CompoundHitTest( star ) ) {
        enemy->m_CurrentFrame = 1;
        enemy->m_NextFrameTime = ms_per_frame;
        enemy->m_Explode->Run(); // added
        large_explosion_snd->Play();
    }
    Projectile* projectile;
    std::vector<Projectile*>::iterator it;
    for(it=projectile_pool->m_ProjectileList.begin(); 
        it!=projectile_pool->m_ProjectileList.end(); 
        it++){
        projectile = *it;
        if( projectile->m_CurrentFrame == 0 && projectile->m_Active ) {
            for( ita = asteroid_list.begin(); ita != 
                asteroid_list.end(); 
                 ita++ ) {
                asteroid = *ita;
                if( asteroid->m_Active ) {
                    if( asteroid->HitTest( projectile ) ) {
                        projectile->m_CurrentFrame = 1;
                        projectile->m_NextFrameTime = ms_per_frame;
                        small_explosion_snd->Play();
                    }
                }
            }
            if( projectile->HitTest( star ) ){
                projectile->m_CurrentFrame = 1;
                projectile->m_NextFrameTime = ms_per_frame;
                small_explosion_snd->Play();
            }
            else if( player->m_CurrentFrame == 0 && ( projectile-
                     >HitTest( player ) ||
                      player->CompoundHitTest( projectile ) ) ) {
                if( player->m_Shield->m_Active == false ) {
                    player->m_CurrentFrame = 1;
                    player->m_NextFrameTime = ms_per_frame;
                    player->m_Explode->Run();
                    large_explosion_snd->Play();
                }
                else { hit_snd->Play(); }
                projectile->m_CurrentFrame = 1;
                projectile->m_NextFrameTime = ms_per_frame;
            }
            else if( enemy->m_CurrentFrame == 0 && ( projectile-
                     >HitTest( enemy ) ||
                      enemy->CompoundHitTest( projectile ) ) ) {
                if( enemy->m_Shield->m_Active == false ) {
                    enemy->m_CurrentFrame = 1;
                    enemy->m_NextFrameTime = ms_per_frame;
                    enemy->m_Explode->Run();
                    large_explosion_snd->Play();
                }
                else { hit_snd->Play(); }
                projectile->m_CurrentFrame = 1;
                projectile->m_NextFrameTime = ms_per_frame;
            }
        }
    }
    for( ita = asteroid_list.begin(); ita != asteroid_list.end(); 
         ita++ ) {
        asteroid = *ita;
        if( asteroid->m_Active ) {
            if( asteroid->HitTest( star ) ) {
                asteroid->Explode();
                small_explosion_snd->Play();
            }
        }
        else { continue; }
        if( player->m_CurrentFrame == 0 && asteroid->m_Active &&
            ( asteroid->HitTest( player ) || player->CompoundHitTest( 
            asteroid ) ) ) {
            if( player->m_Shield->m_Active == false ) {
                player->m_CurrentFrame = 1;
                player->m_NextFrameTime = ms_per_frame;
                player->m_Explode->Run();
                large_explosion_snd->Play();
            }
            else {
                asteroid->Explode();
                small_explosion_snd->Play();
            }
        }
        if( enemy->m_CurrentFrame == 0 && asteroid->m_Active &&
            ( asteroid->HitTest( enemy ) || enemy->CompoundHitTest( 
              asteroid ) ) ) {
            if( enemy->m_Shield->m_Active == false ) {
                enemy->m_CurrentFrame = 1;
                enemy->m_NextFrameTime = ms_per_frame;
                enemy->m_Explode->Run();
                large_explosion_snd->Play();
            }
            else {
                asteroid->Explode();
                small_explosion_snd->Play();
            }
        }
    }
}
```

现在声音将在几次爆炸和碰撞后播放；例如，在玩家爆炸后：

```cpp
player->m_Explode->Run(); 
large_explosion_snd->Play();
```

当敌舰爆炸时也会播放声音：

```cpp
enemy->m_Explode->Run();
large_explosion_snd->Play();
```

在一颗小行星爆炸后，我们也希望有同样的效果：

```cpp
asteroid->Explode();
small_explosion_snd->Play();
```

如果敌人的护盾被击中，我们想播放`hit`声音：

```cpp
if( enemy->m_Shield->m_Active == false ) {
    enemy->m_CurrentFrame = 1;
    enemy->m_NextFrameTime = ms_per_frame;
    enemy->m_Explode->Run();
    large_explosion_snd->Play();
}
else {
    hit_snd->Play();
}
```

同样，如果玩家的护盾被击中，我们还想播放`hit`声音：

```cpp
if( player->m_Shield->m_Active == false ) {
    player->m_CurrentFrame = 1;
    player->m_NextFrameTime = ms_per_frame;

    player->m_Explode->Run();
    large_explosion_snd->Play();
}
else {
    hit_snd->Play();
}
```

最后，我们需要更改`main`函数来初始化我们的音频。以下是完整的`main`函数代码：

```cpp
int main() {
    SDL_Init( SDL_INIT_VIDEO | SDL_INIT_AUDIO );
    int return_val = SDL_CreateWindowAndRenderer( CANVAS_WIDTH, 
    CANVAS_HEIGHT, 0, &window, &renderer );

    if( return_val != 0 ) {
        printf("Error creating renderer %d: %s\n", return_val, 
        IMG_GetError() );
        return 0;
    }

    SDL_SetRenderDrawColor( renderer, 0, 0, 0, 255 );
    SDL_RenderClear( renderer );
    last_frame_time = last_time = SDL_GetTicks();

    player = new PlayerShip();
    enemy = new EnemyShip();
    star = new Star();
    camera = new Camera(CANVAS_WIDTH, CANVAS_HEIGHT);
    render_manager = new RenderManager();
    locator = new Locator();
    enemy_laser_snd = new Audio(ENEMY_LASER, false);
 player_laser_snd = new Audio(PLAYER_LASER, false);
 small_explosion_snd = new Audio(SMALL_EXPLOSION, true);
 large_explosion_snd = new Audio(LARGE_EXPLOSION, true);
 hit_snd = new Audio(HIT, false);
 device_id = SDL_OpenAudioDevice(NULL, 0, &(enemy_laser_snd->spec), 
    NULL, 0);

 if (device_id == 0) {
 printf("Failed to open audio: %s\n", SDL_GetError());
 }
    int asteroid_x = 0;
    int asteroid_y = 0;
    int angle = 0;

    // SCREEN 1
    for( int i_y = 0; i_y < 8; i_y++ ) {
        asteroid_y += 100;
        asteroid_y += rand() % 400;
        asteroid_x = 0;
        for( int i_x = 0; i_x < 12; i_x++ ) {
            asteroid_x += 66;
            asteroid_x += rand() % 400;
            int y_save = asteroid_y;
            asteroid_y += rand() % 400 - 200;
            angle = rand() % 359;
            asteroid_list.push_back(
                new Asteroid( asteroid_x, asteroid_y,
                get_random_float(0.5, 1.0),
                DEG_TO_RAD(angle) ) );
            asteroid_y = y_save;
        }
    }
    projectile_pool = new ProjectilePool();
    emscripten_set_main_loop(game_loop, 0, 0);
    return 1;
}
```

我们需要对`main`函数进行的第一个更改是在`SDL_Init`调用中包括音频子系统的初始化：

```cpp
SDL_Init( SDL_INIT_VIDEO | SDL_INIT_AUDIO );
```

我们需要做的另一个更改是添加新的`Audio`对象和调用`SDL_OpenAudioDevice`：

```cpp
enemy_laser_snd = new Audio(ENEMY_LASER, false);
player_laser_snd = new Audio(PLAYER_LASER, false);
small_explosion_snd = new Audio(SMALL_EXPLOSION, true);
large_explosion_snd = new Audio(LARGE_EXPLOSION, true);
hit_snd = new Audio(HIT, false);

device_id = SDL_OpenAudioDevice(NULL, 0, &(enemy_laser_snd->spec), 
NULL, 0);

if (device_id == 0) {
    printf("Failed to open audio: %s\n", SDL_GetError());
}
```

# 更新 ship.cpp

`ship.cpp`文件有一个小的更改。我们正在添加一个调用，当飞船发射抛射物时播放声音。这发生在`Ship::Shoot()`函数中。您会注意到在调用`projectile->Launch`之后发生对`player_laser_snd->Play()`的调用：

```cpp
void Ship::Shoot() {
     Projectile* projectile;
     if( current_time - m_LastLaunchTime >= c_MinLaunchTime ) {
         m_LastLaunchTime = current_time;
         projectile = projectile_pool->GetFreeProjectile();
         if( projectile != NULL ) {
             projectile->Launch( m_Position, m_Direction );
             player_laser_snd->Play();
         }
     }
 }
```

# 新的 audio.cpp 文件

我们正在添加一个新的`audio.cpp`文件来实现`Audio`类的构造函数和`Audio`类的`Play`函数。以下是完整的`audio.cpp`文件：

```cpp
#include "game.hpp"

Audio::Audio( char* file_name, bool priority_value ) {
    strcpy( FileName, file_name );
    priority = priority_value;

    if( SDL_LoadWAV(FileName, &spec, &buf, &len) == NULL ) {
        printf("Failed to load wave file: %s\n", SDL_GetError());
    }
}

void Audio::Play() {
    if( priority || SDL_GetQueuedAudioSize(device_id) > 2 ) {
        SDL_ClearQueuedAudio(device_id);
    }

    int success = SDL_QueueAudio(device_id, buf, len);
    if( success < 0 ) {
        printf("SDL_QueueAudio %s failed: %s\n", FileName, SDL_GetError());
    }
}
```

该文件中的第一个函数是`Audio`类的构造函数。此函数将`FileName`属性设置为传递的值，并设置`priority`值。它还从传递的文件名加载波形文件，并使用`SDL_LoadWAV`文件设置`spec`、`buf`和`len`属性。

`Audio::Play()`函数首先查看这是否是高优先级音频，或者音频队列的大小是否大于两个声音。如果是这种情况，我们会清空音频队列：

```cpp
if( priority || SDL_GetQueuedAudioSize(device_id) > 2 ) {
    SDL_ClearQueuedAudio(device_id);
}
```

我们这样做是因为我们不想混合音频。我们正在按顺序播放音频。如果我们有一个优先级音频剪辑，我们希望清空队列，以便音频立即播放。如果队列太长，我们也希望这样做。然后我们将调用`SDL_QueueAudio`来排队播放此声音以尽快播放：

```cpp
int success = SDL_QueueAudio(device_id, buf, len);
if( success < 0 ) {
 printf("SDL_QueueAudio %s failed: %s\n", FileName, SDL_GetError());
}
```

现在，我们应该准备编译和运行我们的代码。

# 编译和运行

现在我们已经对我们的代码进行了所有必要的更改，我们可以使用 Emscripten 编译和运行我们的新代码：

```cpp
em++ asteroid.cpp audio.cpp camera.cpp collider.cpp emitter.cpp enemy_ship.cpp finite_state_machine.cpp locator.cpp main.cpp particle.cpp player_ship.cpp projectile_pool.cpp projectile.cpp range.cpp render_manager.cpp shield.cpp ship.cpp star.cpp vector.cpp -o sound_fx.html --preload-file audio --preload-file sprites -std=c++17 -s USE_WEBGL2=1 -s USE_SDL=2 -s USE_SDL_IMAGE=2 -s SDL2_IMAGE_FORMATS=["png"] -s USE_SDL_IMAGE=2 -s SDL2_IMAGE_FORMATS=["png"] 
```

没有添加新的标志来允许我们使用 SDL 音频库。但是，我们需要添加一个新的`--preload-file audio`标志，将新的`audio`目录加载到我们的虚拟文件系统中。一旦编译了游戏的新版本，您可以使用 emrun 来运行它（假设您在编译时包含了必要的 emrun 标志）。如果您愿意，您也可以选择一个不同的 Web 服务器来提供这些文件。

# 总结

我们已经讨论了网络上当前（混乱的）音频状态，并查看了 Emscripten 可用的音频库。我提到了一些可以获得免费音效的地方。我们使用 C 和 Emscripten 创建了一个简单的音频应用程序，允许我们播放一系列音频文件。然后我们为我们的游戏添加了音效，包括爆炸和激光声音。我们修改了`main()`函数中的初始化代码，以初始化 SDL 音频子系统。我们添加了一个新的`Shoot`函数，供我们的飞船在发射抛射物时使用。我们还创建了一个新的`Audio`类来帮助我们播放我们的音频文件。

在下一章中，我们将学习如何为我们的游戏添加一些物理效果。


# 第十三章：游戏物理学

我们的游戏中已经有一些物理学。我们的每艘飞船都有速度和加速度。它们也至少遵守了牛顿的一些定律并保持动量。所有这些早些时候都添加了，没有引起太多轰动。计算机游戏中的物理学可以追溯到最初的计算机游戏《太空战！》，这个游戏启发了我们目前正在编写的游戏。在《太空战！》的原始版本中，太空飞船保持了动量，就像我们现在在游戏中做的那样。黑洞通过引力吸引太空飞船到游戏区域的中心。在创造经典游戏《乒乓球》之前，诺兰·布什内尔创造了《太空战！》的街机克隆版，名为《计算机太空》。《计算机太空》不像《乒乓球》那样受欢迎，诺兰·布什内尔将游戏的商业失败归咎于牛顿定律和公众对基本物理学的理解不足等原因之一。

根据史蒂文·肯特的《视频游戏的终极历史：从乒乓球到宝可梦及其后》，“计算机太空遵守第一定律——动量守恒。（布什内尔可能指的是艾萨克·牛顿的第一定律——物体保持恒定速度，除非受到外力作用。）这对于不理解这一点的人来说确实很困难。”

- 诺兰·布什内尔

物理学在游戏中很常见，但远非普遍。游戏所需的物理学类型高度依赖于游戏的类型。有一个名为“Bullet Physics”的 3D 物理库，但由于它是 3D 的，Bullet 对于我们在这个游戏中将使用的物理学来说是一个相当庞大的库。因此，我们将在游戏中集成一些简单的牛顿物理学，以增加一些额外的风味。我们的游戏中已经有牛顿第一定律的简单实现。当我们加速我们的太空飞船时，它会朝着同样的方向移动，直到我们通过使用向下箭头减速它，或者通过将飞船转向并加速到当前速度的相反方向来“翻转和燃烧”。

您需要在构建中包含几个图像和音频文件，以使此项目正常工作。确保您从项目的 GitHub 中包括`/Chapter13/sprites/`文件夹以及`/Chapter13/audio/`文件夹。如果您还没有下载 GitHub 项目，可以在[`github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly`](https://github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly)上获取它。

在本章中，我们将应用物理学的以下方面：

+   小行星、抛射物和太空飞船之间的弹性碰撞。

+   当我们的太空飞船射击时，应该有一个反冲（牛顿第三定律）。

+   恒星的引力应该吸引玩家的太空飞船。

# 牛顿第三定律

牛顿第三定律通常陈述为，“对于每一个动作，都有一个相等和相反的反作用力”。这意味着当物体 A 对物体 B 施加力时，物体 B 会以同样的力反作用于物体 A。一个例子是从枪中发射子弹。当持枪的人发射子弹时，枪会以子弹离开枪的同样力量产生反冲。这可能听起来违反直觉，因为子弹可以杀死人，但是枪的反冲并不会杀死开枪的人。这是因为枪比子弹大得多，而牛顿第一定律规定了“F = ma”，即力等于质量乘以加速度。换句话说，如果枪比子弹大 50 倍，那么同样的力只会使其加速到 1/50 的速度。我们将修改我们的太空飞船，使其在射出抛射物时，根据太空飞船和抛射物的相对质量，以相反方向加速。这将给我们的飞船炮筒一个反冲。

# 添加重力

在我们为飞船的火炮添加后坐力之后，我还想在我们的游戏中为飞船添加一个引力效应，当它们在星球附近一定距离内时，会将飞船吸引向星球。引力随着两个物体之间距离的平方减小。这很方便，因为这意味着我们可以用`MagSQ`函数计算引力效应，这比`Magnitude`函数运行得快得多。出于个人偏好，我选择不在抛射物和小行星上添加引力效应。如果你选择这样做，添加这种效应并不难。

# 改进碰撞

我们将改进游戏中飞船与小行星和抛射物之间的碰撞。为了简化事情，我们将使用弹性碰撞。弹性碰撞是指保持所有动能的碰撞。实际上，碰撞总是会损失一些能量，转化为热量或摩擦，即使是接近弹性碰撞的碰撞，比如台球。然而，使我们的碰撞完全弹性化简化了数学。在游戏中，简单的数学通常意味着更快的算法。

有关弹性碰撞的更多信息，维基百科有一篇很好的文章([http](https://en.wikipedia.org/wiki/Elastic_collision)[s://en.wikipedia.org/wiki/Elastic_collision](https://en.wikipedia.org/wiki/Elastic_collision))，讨论了我们将用来实现弹性碰撞函数的数学。

# 修改代码

在这一部分，我们将对我们的游戏对象进行一些更改。我们需要在我们的“碰撞器”类中添加质量和弹性碰撞。我们的星星应该能够产生引力，并以与距离的平方成反比的力吸引玩家和敌人的飞船。我们需要修改我们的碰撞函数，以在我们的飞船、小行星和抛射物之间添加弹性碰撞。

# 更改 game.hpp 文件

为了将物理学引入我们的游戏，我们需要修改几个类定义并添加新的`#define`宏。让我们从更新我们的`game.hpp`文件开始。我们需要添加的第一件事是`#define`，以设置星球质量的常量值。我希望在我们的`ElasticCollision`函数中检查星球质量的大常量值。如果我们弹性碰撞中的任一对象的质量与`STAR_MASS`相同，我们不希望加速该对象。实际上，如果你把一块岩石扔进太阳，你会在你扔岩石的方向上微微加速太阳。相对于太阳来说，这个量是如此之小，以至于不可检测。我们将为星球的质量设定一个固定值，任何质量与该值相同的物体在游戏中被击中时都不会加速。为此，我们需要添加以下`#define`：

```cpp
#define STAR_MASS 9999999
```

在添加了`#define`之后，我们需要修改我们的`Collider`类，给它一个新的`ElasticCollision`函数。这个函数将接收第二个`Collider`对象，并使用这两个对象的速度和质量来确定它们的新速度。我们还需要添加一个名为`m_Mass`的质量属性。最后，我们需要将两个属性移到我们的`Collider`类中，这些属性以前在`Collider`的子类中。这些变量是 2D`m_Direction`和`m_Velocity`向量，因为我们的弹性碰撞函数将需要这些数据来计算新的速度。这是新版本的`Collider`类的样子：

```cpp
class Collider {
    public:
        bool m_Active;
        float* m_ParentRotation;
        float* m_ParentX;
        float* m_ParentY;
        Vector2D m_TempPoint;

        bool CCHitTest( Collider* collider );

 void ElasticCollision( Collider* collider );
 float m_Mass;
 Vector2D m_Direction;
 Vector2D m_Velocity;
 Vector2D m_Position;

        float m_Radius;
        float m_SteeringRadius;
        float m_SteeringRadiusSQ;
        void SetParentInformation( float* rotation, float* x, float* y );

        Collider(float radius);
        bool HitTest( Collider *collider );
        bool SteeringLineTest( Vector2D &p1, Vector2D &p2 );
        bool SteeringRectTest( Vector2D &start_point, Vector2D 
                               &end_point );
        void WrapPosition();
};
```

我们添加的四行代码位于这个新版本的类的中心附近：

```cpp
void ElasticCollision( Collider* collider );
float m_Mass;
Vector2D m_Direction;
Vector2D m_Velocity;
```

在将`m_Direction`和`m_Velocity`添加到我们的`Collider`类之后，我们需要从三个子类中删除`m_Velocity`，这些子类在我们游戏的先前版本中有这些代码。我们需要从`Asteroid`、`Ship`和`Projectile`类中删除这些属性。以下是我们需要删除的两行：

```cpp
Vector2D m_Direction;
Vector2D m_Velocity;
```

在下面的代码片段中，我们有删除了那两行后的`Asteroid`类：

```cpp
class Asteroid : public Collider {
    public:
        SDL_Texture *m_SpriteTexture;
        SDL_Rect m_src = {.x = 0, .y = 0, .w = 16, .h = 16 };
        SDL_Rect m_dest = {.x = 0, .y = 0, .w = 0, .h = 0 };

        Uint32 m_CurrentFrame = 0;
        int m_NextFrameTime;
        float m_Rotation;

        Emitter* m_Explode;
        Emitter* m_Chunks;

        Asteroid( float x, float y,
                  float velocity,
                  float rotation );

        void Move();
        void Render();
        void Explode();
};
```

在删除了那两行后，`Ship`类将会是什么样子：

```cpp
class Ship : public Collider {
    public:
        const float c_Acceleration = 10.0f;
        const float c_MaxVelocity = 100.0f;
        const int c_AliveTime = 2000;
        const Uint32 c_MinLaunchTime = 300;

        bool m_Accelerating = false;
        Uint32 m_LastLaunchTime;
        const int c_Width = 32;
        const int c_Height = 32;
        SDL_Texture *m_SpriteTexture;
        SDL_Rect src = {.x = 0, .y = 0, .w = 32, .h = 32 };

        Emitter* m_Explode;
        Emitter* m_Exhaust;
        Shield* m_Shield;
        std::vector<Collider*> m_Colliders;

        Uint32 m_CurrentFrame = 0;
        int m_NextFrameTime;
        float m_Rotation;

        void RotateLeft();
        void RotateRight();
        void Accelerate();
        void Decelerate();
        void CapVelocity();
        void Shoot();
        virtual void Move() = 0;
        Ship();
        void Render();
        bool CompoundHitTest( Collider* collider );
};
```

最后，在删除了那两行后，`Projectile`类将会是什么样子：

```cpp
class Projectile: public Collider {
    public:
        const char* c_SpriteFile = "sprites/ProjectileExp.png";
        const int c_Width = 16;
        const int c_Height = 16;
        SDL_Texture *m_SpriteTexture;
        SDL_Rect src = {.x = 0, .y = 0, .w = 16, .h = 16 };

        Uint32 m_CurrentFrame = 0;
        int m_NextFrameTime;
        const float c_Velocity = 300.0;
        const float c_AliveTime = 2000;
        float m_TTL;

        Projectile();
        void Move();
        void Render();
        void Launch(Vector2D &position, Vector2D &direction);
};
```

我们必须改变的最后一个类是我们的`Star`类。`Star`类现在将能够通过引力吸引我们游戏中的飞船。为了做到这一点，我们将添加一个常量属性，定义引力作用的最大范围。实际上，重力是无限延伸的，但是对于我们的游戏，当星星不在屏幕上（或者至少离得很远）时，我们不希望重力影响我们的飞船。因此，我们将限制引力效应的距离为 500 像素。我们还将在我们的类中添加一个名为`ShipGravity`的新函数。我们将把一个`Ship`对象传递给这个函数，该函数将根据到`Star`对象的平方距离来修改飞船的速度。这是新版本的`Star`类定义将会是什么样子的：

```cpp
class Star : public Collider {
    public:
        const float c_MaxGravityDistSQ = 250000.0; // 300 squared

        SDL_Texture *m_SpriteTexture;
        SDL_Rect m_src = {.x = 0, .y = 0, .w = 64, .h = 64 };
        SDL_Rect m_dest = {.x = 0, .y = 0, .w = 64, .h = 64 };

        std::vector<Emitter*> m_FlareList;

        Uint32 m_CurrentFrame = 0;
        int m_NextFrameTime;

        Star();

        void Move();
        void Render();

        void ShipGravity( Ship* s );
};
```

# 更改 collider.cpp

我们将要更改的下一个文件是`collider.cpp`文件，其中包含我们在`Collider`类定义中声明的函数。唯一的变化将是添加一个名为`ElasticCollision`的函数。该函数根据这些对象的质量和起始速度修改我们两个碰撞器的位置和速度。`ElasticCollision`函数看起来是这样的：

```cpp
void Collider::ElasticCollision( Collider* collider ) {
    if( collider->m_Mass == STAR_MASS || m_Mass == STAR_MASS ) {
        return;
    }

    Vector2D separation_vec = collider->m_Position - m_Position;

    separation_vec.Normalize();
    separation_vec *= collider->m_Radius + m_Radius;

    collider->m_Position = m_Position + separation_vec;

    Vector2D old_v1 = m_Velocity;
    Vector2D old_v2 = collider->m_Velocity;

    m_Velocity = old_v1 * ((m_Mass - collider->m_Mass)/(m_Mass + 
    collider->m_Mass)) +
    old_v2 * ((2 * collider->m_Mass) / (m_Mass + collider->m_Mass));

    collider->m_Velocity = old_v1 * ((2 * collider->m_Mass)/(m_Mass + 
    collider->m_Mass)) +
    old_v2 * ((collider->m_Mass - m_Mass)/(m_Mass + collider->m_Mass));
}
```

函数的第一件事是检查两个碰撞器中是否有一个的质量是星星。如果有一个是星星，我们就不改变它们的速度。星星的速度不会改变，因为它太庞大而无法移动，而与星星碰撞的对象也不会改变其质量，因为它在碰撞中被摧毁：

```cpp
if( collider->m_Mass == STAR_MASS || m_Mass == STAR_MASS ) {
    return;
}
```

在质量检查之后，我们需要调整碰撞器的位置，以使它们不重叠。重叠可能发生是因为我们的对象的位置每一帧都在变化，并不是连续的。因此，我们需要移动其中一个对象的位置，使其与另一个对象轻微接触。更准确的做法是修改两个对象的位置，每个对象修改的量是另一个对象的一半，但是方向不同。为简单起见，我们只会改变一个碰撞器的位置：

```cpp
separation_vec.Normalize();
separation_vec *= collider->m_Radius + m_Radius;

collider->m_Position = m_Position + separation_vec;
```

之后，我们将使用这两个对象的质量和起始速度来修改这两个碰撞器对象的速度：

```cpp
Vector2D old_v1 = m_Velocity;
Vector2D old_v2 = collider->m_Velocity;

m_Velocity = old_v1 * ((m_Mass - collider->m_Mass)/(m_Mass + collider->m_Mass)) +
old_v2 * ((2 * collider->m_Mass) / (m_Mass + collider->m_Mass));

collider->m_Velocity = old_v1 * ((2 * collider->m_Mass)/(m_Mass + collider->m_Mass)) +
old_v2 * ((collider->m_Mass - m_Mass)/(m_Mass + collider->m_Mass));
```

如果您想了解我们用来计算新速度的公式，可以查看维基百科关于弹性碰撞的文章[`en.wikipedia.org/wiki/Elastic_collision`](https://en.wikipedia.org/wiki/Elastic_collision)。

# 对 star.cpp 的更改

在我们的`star.cpp`文件中，我们需要修改我们的`Star`类的构造函数，以及它的`Move`函数。我们还需要添加一个名为`ShipGravity`的新函数。我们将首先在我们的`Star`类构造函数的某处添加以下行：

```cpp
m_Mass = STAR_MASS;
```

之后，我们需要定义我们的`ShipGravity`函数。以下代码定义了该函数：

```cpp
void Star::ShipGravity( Ship* s ) {
    Vector2D dist_vec = m_Position - s->m_Position;
    float dist_sq = dist_vec.MagSQ();

    if( dist_sq < c_MaxGravityDistSQ ) {
        float force = (c_MaxGravityDistSQ / dist_sq) * delta_time;
        dist_vec.Normalize();
        dist_vec *= force;
        s->m_Velocity += dist_vec;
    }
}
```

第一行创建了一个`dist_vec`向量，它是表示星星位置和飞船位置之间距离的向量。第二行得到了星星和飞船之间的平方距离。之后，我们有一个`if`块，看起来是这样的：

```cpp
if( dist_sq < c_MaxGravityDistSQ ) {
    float force = (c_MaxGravityDistSQ / dist_sq) * delta_time;
    dist_vec.Normalize();
    dist_vec *= force;
    s->m_Velocity += dist_vec;
}
```

这个`if`块正在检查与引力影响飞船的最大距离的平方距离，我们在`c_MaxGravityDistSQ`常量中定义了这个距离。因为引力随着星球和我们飞船之间的距离的平方减小，我们通过将最大引力距离除以 50 倍距离的平方来计算标量力。50 的值是相当任意选择的，是我在数字上摸索直到引力感觉合适的结果。如果您希望引力的力量不同，可以选择不同的值。您还可以通过更改我们在`game.hpp`中定义的`c_MaxGravityDistSQ`的值来修改最大引力距离。以下行用于将我们的标量力值转换为指向我们星球的矢量力值：

```cpp
dist_vec.Normalize();
dist_vec *= force;
```

现在我们已经将`dist_vec`转换为一个指向我们星球的力向量，我们可以将该力向量添加到我们飞船的速度上，以在我们的飞船上创建引力效应：

```cpp
s->m_Velocity += dist_vec;
```

我们需要做的最后一个更改是`Move`函数。我们需要添加两个对`ShipGravity`函数的调用；一个用于在玩家身上创建引力效应，另一个用于在敌方飞船上创建引力效应。以下是`Move`函数的新版本：

```cpp
void Star::Move() {
    m_NextFrameTime -= diff_time;

    if( m_NextFrameTime <= 0 ) {
        ++m_CurrentFrame;
        m_NextFrameTime = ms_per_frame;
        if( m_CurrentFrame >= 8 ) {
            m_CurrentFrame = 0;
        }
    }

 ShipGravity( player );
 ShipGravity( enemy );
}
```

最后两行是新的。确保将这两行添加到`Move`函数中：

```cpp
ShipGravity( player );
ShipGravity( enemy );
```

# 更改`main.cpp`文件

在更新我们的`star.cpp`文件之后，我们需要更改`main.cpp`文件以整合我们的弹性碰撞。我们需要对`collisions()`函数进行所有这些更改。以下是`collisions`的完整新版本：

```cpp
void collisions() {
 Asteroid* asteroid;
 std::vector<Asteroid*>::iterator ita;
    if( player->m_CurrentFrame == 0 && player->CompoundHitTest( star ) ) {
        player->m_CurrentFrame = 1;
        player->m_NextFrameTime = ms_per_frame;
        player->m_Explode->Run();
        large_explosion_snd->Play();
    }
    if( enemy->m_CurrentFrame == 0 && enemy->CompoundHitTest( star ) ) {
        enemy->m_CurrentFrame = 1;
        enemy->m_NextFrameTime = ms_per_frame;
        enemy->m_Explode->Run();
        large_explosion_snd->Play();
    }
    Projectile* projectile;
    std::vector<Projectile*>::iterator it;
    for(it=projectile_pool->m_ProjectileList.begin(); 
    it!=projectile_pool->m_ProjectileList.end();
    it++) {
        projectile = *it;
        if( projectile->m_CurrentFrame == 0 && projectile->m_Active ) {
            for( ita = asteroid_list.begin(); ita != asteroid_list.end(); 
                 ita++ 
            ) {
                asteroid = *ita;
                if( asteroid->m_Active ) {
                    if( asteroid->HitTest( projectile ) ) {
 asteroid->ElasticCollision( projectile );
                        projectile->m_CurrentFrame = 1;
                        projectile->m_NextFrameTime = ms_per_frame;
                        small_explosion_snd->Play();
                    }
                }
            }
            if( projectile->HitTest( star ) ){
                projectile->m_CurrentFrame = 1;
                projectile->m_NextFrameTime = ms_per_frame;
                small_explosion_snd->Play();
            }
            else if( player->m_CurrentFrame == 0 && ( projectile->HitTest( 
            player ) ||
                      player->CompoundHitTest( projectile ) ) ) {
                if( player->m_Shield->m_Active == false ) {
                    player->m_CurrentFrame = 1;
                    player->m_NextFrameTime = ms_per_frame;
                    player->m_Explode->Run();
                    large_explosion_snd->Play();
                }
                else {
                    hit_snd->Play();
 player->ElasticCollision( projectile );
                }
                projectile->m_CurrentFrame = 1;
                projectile->m_NextFrameTime = ms_per_frame;
            }
            else if( enemy->m_CurrentFrame == 0 && ( projectile-
            >HitTest( enemy ) || enemy->CompoundHitTest( projectile ) ) 
             ) {
                if( enemy->m_Shield->m_Active == false ) {
                    enemy->m_CurrentFrame = 1;
                    enemy->m_NextFrameTime = ms_per_frame;
                    enemy->m_Explode->Run();
                    large_explosion_snd->Play();
                }
                else {
                    enemy->ElasticCollision( projectile );
                    hit_snd->Play();
                }
                projectile->m_CurrentFrame = 1;
                projectile->m_NextFrameTime = ms_per_frame;
            }
        }
    }
    for( ita = asteroid_list.begin(); ita != asteroid_list.end(); ita++ ) {
        asteroid = *ita;
        if( asteroid->m_Active ) {
            if( asteroid->HitTest( star ) ) {
                asteroid->Explode();
                small_explosion_snd->Play();
            }
        }
        else { continue; }
        if( player->m_CurrentFrame == 0 && asteroid->m_Active &&
            ( asteroid->HitTest( player ) || player->CompoundHitTest( 
            asteroid ) ) ) {
            if( player->m_Shield->m_Active == false ) {
                player->m_CurrentFrame = 1;
                player->m_NextFrameTime = ms_per_frame;
                player->m_Explode->Run();
                large_explosion_snd->Play();
            }
            else {
 player->ElasticCollision( asteroid );
                small_explosion_snd->Play();
            }
        }
        if( enemy->m_CurrentFrame == 0 && asteroid->m_Active &&
            ( asteroid->HitTest( enemy ) || enemy->CompoundHitTest( 
            asteroid ) ) ) {
            if( enemy->m_Shield->m_Active == false ) {
                enemy->m_CurrentFrame = 1;
                enemy->m_NextFrameTime = ms_per_frame;
                enemy->m_Explode->Run();
                large_explosion_snd->Play();
            }
            else {
 enemy->ElasticCollision( asteroid );
                small_explosion_snd->Play();
            }
        }
    }
    Asteroid* asteroid_1;
    Asteroid* asteroid_2;
    std::vector<Asteroid*>::iterator ita_1;
    std::vector<Asteroid*>::iterator ita_2;
    for( ita_1 = asteroid_list.begin(); ita_1 != asteroid_list.end(); 
         ita_1++ ) {
        asteroid_1 = *ita_1;
        if( !asteroid_1->m_Active ) { continue; }
        for( ita_2 = ita_1+1; ita_2 != asteroid_list.end(); ita_2++ ) {
            asteroid_2 = *ita_2;
            if( !asteroid_2->m_Active ) { continue; }
            if( asteroid_1->HitTest( asteroid_2 ) ) {
 asteroid_1->ElasticCollision( asteroid_2 );
            }
        }
    }
}
```

在此函数的第一部分中，我们循环遍历抛射物并检查它们是否击中了小行星或飞船。如果抛射物在飞船启用护盾时击中了小行星或飞船，我们希望创建一个弹性碰撞。抛射物仍将被摧毁，但飞船或小行星的速度将根据碰撞进行修改。以下是`projectile`循环的代码：

```cpp
for( it = projectile_pool->m_ProjectileList.begin(); it != projectile_pool->m_ProjectileList.end(); it++ ) {
    projectile = *it;
    if( projectile->m_CurrentFrame == 0 && projectile->m_Active ) {
        for( ita = asteroid_list.begin(); ita != asteroid_list.end(); 
        ita++ ) {
            asteroid = *ita;
            if( asteroid->m_Active ) {
                if( asteroid->HitTest( projectile ) ) {
 asteroid->ElasticCollision( projectile );
                    projectile->m_CurrentFrame = 1;
                    projectile->m_NextFrameTime = ms_per_frame;
                    small_explosion_snd->Play();
                }
            }
        }
        if( projectile->HitTest( star ) ){
            projectile->m_CurrentFrame = 1;
            projectile->m_NextFrameTime = ms_per_frame;
            small_explosion_snd->Play();
        }
        else if( player->m_CurrentFrame == 0 &&
                ( projectile->HitTest( player ) ||
                  player->CompoundHitTest( projectile ) ) ) {
            if( player->m_Shield->m_Active == false ) {
                player->m_CurrentFrame = 1;
                player->m_NextFrameTime = ms_per_frame;

                player->m_Explode->Run();
                large_explosion_snd->Play();
            }
            else {
                hit_snd->Play();
 player->ElasticCollision( projectile );
            }
            projectile->m_CurrentFrame = 1;
            projectile->m_NextFrameTime = ms_per_frame;
        }
        else if( enemy->m_CurrentFrame == 0 &&
                ( projectile->HitTest( enemy ) ||
                  enemy->CompoundHitTest( projectile ) ) ) {
            if( enemy->m_Shield->m_Active == false ) {
                enemy->m_CurrentFrame = 1;
                enemy->m_NextFrameTime = ms_per_frame;
                enemy->m_Explode->Run();
                large_explosion_snd->Play();
            }
            else {
 enemy->ElasticCollision( projectile );
                hit_snd->Play();
            }
            projectile->m_CurrentFrame = 1;
            projectile->m_NextFrameTime = ms_per_frame;
        }
    }
}
```

此循环执行的第一系列检查是针对每颗小行星。它寻找当前正在碰撞的活动小行星。如果这些条件为真，它首先调用`ElasticCollision`函数，传入抛射物：

```cpp
for( ita = asteroid_list.begin(); ita != asteroid_list.end(); ita++ ) {
    asteroid = *ita;
    if( asteroid->m_Active ) {
        if( asteroid->HitTest( projectile ) ) {
 asteroid->ElasticCollision( projectile );
            projectile->m_CurrentFrame = 1;
            projectile->m_NextFrameTime = ms_per_frame;
            small_explosion_snd->Play();
        }
    }
```

这段代码与早期版本相同，但增加了对`ElasticCollision`的调用：

```cpp
asteroid->ElasticCollision( projectile );
```

在我们循环遍历每个活动抛射物时，如果抛射物击中玩家飞船的护盾已经启用，我们将添加一个对`ElasticCollision`函数的调用：

```cpp
else if( player->m_CurrentFrame == 0 &&
        ( projectile->HitTest( player ) ||
          player->CompoundHitTest( projectile ) ) ) {
    if( player->m_Shield->m_Active == false ) {
        player->m_CurrentFrame = 1;
        player->m_NextFrameTime = ms_per_frame;
        player->m_Explode->Run();
        large_explosion_snd->Play();
    }
    else {
        hit_snd->Play();
 player->ElasticCollision( projectile );
    }
    projectile->m_CurrentFrame = 1;
    projectile->m_NextFrameTime = ms_per_frame;
}
```

当敌方飞船在护盾启用时被抛射物击中时，我们也会做同样的处理：

```cpp
    else if( enemy->m_CurrentFrame == 0 &&
            ( projectile->HitTest( enemy ) ||
              enemy->CompoundHitTest( projectile ) ) ) {
        if( enemy->m_Shield->m_Active == false ) {
            enemy->m_CurrentFrame = 1;
            enemy->m_NextFrameTime = ms_per_frame;
            enemy->m_Explode->Run();
            large_explosion_snd->Play();
        }
        else {
 enemy->ElasticCollision( projectile );
            hit_snd->Play();
        }
        projectile->m_CurrentFrame = 1;
        projectile->m_NextFrameTime = ms_per_frame;
    }
}
```

在循环遍历所有活动抛射物之后，`collisions`函数会循环遍历所有小行星，寻找小行星与飞船之间的碰撞。如果飞船没有启用护盾，飞船将被摧毁。我们不对代码的这部分进行任何修改。在我们的代码的早期版本中，如果飞船启用了护盾，我们会摧毁小行星。现在，我们将进行弹性碰撞，这将导致飞船和小行星相互弹开。这就是这个`asteroid`循环的样子：

```cpp
for( ita = asteroid_list.begin(); ita != asteroid_list.end(); ita++ ) {
    asteroid = *ita;
    if( asteroid->m_Active ) {
        if( asteroid->HitTest( star ) ) {
            asteroid->Explode();
            small_explosion_snd->Play();
        }
    }
    else {
        continue;
    }

    if( player->m_CurrentFrame == 0 &&
        asteroid->m_Active &&
        ( asteroid->HitTest( player ) ||
          player->CompoundHitTest( asteroid ) ) ) {
        if( player->m_Shield->m_Active == false ) {
            player->m_CurrentFrame = 1;
            player->m_NextFrameTime = ms_per_frame;

            player->m_Explode->Run();
            large_explosion_snd->Play();
        }
        else {
 player->ElasticCollision( asteroid );
            small_explosion_snd->Play();
        }
    }
    if( enemy->m_CurrentFrame == 0 &&
        asteroid->m_Active &&
        ( asteroid->HitTest( enemy ) ||
          enemy->CompoundHitTest( asteroid ) ) ) {
        if( enemy->m_Shield->m_Active == false ) {
            enemy->m_CurrentFrame = 1;
            enemy->m_NextFrameTime = ms_per_frame;

            enemy->m_Explode->Run();
            large_explosion_snd->Play();
        }
        else {
            enemy->ElasticCollision( asteroid );
            small_explosion_snd->Play();
        }
    }
}
```

现在有两个对`ElasticCollision`的调用。一个是当玩家飞船与小行星碰撞且玩家飞船的护盾已经启用时。另一个是当敌方飞船与小行星碰撞且敌方飞船的护盾已经启用时。

我们必须对我们的`collisions()`函数进行的最后一个修改是添加一个新的双重`asteroid`循环，它将循环遍历我们所有的小行星，寻找它们之间的碰撞。这会产生一个有趣的效果，小行星会像台球一样弹开。如果检测到两个小行星之间的碰撞，我们调用`ElasticCollision`：

```cpp
Asteroid* asteroid_1;
Asteroid* asteroid_2;

std::vector<Asteroid*>::iterator ita_1;
std::vector<Asteroid*>::iterator ita_2;

for( ita_1 = asteroid_list.begin(); ita_1 != asteroid_list.end(); ita_1++ ) {
    asteroid_1 = *ita_1;
    if( !asteroid_1->m_Active ) {
        continue;
    }

    for( ita_2 = ita_1+1; ita_2 != asteroid_list.end(); ita_2++ ) {
        asteroid_2 = *ita_2;
        if( !asteroid_2->m_Active ) {
            continue;
        }

        if( asteroid_1->HitTest( asteroid_2 ) ) {
 asteroid_1->ElasticCollision( asteroid_2 );
        }
    }
}
```

# 对 asteroid.cpp 和 projectile.cpp 的更改

我们需要对`asteroid.cpp`和`projectile.cpp`进行小的修改。我们为`Collider`类添加了一个名为`m_Mass`的新属性，因此所有从`Collider`派生的类都继承了这个属性。`m_Mass`属性被我们的`ElasticCollision`函数使用，以确定这些物体在弹性碰撞后将如何移动。飞船的质量与抛射物的质量之间的比率将用于计算飞船射击抛射物时发生的后坐力的大小。第一个修改是对`Projectile`类构造函数的修改。以下是该构造函数的新版本：

```cpp
Projectile::Projectile(): Collider(4.0) {
    m_Active = false;

    SDL_Surface *temp_surface = IMG_Load( c_SpriteFile );

    if( !temp_surface ) {
        printf("failed to load image: %s\n", IMG_GetError() );
        return;
    }

    m_SpriteTexture = SDL_CreateTextureFromSurface( renderer, temp_surface 
    );

    if( !m_SpriteTexture ) {
        printf("failed to create texture: %s\n", IMG_GetError() );
        return;
    }

    SDL_FreeSurface( temp_surface );

 m_Mass = 1.0;
}
```

唯一的修改是最后一行，我们将`m_Mass`设置为`1.0`：

```cpp
m_Mass = 1.0;
```

需要修改的下一个构造函数位于`asteroid.cpp`文件中。我们需要修改`Asteroid`类的构造函数。以下是`Asteroid`构造函数的新版本：

```cpp
Asteroid::Asteroid( float x, float y, float velocity, float rotation ): Collider(8.0) {
    SDL_Surface *temp_surface = IMG_Load( ADSTEROID_SPRITE_FILE );
    if( !temp_surface ) {
        printf("failed to load image: %s\n", IMG_GetError() );
        return;
    }
    else { printf("success creating asteroid surface\n"); }
    m_SpriteTexture = SDL_CreateTextureFromSurface( renderer, temp_surface 
    );
    if( !m_SpriteTexture ) {
        printf("failed to create texture: %s\n", IMG_GetError() );
        return;
    }
    else { printf("success creating asteroid texture\n"); }
    SDL_FreeSurface( temp_surface );
    m_Explode = new Emitter((char*)"/sprites/Explode.png", 100, 0, 360, 
    1000, 0.3, false, 20.0, 40.0, 10, 0, 0, 5, 1.0, 2.0, 1.0, 2.0,
    0xffffff, 0xffffff, 0.01, 10, false, false, 800, 8 ); 
    m_Explode->m_parent_rotation_ptr = &m_Rotation;
    m_Explode->m_parent_x_ptr = &(m_Position.x);
    m_Explode->m_parent_y_ptr = &(m_Position.y);
    m_Explode->m_Active = false;
    m_Chunks = new Emitter((char*)"/sprites/small-asteroid.png",40,0,360, 
    1000, 0.05, false, 80.0, 150.0, 5,0,0,10,2.0,2.0,0.25, 0.5, 0xffffff, 
    0xffffff, 0.1, 10, false, true, 1000, 8 ); 
    m_Chunks->m_parent_rotation_ptr = &m_Rotation;
    m_Chunks->m_parent_x_ptr = &m_Position.x;
    m_Chunks->m_parent_y_ptr = &m_Position.y;
    m_Chunks->m_Active = false;
    m_Position.x = x;
    m_Position.y = y;
    Vector2D direction;
    direction.x = 1;
    direction.Rotate( rotation );
    m_Direction = direction;
    m_Velocity = m_Direction * velocity;
    m_dest.h = m_src.h = m_dest.w = m_src.w = 16;
    m_Rotation = rotation;
    m_Active = true;
    m_CurrentFrame = 0;
    m_NextFrameTime = ms_per_frame;

    m_Mass = 100.0;
}
```

再次，我们要添加的唯一一行是最后一行，我们将`m_Mass`设置为`100.0`：

```cpp
m_Mass = 100.0;
```

# 对 ship.cpp 文件的更改

对`ship.cpp`文件的第一个更改将是对`Ship`构造函数的更改。这是一个简单的更改，我们需要在构造函数的最后进行设置飞船的质量为`50.0`。以下是`Ship`类构造函数的新版本：

```cpp
Ship::Ship() : Collider(8.0) {
    m_Rotation = PI;

    m_LastLaunchTime = current_time;

    m_Accelerating = false;

    m_Exhaust = new Emitter((char*)"/sprites/ProjectileExpOrange.png", 200,
                             -10, 10,
                             400, 1.0, true,
                             0.1, 0.1,
                             30, 0, 12, 0.5,
                             0.5, 1.0,
                             0.5, 1.0,
                             0xffffff, 0xffffff,
                             0.7, 10,
                             true, true,
                             1000, 6 );

    m_Exhaust->m_parent_rotation_ptr = &m_Rotation;
    m_Exhaust->m_parent_x_ptr = &(m_Position.x);
    m_Exhaust->m_parent_y_ptr = &(m_Position.y);
    m_Exhaust->m_x_adjustment = 10;
    m_Exhaust->m_y_adjustment = 10;
    m_Exhaust->m_Active = false;

    m_Explode = new Emitter((char*)"/sprites/Explode.png", 100,
                             0, 360,
                             1000, 0.3, false,
                             20.0, 40.0,
                             10, 0, 0, 5,
                             1.0, 2.0,
                             1.0, 2.0,
                             0xffffff, 0xffffff,
                             0.0, 10,
                             false, false,
                             800, 8 );

    m_Explode->m_parent_rotation_ptr = &m_Rotation;
    m_Explode->m_parent_x_ptr = &(m_Position.x);
    m_Explode->m_parent_y_ptr = &(m_Position.y);
    m_Explode->m_Active = false;

    m_Direction.y = 1.0;

    m_Active = true;
 m_Mass = 50.0;
}
```

唯一更改的是最后一行：

```cpp
m_Mass = 50.0;
```

我们还需要改变`Shoot`函数以添加后坐力。将添加几行代码来修改飞船的速度，通过添加一个与飞船面对的方向相反的向量，并且其大小基于发射的抛射物的速度和相对质量。以下是新的`Shoot`函数：

```cpp
void Ship::Shoot() {
    Projectile* projectile;
    if( current_time - m_LastLaunchTime >= c_MinLaunchTime ) {
        m_LastLaunchTime = current_time;
        projectile = projectile_pool->GetFreeProjectile();
        if( projectile != NULL ) {
            projectile->Launch( m_Position, m_Direction );
            player_laser_snd->Play();
            m_Velocity -= m_Direction * (projectile->c_Velocity * projectile->m_Mass / 
                                                                              m_Mass);
            CapVelocity();
        }
    }
}
```

这是我们要添加到函数中的两行代码：

```cpp
m_Velocity -= m_Direction * (projectile->c_Velocity * projectile->m_Mass / m_Mass);
CapVelocity();
```

# 编译 physics.html 文件

现在我们已经添加了物理效果，是时候编译我们的代码了。我们可以使用以下`em++`命令构建`physics.html`文件：

```cpp
em++ asteroid.cpp audio.cpp camera.cpp collider.cpp emitter.cpp enemy_ship.cpp finite_state_machine.cpp locator.cpp main.cpp particle.cpp player_ship.cpp projectile_pool.cpp projectile.cpp range.cpp render_manager.cpp shield.cpp ship.cpp star.cpp vector.cpp -o physics.html --preload-file audio --preload-file sprites -std=c++17 -s USE_WEBGL2=1 -s USE_SDL=2 -s USE_SDL_IMAGE=2 -s SDL2_IMAGE_FORMATS=["png"] -s USE_SDL_IMAGE=2 -s SDL2_IMAGE_FORMATS=["png"] 
```

以下的屏幕截图可能看起来与早期版本相似，但当你发射抛射物时，飞船将向后加速。如果你的护盾打开时与小行星碰撞，你将像台球一样弹开。离太阳太近，引力将开始吸引你的飞船：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/10269f25-3eed-46f3-9771-a8ed315e3005.png)

图 13.1：physics.html 截图

# 总结

在本章中，我们讨论了计算机游戏中物理学的历史，以及这一历史可以追溯到第一个计算机游戏*SpaceWar!*。我们谈到了我们游戏中已经有的物理学，其中包括动量守恒。我们简要讨论了牛顿第三定律及其在游戏中的应用，然后通过使用第三定律在我们的游戏中添加了更多的牛顿物理学。我们为我们的星球添加了一个引力场，并使其以与两个物体之间距离的平方成反比的力吸引我们游戏中的飞船。最后，我们为我们的飞船、抛射物和小行星添加了弹性碰撞。

在下一章中，我们将为我们的游戏添加**用户界面**（**UI**）。我们还将把游戏分成多个屏幕，并添加鼠标界面。
