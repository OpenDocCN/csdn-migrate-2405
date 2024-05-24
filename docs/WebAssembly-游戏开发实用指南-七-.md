# WebAssembly 游戏开发实用指南（七）

> 原文：[`annas-archive.org/md5/2bc11e3fb2b816b3a221f95dafc6aa63`](https://annas-archive.org/md5/2bc11e3fb2b816b3a221f95dafc6aa63)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：UI 和鼠标输入

**用户界面**（**UI**）定义了计算机程序与用户之间的交互。在我们的游戏中，到目前为止，我们的交互仅限于控制玩家飞船的键盘界面。当我们编写粒子系统配置应用程序时，我们使用 HTML 来定义更强大的用户界面，这使我们能够输入值来配置我们的粒子系统。从该用户界面，我们的代码必须间接地与 WebAssembly 代码进行交互。这是一种您可以继续在游戏中使用的技术，如果您想利用 HTML 来定义您的用户界面，但它有一些缺点。首先，我们可能希望用户界面元素覆盖我们游戏内容。通过 DOM 进行此类效果的效率不是很高。如果 UI 元素在游戏引擎内部呈现，游戏内的 UI 和对象之间的交互也更容易。此外，您可能正在开发 C/C++代码以用于平台以及 Web 发布。如果是这种情况，您可能不希望 HTML 在用户界面中扮演太大的角色。

在本章中，我们将在游戏中实现一些 UI 功能。我们需要实现一个`Button`类，这是最简单和最常见的 UI 元素之一。我们还需要实现一个单独的屏幕和游戏状态，以便我们可以有一个开始和结束游戏画面。

您需要在构建中包含几个图像和音频文件，以使此项目正常工作。确保您从此项目的 GitHub 存储库中包含`/Chapter14/sprites/`和`/Chapter14/audio/`文件夹。如果您还没有下载 GitHub 项目，可以在这里在线获取：[`github.com/PacktPublishing/Hands-On-Game-Development`](https://github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly)。

在本章中，我们将涵盖以下主题：

+   UI 需求

+   获取鼠标输入

+   创建一个按钮

+   开始游戏画面

+   游戏结束画面

# UI 需求

在实现 UI 时，我们需要做的第一件事是确定一些需求。我们的用户界面到底需要什么？其中的第一部分是决定我们游戏需要哪些游戏画面。这通常是游戏设计过程中早期就要做的事情，但因为我正在写一本关于 WebAssembly 的书，所以我把这一步留到了后面的章节。决定游戏需要哪些画面通常涉及故事板和一个过程，通过这个过程，您可以通过讨论（如果有多人在游戏上工作）或者思考用户将如何与您的网页以及网页上的游戏进行交互的方式来决定：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/44bf0fc4-4b90-44ee-bf06-3d7e6882c67e.png)

图 14.1：我们用户界面的故事板示例

您不必绘制故事板，但我发现在思考游戏 UI 所需的内容时很有用。当您需要将这些信息传达给另一名团队成员或艺术家时，它甚至更有用。在思考我们在这个游戏中需要什么之前的故事板时，我列出了以下需求清单：

+   开场画面

+   说明

+   播放按钮

+   游戏游玩画面

+   得分文本

+   游戏结束画面

+   你赢了的消息

+   你输了的消息

+   再玩一次按钮

# 开场画面

我们的游戏需要一个开场画面，原因有几个。首先，我们不希望用户加载网页后立即开始游戏。用户加载网页并不立即开始玩游戏有很多原因。如果他们的连接速度慢，他们可能在游戏加载时离开电脑，可能不会注意到游戏加载完成的那一刻。如果他们通过点击链接来到这个页面，他们可能还没有准备好在游戏加载完成后立即开始玩。在将玩家投入游戏之前，让玩家确认他们已经准备好是一个很好的做法。开场画面还应包括一些基本游戏玩法的说明。街机游戏在街机柜上放置简单的说明，告诉玩家他们必须做什么才能玩游戏。众所周知，游戏 Pong 在柜子上印有说明*避免错过球以获得高分*。不幸的是，我们没有街机柜来打印我们的说明，所以使用开场游戏画面是下一个最好的选择。我们还需要一个按钮，让用户在点击时开始玩游戏，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/d514eacc-d959-427c-96d8-92bff06984f1.png)

图 14.2：开场画面图像

# 游戏画面

游戏画面是我们一直拥有的画面。这是玩家在其中移动他们的太空飞船，试图摧毁敌人飞船的画面。我们可能不需要改变这个画面的工作方式，但我们需要根据游戏状态添加到这个画面的过渡。游戏需要在玩家点击按钮时从开场画面过渡到我们的游戏画面。如果任何一艘飞船被摧毁，玩家还需要从这个画面过渡到游戏结束画面。如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/2a9a73da-59ea-4d7f-9456-4c7faace707d.png)

图 14.3：原始画面现在是游戏画面

# 游戏结束画面

如果其中一艘飞船被摧毁，游戏就结束了。如果玩家的飞船被摧毁，那么玩家就输了游戏。如果敌人的飞船被摧毁，那么玩家就赢了游戏。*游戏结束画面*告诉我们游戏结束了，并告诉我们玩家是赢了还是输了。它还需要提供一个按钮，让我们的玩家如果愿意的话可以再次玩游戏。游戏结束画面如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/d1ba8bf3-352c-4a1c-9774-b335856ee951.png)

图 14.4：游戏结束画面

# 鼠标输入

在我们实现按钮之前，我们需要学习如何在 SDL 中使用鼠标输入。我们用来获取键盘输入的代码在我们的`main.cpp`文件中。在`input`函数内，您会找到对`SDL_PollEvent`的调用，然后是几个不同的 switch 语句。第一个 switch 语句检查`event.type`是否为`SDL_KEYDOWN`。第二个 switch 检查`event.key.keysym.sym`来查看我们按下了哪个键：

```cpp
if( SDL_PollEvent( &event ) ){
    switch( event.type ){
        case SDL_KEYDOWN:
            switch( event.key.keysym.sym ){
                case SDLK_LEFT:
                    left_key_down = true;
                    break;
                case SDLK_RIGHT:
                    right_key_down = true;
                    break;
                case SDLK_UP:
                    up_key_down = true;
                    break;
                case SDLK_DOWN:
                    down_key_down = true;
                    break;
                case SDLK_f:
                    f_key_down = true;
                    break;
                case SDLK_SPACE:
                    space_key_down = true;
                    break;
                default:
                    break;
            }
            break;
```

当我们寻找鼠标输入时，我们需要使用相同的`SDL_PollEvent`函数来检索我们的鼠标事件。我们关心的三个鼠标事件是`SDL_MOUSEMOTION`，`SDL_MOUSEBUTTONDOWN`和`SDL_MOUSEBUTTONUP`。一旦我们知道我们正在处理的鼠标事件的类型，我们就可以使用`SDL_GetMouseState`来找到鼠标事件发生时的`x`和`y`坐标：

```cpp
if(SDL_PollEvent( &event ) )
{
    switch (event.type)
    {
        case SDL_MOUSEMOTION:
        {
            int x_val = 0;
            int y_val = 0;
            SDL_GetMouseState( &x_val, &y_val );
            printf(”mouse move x=%d y=%d\n”, x_val, y_val);
        }
        case SDL_MOUSEBUTTONDOWN:
        {
            switch (event.button.button)
            {
                case SDL_BUTTON_LEFT:
                {
                    int x_val = 0;
                    int y_val = 0;
                    SDL_GetMouseState( &x_val, &y_val );
                    printf(”mouse down x=%d y=%d\n”, x_val, y_val);
                    break;
                }
                default:
                {
                    break;
                }
            }
            break;
        }
        case SDL_MOUSEBUTTONUP:
        {
            switch (event.button.button)
            {
                case SDL_BUTTON_LEFT:
                {
                    int x_val = 0;
                    int y_val = 0;
                    SDL_GetMouseState( &x_val, &y_val );
                    printf(”mouse up x=%d y=%d\n”, x_val, y_val);
                    break;
                }
                default:
                {
                    break;
                }
            }
            break;
        }
```

现在我们可以接收鼠标输入，让我们创建一个简单的用户界面按钮。

# 创建一个按钮

现在我们知道如何在 WebAssembly 中使用 SDL 捕获鼠标输入，我们可以利用这些知识创建一个可以被鼠标点击的按钮。我们需要做的第一件事是在`game.hpp`文件中创建一个`UIButton`类定义。我们的按钮将有多个与之关联的精灵纹理。按钮通常有悬停状态和点击状态，因此如果用户将鼠标悬停在按钮上或点击按钮，我们将希望显示我们精灵的另一个版本：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/647d63a3-ca68-451a-9781-0dd05a7f5597.png)

图 14.5：按钮状态

为了捕获这些事件，我们将需要函数来检测鼠标是否点击了我们的按钮或悬停在其上。以下是我们类定义的样子：

```cpp
class UIButton {
    public:
        bool m_Hover;
        bool m_Click;
        bool m_Active;
        void (*m_Callback)();

        SDL_Rect m_dest = {.x = 0, .y = 0, .w = 128, .h = 32 };
        SDL_Texture *m_SpriteTexture;
        SDL_Texture *m_ClickTexture;
        SDL_Texture *m_HoverTexture;

        UIButton( int x, int y,
        char* file_name, char* hover_file_name, char* click_file_name,
        void (*callback)() );

        void MouseClick(int x, int y);
        void MouseUp(int x, int y);
        void MouseMove( int x, int y );
        void KeyDown( SDL_Keycode key );
        void RenderUI();
};
```

前三个属性是按钮状态属性，告诉我们的渲染函数要绘制什么精灵，或者如果按钮处于非活动状态，则不要绘制任何内容。如果`m_Hover`属性为`true`，则会导致我们的渲染器绘制`m_HoverTexture`。如果`m_Click`属性为`true`，则会导致我们的渲染器绘制`m_ClickTexture`。最后，如果将`m_Active`设置为`false`，则会导致我们的渲染器不绘制任何内容。

以下一行是指向我们回调函数的函数指针：

```cpp
void (*m_Callback)();
```

这个函数指针在我们的构造函数中设置，是我们在有人点击按钮时调用的函数。在函数指针之后，我们有我们的目标矩形，它将在构造函数运行后具有按钮图像文件的位置、宽度和高度：

```cpp
SDL_Rect m_dest = {.x = 0, .y = 0, .w = 128, .h = 32 };
```

然后，我们有三个纹理。这些纹理用于根据我们之前讨论的状态标志在渲染时绘制图像：

```cpp
SDL_Texture *m_SpriteTexture;
SDL_Texture *m_ClickTexture;
SDL_Texture *m_HoverTexture;
```

接下来，我们有构造函数。此函数获取我们按钮的`x`和`y`屏幕坐标。之后，有三个字符串，它们是我们将用来加载纹理的三个 PNG 文件的位置。最后一个参数是回调函数的指针：

```cpp
UIButton( int x, int y,
         char* file_name, char* hover_file_name, char* click_file_name,
         void (*callback)() );
```

然后，根据鼠标的当前状态，我们将需要在调用`SDL_PollEvent`之后调用三个函数：

```cpp
void MouseClick(int x, int y);
void MouseUp(int x, int y);
void MouseMove( int x, int y );
```

`KeyDown`函数将在按下键时获取键码，如果键码与我们的热键匹配，我们希望将其用作使用鼠标点击按钮的替代方法：

```cpp
void KeyDown( SDL_Keycode key );
```

`RenderUI`函数类似于我们为其他对象创建的`Render`函数。`RenderUI`和`Render`之间的区别在于，当将精灵渲染到屏幕时，`Render`函数将考虑摄像机位置。`RenderUI`函数将始终在画布空间中进行渲染：

```cpp
void RenderUI();
```

在下一节中，我们将创建用户界面状态信息以跟踪当前屏幕。

# 屏幕状态

在我们开始向游戏添加新屏幕之前，我们需要创建一些屏幕状态。我们将在`main.cpp`文件中管理这些状态的大部分内容。不同的屏幕状态将需要不同的输入，将运行不同的逻辑和不同的渲染函数。我们将在我们代码的最高级别管理所有这些，作为我们游戏循环调用的函数。我们将在`game.hpp`文件中作为枚举定义可能的状态列表：

```cpp
enum SCREEN_STATE {
    START_SCREEN = 0,
    PLAY_SCREEN = 1,
    PLAY_TRANSITION = 2,
    GAME_OVER_SCREEN = 3,
    YOU_WIN_SCREEN = 4
};
```

您可能会注意到，即使只有三个不同的屏幕，我们总共有五种不同的屏幕状态。`START_SCREEN`和`PLAY_SCREEN`分别是开始屏幕和播放屏幕。`PLAY_TRANSITION`状态通过淡入游戏来在`START_SCREEN`和`PLAY_SCREEN`之间过渡屏幕，而不是突然切换到播放。我们将为游戏结束屏幕使用两种不同的状态。这些状态是`GAME_OVER_SCREEN`和`YOU_WIN_SCREEN`。这两种状态之间唯一的区别是游戏结束时显示的消息。

# 对 games.hpp 的更改

我们将需要对我们的`game.hpp`文件进行一些额外的更改。除了我们的`UIButton`类，我们还需要添加一个`UISprite`类定义文件。`UISprite`只是一个普通的在画布空间中绘制的图像。它除了作为 UI 元素呈现的精灵之外，不具有任何功能。定义如下：

```cpp
class UISprite {
    public:
        bool m_Active;
        SDL_Texture *m_SpriteTexture;
        SDL_Rect m_dest = {.x = 0, .y = 0, .w = 128, .h = 32 };
        UISprite( int x, int y, char* file_name );
        void RenderUI();
};
```

与按钮类似，它具有一个由`m_Active`属性表示的活动状态。如果此值为 false，则精灵将不会渲染。它还具有精灵纹理和目标属性，告诉渲染器要绘制什么以及在哪里绘制它：

```cpp
SDL_Texture *m_SpriteTexture;
SDL_Rect m_dest = {.x = 0, .y = 0, .w = 128, .h = 32 };
```

它有一个简单的构造函数，接受我们将在画布上呈现精灵的`x`和`y`坐标，以及虚拟文件系统中图像的文件名，我们将从中加载精灵：

```cpp
UISprite( int x, int y, char* file_name );
```

最后，它有一个名为`RenderUI`的渲染函数，将精灵呈现到画布上：

```cpp
void RenderUI();
```

# 修改 RenderManager 类

`RenderManager`类将需要一个新属性和一个新函数。在我们游戏的先前版本中，我们可以呈现一种类型的背景，那就是我们的滚动星空。当我们呈现我们的开始屏幕时，我想使用一个包含一些游戏玩法说明的新自定义背景。

这是`RenderManager`类定义的新版本：

```cpp
class RenderManager {
    public:
        const int c_BackgroundWidth = 800;
        const int c_BackgroundHeight = 600;
        SDL_Texture *m_BackgroundTexture;
        SDL_Rect m_BackgroundDest = {.x = 0, .y = 0, .w = 
        c_BackgroundWidth, .h = c_BackgroundHeight };
        SDL_Texture *m_StartBackgroundTexture;

        RenderManager();
        void RenderBackground();
        void RenderStartBackground(int alpha = 255);
        void Render( SDL_Texture *tex, SDL_Rect *src, SDL_Rect *dest, 
        float rad_rotation = 0.0,
                     int alpha = 255, int red = 255, int green = 255, 
                     int blue = 255 );
        void RenderUI( SDL_Texture *tex, SDL_Rect *src, SDL_Rect *dest, 
        float rad_rotation = 0.0,
                       int alpha = 255, int red = 255, int green = 255, 
                       int blue = 255 );
};
```

我们添加了一个新的`SDL_Texture`，我们将使用它在开始屏幕上呈现背景图像：

```cpp
SDL_Texture *m_StartBackgroundTexture;
```

除了新属性之外，我们还添加了一个新函数，在开始屏幕激活时呈现该图像：

```cpp
void RenderStartBackground(int alpha = 255);
```

传入此函数的 alpha 值将用于在`PLAY_TRANSITION`屏幕状态期间淡出开始屏幕。该过渡状态将在玩家点击“播放”按钮时开始，并持续约一秒钟。

# 新的外部变量

我们需要添加三个新的`extern`变量定义，这些变量将引用我们在`main.cpp`文件中声明的变量。其中两个变量是指向`UISprite`对象的指针，其中一个变量是指向`UIButton`的指针。以下是三个`extern`定义：

```cpp
extern UISprite *you_win_sprite;
extern UISprite *game_over_sprite;
extern UIButton* play_btn;
```

我们在游戏结束屏幕上使用这两个`UISprite`指针。第一个`you_win_sprite`是玩家赢得游戏时将显示的精灵。第二个精灵`game_over_sprite`是玩家失败时将显示的精灵。最后一个变量`play_btn`是在开始屏幕上显示的播放按钮。

# 对 main.cpp 的更改

我们从游戏循环内管理新的屏幕状态。因此，我们将在`main.cpp`文件中进行大部分更改。我们需要将`input`函数分解为三个新函数，分别用于我们的游戏屏幕中的每一个。我们需要将我们的`render`函数分解为`start_render`和`play_render`函数。我们不需要`end_render`函数，因为在显示结束屏幕时，我们将继续使用`play_render`函数。

我们还需要一个函数来显示开始屏幕和游戏屏幕之间的过渡。在游戏循环内，我们需要添加逻辑以根据当前屏幕执行不同的循环逻辑。

# 添加全局变量

我们需要对`main.cpp`文件进行的第一个更改是添加新的全局变量。我们将需要新的全局变量来表示我们的用户界面精灵和按钮。我们将需要一个新的全局变量来表示当前屏幕状态，状态之间的过渡时间，以及告诉我们玩家是否赢得了游戏的标志。以下是我们在`main.cpp`文件中需要的新全局变量：

```cpp
UIButton* play_btn;
UIButton* play_again_btn;
UISprite *you_win_sprite;
UISprite *game_over_sprite;
SCREEN_STATE current_screen = START_SCREEN;
int transition_time = 0;
bool you_win = false;
```

前两个变量是`UIButton`对象指针。第一个是`play_btn`，这是用户将点击以开始玩游戏的开始屏幕按钮。第二个是`play_again_btn`，这是玩家可以点击以重新开始游戏的游戏结束屏幕上的按钮。在 UIButtons 之后，我们有两个`UISprite`对象：

```cpp
UISprite *you_win_sprite;
UISprite *game_over_sprite;
```

这些是显示在游戏结束屏幕上的精灵。显示哪个精灵取决于玩家是否摧毁了敌舰还是相反。在这些精灵之后，我们有一个`SCREEN_STATE`变量，用于跟踪当前屏幕状态：

```cpp
SCREEN_STATE current_screen = START_SCREEN;
```

`transition_time`变量用于跟踪开始屏幕和游戏屏幕之间过渡状态中剩余的时间量。`you_win`标志在游戏结束时设置，并用于跟踪谁赢得了游戏。

# 输入函数

我们游戏的先前版本有一个单一的`input`函数，它使用`SDL_PollEvent`来轮询按键。在这个版本中，我们希望为三个屏幕状态中的每一个都有一个输入函数。我们应该做的第一件事是将原始的`input`函数重命名为`play_input`。这将不再是一个通用的输入函数，它只会执行游戏屏幕的输入功能。现在我们已经重命名了原始的输入函数，让我们定义开始屏幕的输入函数并称之为`start_input`：

```cpp
void start_input() {
    if(SDL_PollEvent( &event ) )
    {
        switch (event.type)
        {
            case SDL_MOUSEMOTION:
            {
                int x_val = 0;
                int y_val = 0;
                SDL_GetMouseState( &x_val, &y_val );
                play_btn->MouseMove(x_val, y_val);
            }
            case SDL_MOUSEBUTTONDOWN:
            {
                switch (event.button.button)
                {
                    case SDL_BUTTON_LEFT:
                    {
                        int x_val = 0;
                        int y_val = 0;
                        SDL_GetMouseState( &x_val, &y_val );
                        play_btn->MouseClick(x_val, y_val);
                        break;
                    }
                    default:
                    {
                        break;
                    }
                }
                break;
            }
            case SDL_MOUSEBUTTONUP:
            {
                switch (event.button.button)
                {
                    case SDL_BUTTON_LEFT:
                    {
                        int x_val = 0;
                        int y_val = 0;
                        SDL_GetMouseState( &x_val, &y_val );
                        play_btn->MouseUp(x_val, y_val);
                        break;
                    }
                    default:
                    {
                        break;
                    }
                }
                break;
            }
            case SDL_KEYDOWN:
            {
                play_btn->KeyDown( event.key.keysym.sym );
            }
        }
    }
}
```

与我们的`play_input`函数一样，`start_input`函数将调用`SDL_PollEvent`。除了检查`SDL_KEYDOWN`来确定是否按下了键，我们还将检查三个鼠标事件：`SDL_MOUSEMOTION`，`SDL_MOUSEBUTTONDOWN`和`SDL_MOUSEBUTTONUP`。在检查这些鼠标事件时，我们将根据我们检索到的`SDL_GetMouseState`值来调用`play_btn`函数。鼠标事件将触发以下代码：

```cpp
case SDL_MOUSEMOTION:
{
    int x_val = 0;
    int y_val = 0;
    SDL_GetMouseState( &x_val, &y_val );
    play_btn->MouseMove(x_val, y_val);
}
```

如果`event.type`是`SDL_MOUSEMOTION`，我们创建`x_val`和`y_val`整数变量，并使用`SDL_GetMouseState`来检索鼠标光标的`x`和`y`坐标。然后我们调用`play_btn->MouseMove(x_val, y_val)`。这将鼠标 x 和 y 坐标传递给播放按钮，按钮使用这些值来确定按钮是否处于悬停状态。如果`event.type`是`SDL_MOUSEBUTTONDOWN`，我们会做类似的事情：

```cpp
case SDL_MOUSEBUTTONDOWN:
{
    switch (event.button.button)
    {
        case SDL_BUTTON_LEFT:
        {
            int x_val = 0;
            int y_val = 0;

            SDL_GetMouseState( &x_val, &y_val );
            play_btn->MouseClick(x_val, y_val);
            break;
        }
        default:
        {
            break;
        }
    }
    break;
}
```

如果鼠标按钮被按下，我们会查看`event.button.button`来确定被点击的按钮是否是左鼠标按钮。如果是，我们将使用`x_val`和`y_val`与`SDL_GetMouseState`结合来找到鼠标光标的位置。我们使用这些值来调用`play_btn->MouseClick(x_val, y_val)`。`MouseClick`函数将确定按钮点击是否落在按钮内，如果是，它将调用按钮的回调函数。

当事件是`SDL_MOUSEBUTTONUP`时执行的代码与`SDL_MOUSEBUTTONDOWN`非常相似，唯一的区别是它调用`play_btn->MouseUp`而不是`play_btn->MouseClick`：

```cpp
case SDL_MOUSEBUTTONUP:
{
    switch (event.button.button)
    {
        case SDL_BUTTON_LEFT:
        {
            int x_val = 0;
            int y_val = 0;

            SDL_GetMouseState( &x_val, &y_val );
            play_btn->MouseUp(x_val, y_val);
            break;
        }
        default:
        {
            break;
        }
    }
    break;
}
```

除了鼠标事件，我们还将把键盘事件传递给我们的按钮。这样做是为了我们可以创建一个热键来触发回调函数：

```cpp
case SDL_KEYDOWN:
{
    play_btn->KeyDown( event.key.keysym.sym );
}
```

# 结束输入函数

在`start_input`函数之后，我们将定义`end_input`函数。`end_input`函数与`start_input`函数非常相似。唯一的显著区别是`play_btn`对象被`play_again_btn`对象替换，它将有一个不同的回调和与之关联的 SDL 纹理：

```cpp
void end_input() {
    if(SDL_PollEvent( &event ) )
    {
        switch(event.type)
        {
            case SDL_MOUSEMOTION:
            {
                int x_val = 0;
                int y_val = 0;
                SDL_GetMouseState( &x_val, &y_val );
                play_again_btn->MouseMove(x_val, y_val);
            }
            case SDL_MOUSEBUTTONDOWN:
            {
                switch(event.button.button)
                {
                    case SDL_BUTTON_LEFT:
                    {
                        int x_val = 0;
                        int y_val = 0;
                        SDL_GetMouseState( &x_val, &y_val );
                        play_again_btn->MouseClick(x_val, y_val);
                        break;
                    }
                    default:
                    {
                        break;
                    }
                }
                break;
            }
            case SDL_MOUSEBUTTONUP:
            {
                switch(event.button.button)
                {
                    case SDL_BUTTON_LEFT:
                    {
                        int x_val = 0;
                        int y_val = 0;
                        SDL_GetMouseState( &x_val, &y_val );
                        play_again_btn->MouseUp(x_val, y_val);
                        break;
                    }
                    default:
                    {
                        break;
                    }
                }
                break;
            }
            case SDL_KEYDOWN:
            {
                printf("SDL_KEYDOWN\n");
                play_again_btn->KeyDown( event.key.keysym.sym );
            }
        }
    }
}
```

# 渲染函数

在我们游戏的先前版本中，我们有一个单一的渲染函数。现在，我们必须为我们的开始屏幕和游戏屏幕分别设置渲染函数。现有的渲染器将成为我们新的游戏屏幕渲染器，因此我们必须将`render`函数重命名为`play_render`。我们还需要为我们的开始屏幕添加一个名为`start_render`的渲染函数。这个函数将渲染我们的新背景和`play_btn`。以下是`start_render`的代码：

```cpp
void start_render() {
    render_manager->RenderStartBackground();
    play_btn->RenderUI();
}
```

# 碰撞函数

`collisions()`函数需要进行一些小的修改。当玩家飞船或敌人飞船被摧毁时，我们需要将当前屏幕更改为游戏结束屏幕。根据哪艘飞船被摧毁，我们将需要将其更改为胜利屏幕或失败屏幕。以下是我们碰撞函数的新版本：

```cpp
void collisions() {
 Asteroid* asteroid;
 std::vector<Asteroid*>::iterator ita;
    if( player->m_CurrentFrame == 0 && player->CompoundHitTest( star ) ) {
        player->m_CurrentFrame = 1;
        player->m_NextFrameTime = ms_per_frame;
        player->m_Explode->Run();
        current_screen = GAME_OVER_SCREEN;
        large_explosion_snd->Play();
    }
    if( enemy->m_CurrentFrame == 0 && enemy->CompoundHitTest( star ) ) {
        enemy->m_CurrentFrame = 1;
        enemy->m_NextFrameTime = ms_per_frame;
        current_screen = YOU_WIN_SCREEN;
        enemy->m_Explode->Run();
        large_explosion_snd->Play();
    }
    Projectile* projectile;
    std::vector<Projectile*>::iterator it;
    for(it=projectile_pool->m_ProjectileList.begin(); 
    it!=projectile_pool->m_ProjectileList.end();it++){
        projectile = *it;
        if( projectile->m_CurrentFrame == 0 && projectile->m_Active ) {
            for( ita = asteroid_list.begin(); ita!=asteroid_list.end(); 
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
                ( projectile->HitTest( player ) || player->CompoundHitTest( 
                 projectile ) ) ) {
                if( player->m_Shield->m_Active == false ) {
                    player->m_CurrentFrame = 1;
                    player->m_NextFrameTime = ms_per_frame;
                    current_screen = GAME_OVER_SCREEN;
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
                ( projectile->HitTest( enemy ) || enemy->CompoundHitTest( 
                 projectile ) ) ) {
                if( enemy->m_Shield->m_Active == false ) {
                    enemy->m_CurrentFrame = 1;
                    enemy->m_NextFrameTime = ms_per_frame;
                    current_screen = YOU_WIN_SCREEN;
                    enemy->m_Explode->Run();
                    large_explosion_snd->Play();
                    enemy->m_Shield->m_ttl -= 1000;
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
                current_screen = GAME_OVER_SCREEN;
                large_explosion_snd->Play();
            }
            else {
                player->ElasticCollision( asteroid );
                small_explosion_snd->Play();
            }
        }
        if( enemy->m_CurrentFrame == 0 && asteroid->m_Active &&
          ( asteroid->HitTest( enemy ) || enemy->CompoundHitTest( asteroid 
           ) ) ) {
            if( enemy->m_Shield->m_Active == false ) {
                enemy->m_CurrentFrame = 1;
                enemy->m_NextFrameTime = ms_per_frame;

                enemy->m_Explode->Run();
                current_screen = YOU_WIN_SCREEN;
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
            if(asteroid_1->HitTest(asteroid_2)) { 
            asteroid_1->ElasticCollision( asteroid_2 ); }
        }
    }
}
```

您会注意到每次玩家被销毁时，都会调用`player->m_Explode->Run()`。现在我们会在这行代码后面调用`current_screen = GAME_OVER_SCREEN`，将屏幕设置为玩家失败画面。我们还可以通过向`Ship`类添加一个函数来完成此操作，该函数既运行爆炸动画又设置游戏画面，但我选择通过在`main`函数内部进行更改来修改更少的文件。如果我们将此项目用于除演示目的之外的其他用途，我可能会选择另一种方式。

我们对碰撞所做的其他更改类似。每当敌人被`enemy->m_Explode->Run()`函数销毁时，我们会跟着一行代码将当前画面设置为“你赢了”画面，就像这样：

```cpp
current_screen = YOU_WIN_SCREEN;
```

# 过渡状态

从开始画面突然过渡到游戏画面可能有点令人不适。为了使过渡更加平滑，我们将创建一个名为`draw_play_transition`的过渡函数，它将使用 alpha 淡入淡出来将我们的画面从开始画面过渡到游戏画面。该函数如下所示：

```cpp
void draw_play_transition() {
    transition_time -= diff_time;
    if( transition_time <= 0 ) {
        current_screen = PLAY_SCREEN;
        return;
    }
    render_manager->RenderStartBackground(transition_time/4);
}
```

此函数使用我们之前创建的`transition_time`全局变量，并减去自上一帧以来的毫秒数。它使用该值除以 4 作为 alpha 值，用于绘制开始画面背景，使其在过渡到游戏画面时淡出。当过渡时间降至 0 以下时，我们将当前画面设置为播放画面。过渡开始时，我们将`transition_time`设置为 1,020 毫秒，稍多于一秒。将该值除以 4 会得到一个从 255（完全不透明）到 0（完全透明）的值。

# 游戏循环

`game_loop`函数将需要修改以执行每个画面的不同逻辑。以下是游戏循环的新版本：

```cpp
void game_loop() {
    current_time = SDL_GetTicks();
    diff_time = current_time - last_time;
    delta_time = diff_time / 1000.0;
    last_time = current_time;
    if( current_screen == START_SCREEN ) {
        start_input();
        start_render();
    }
    else if( current_screen == PLAY_SCREEN || current_screen == 
             PLAY_TRANSITION ) {
        play_input();
        move();
        collisions();
        play_render();
        if( current_screen == PLAY_TRANSITION ) {
            draw_play_transition();
        }
    }
    else if( current_screen == YOU_WIN_SCREEN || current_screen == 
             GAME_OVER_SCREEN ) {
        end_input();
        move();
        collisions();
        play_render();
        play_again_btn->RenderUI();
        if( current_screen == YOU_WIN_SCREEN ) {
            you_win_sprite->RenderUI();
        }
        else {
            game_over_sprite->RenderUI();
        }
    }
}
```

我们有新的分支逻辑，根据当前画面进行分支。第一个`if`块在当前画面是开始画面时运行`start_input`和`start_render`函数：

```cpp
if( current_screen == START_SCREEN ) {
    start_input();
    start_render();
}
```

游戏画面和游戏过渡与原始游戏循环逻辑相同，除了代码块末尾的`PLAY_TRANSITION`周围的`if`块。这通过调用我们之前定义的`draw_play_transition()`函数来绘制游戏过渡：

```cpp
else if( current_screen == PLAY_SCREEN || current_screen == PLAY_TRANSITION ) {
    play_input();
    move();
    collisions();
    play_render();
    if( current_screen == PLAY_TRANSITION ) {
        draw_play_transition();
    }
}
```

函数中的最后一块代码是游戏结束画面。如果当前画面是`YOU_WIN_SCREEN`，它将渲染`you_win_sprite`，如果当前画面是`GAME_OVER_SCREEN`，它将渲染`game_over_sprite`：

```cpp
else if( current_screen == YOU_WIN_SCREEN || current_screen == 
         GAME_OVER_SCREEN ) {
    end_input();
    move();
    collisions();
    play_render();
    play_again_btn->RenderUI();
    if( current_screen == YOU_WIN_SCREEN ) {
        you_win_sprite->RenderUI();
    }
    else {
        game_over_sprite->RenderUI();
    }
}
```

# 播放和再玩一次回调

在对游戏循环进行更改后，我们需要为我们的按钮添加一些回调函数。其中之一是`play_click`函数。这是当玩家在开始画面上点击播放按钮时运行的回调。此函数将当前画面设置为播放过渡，并将过渡时间设置为 1,020 毫秒：

```cpp
void play_click() {
    current_screen = PLAY_TRANSITION;
    transition_time = 1020;
}
```

之后，我们将定义`play_again_click`回调。当玩家在游戏结束画面上点击再玩一次按钮时，此函数将运行。因为这是一个网络游戏，我们将使用一个小技巧来简化这个逻辑。在几乎任何其他平台上编写的游戏中，您需要创建一些重新初始化逻辑，需要回到游戏中并重置所有内容的状态。我们将通过使用 JavaScript 简单地重新加载网页来*作弊*：

```cpp
void play_again_click() {
    EM_ASM(
        location.reload();
    );
}
```

这种作弊方法并不适用于所有游戏。重新加载某些游戏会导致无法接受的延迟。对于某些游戏，可能有太多的状态信息需要保留。但是，对于这个游戏，重新加载页面是一个快速简单的方法来完成任务。

# 主函数的更改

我们在应用程序中使用`main`函数来执行所有游戏初始化。这是我们需要添加一些代码来初始化游戏结束画面和新按钮所使用的精灵的地方。

在以下代码片段中，我们有我们的新精灵初始化行：

```cpp
game_over_sprite = new UISprite( 400, 300, (char*)"/sprites/GameOver.png" );
game_over_sprite->m_Active = true;
you_win_sprite = new UISprite( 400, 300, (char*)"/sprites/YouWin.png" );
you_win_sprite->m_Active = true;
```

您可以看到，我们将`game_over_sprite`坐标和`you_win_sprite`坐标设置为`400, 300`。这将使这些精灵位于屏幕中央。我们设置两个精灵都处于活动状态，因为它们只会在游戏结束屏幕上呈现。在代码的后面，我们将调用我们的`UIButton`对象的构造函数：

```cpp
play_btn = new UIButton(400, 500,
                     (char*)"/sprites/play_button.png",
                     (char*)"/sprites/play_button_hover.png",
                     (char*)"/sprites/play_button_click.png",
                     play_click );

play_again_btn = new UIButton(400, 500,
                     (char*)"/sprites/play_again_button.png",
                     (char*)"/sprites/play_again_button_hover.png",
                     (char*)"/sprites/play_again_button_click.png",
                     play_again_click );
```

这将两个按钮都放置在`400, 500`，在 x 轴上居中，但靠近游戏屏幕底部的 y 轴。回调设置为`play_click`和`play_again_click`，我们之前定义过。以下是整个`main`函数的样子：

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
    game_over_sprite = new UISprite( 400, 300, 
    (char*)"/sprites/GameOver.png" );
    game_over_sprite->m_Active = true;
    you_win_sprite = new UISprite( 400, 300, 
    (char*)"/sprites/YouWin.png" );
    you_win_sprite->m_Active = true;
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
    SDL_PauseAudioDevice(device_id, 0);
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
    play_btn = new UIButton(400, 500,
                     (char*)"/sprites/play_button.png",
                     (char*)"/sprites/play_button_hover.png",
                     (char*)"/sprites/play_button_click.png",
                     play_click );
    play_again_btn = new UIButton(400, 500,
                     (char*)"/sprites/play_again_button.png",
                     (char*)"/sprites/play_again_button_hover.png",
                     (char*)"/sprites/play_again_button_click.png",
                     play_again_click );
    emscripten_set_main_loop(game_loop, 0, 0);
    return 1;
}
```

在下一节中，我们将在我们的`ui_button.cpp`文件中定义函数。

# ui_button.cpp

`UIButton`对象有几个必须定义的函数。我们创建了一个新的`ui_button.cpp`文件，将保存所有这些新函数。我们需要定义一个构造函数，以及`MouseMove`、`MouseClick`、`MouseUp`、`KeyDown`和`RenderUI`。

首先，我们将包括我们的`game.hpp`文件：

```cpp
#include "game.hpp"
```

现在，我们将定义我们的构造函数：

```cpp
UIButton::UIButton( int x, int y, char* file_name, char* hover_file_name, char* click_file_name, void (*callback)() ) {
    m_Callback = callback;
    m_dest.x = x;
    m_dest.y = y;
    SDL_Surface *temp_surface = IMG_Load( file_name );

    if( !temp_surface ) {
        printf("failed to load image: %s\n", IMG_GetError() );
        return;
    }
    else {
        printf("success creating ui button surface\n");
    }
    m_SpriteTexture = SDL_CreateTextureFromSurface( renderer, 
    temp_surface );
    if( !m_SpriteTexture ) {
        return;
    }
    SDL_QueryTexture( m_SpriteTexture,
                        NULL, NULL,
                        &m_dest.w, &m_dest.h );
    SDL_FreeSurface( temp_surface );

     temp_surface = IMG_Load( click_file_name );
    if( !temp_surface ) {
        printf("failed to load image: %s\n", IMG_GetError() );
        return;
    }
    else {
        printf("success creating ui button click surface\n");
    }
    m_ClickTexture = SDL_CreateTextureFromSurface( renderer, 
    temp_surface );

    if( !m_ClickTexture ) {
        return;
    }
    SDL_FreeSurface( temp_surface );

    temp_surface = IMG_Load( hover_file_name );
    if( !temp_surface ) {
        printf("failed to load image: %s\n", IMG_GetError() );
        return;
    }
    else {
        printf("success creating ui button hover surface\n");
    }
    m_HoverTexture = SDL_CreateTextureFromSurface( renderer, 
    temp_surface );

    if( !m_HoverTexture ) {
        return;
    }
    SDL_FreeSurface( temp_surface );

    m_dest.x -= m_dest.w / 2;
    m_dest.y -= m_dest.h / 2;

    m_Hover = false;
    m_Click = false;
    m_Active = true;
}
```

构造函数从传入的参数设置回调函数开始：

```cpp
m_Callback = callback;
```

然后，它从我们传递的参数设置了`m_dest`矩形的`x`和`y`坐标：

```cpp
m_dest.x = x;
m_dest.y = y;
```

之后，它将三个不同的图像文件加载到三个不同的纹理中，用于按钮、按钮的悬停状态和按钮的点击状态：

```cpp
SDL_Surface *temp_surface = IMG_Load( file_name );

if( !temp_surface ) {
    printf("failed to load image: %s\n", IMG_GetError() );
    return;
}
else {
    printf("success creating ui button surface\n");
}
m_SpriteTexture = SDL_CreateTextureFromSurface( renderer, temp_surface );

if( !m_SpriteTexture ) {
    return;
}
SDL_QueryTexture( m_SpriteTexture,
                  NULL, NULL,
                  &m_dest.w, &m_dest.h );
SDL_FreeSurface( temp_surface );

temp_surface = IMG_Load( click_file_name );

if( !temp_surface ) {
    printf("failed to load image: %s\n", IMG_GetError() );
    return;
}
else {
    printf("success creating ui button click surface\n");
}
m_ClickTexture = SDL_CreateTextureFromSurface( renderer, temp_surface );

if( !m_ClickTexture ) {
    return;
}
SDL_FreeSurface( temp_surface );

temp_surface = IMG_Load( hover_file_name );
if( !temp_surface ) {
    printf("failed to load image: %s\n", IMG_GetError() );
    return;
}
else {
    printf("success creating ui button hover surface\n");
}
m_HoverTexture = SDL_CreateTextureFromSurface( renderer, temp_surface );

if( !m_HoverTexture ) {
    return;
}
SDL_FreeSurface( temp_surface );
```

前面的代码应该看起来很熟悉，因为在这一点上，将图像文件加载到`SDL_Texture`对象中是我们经常做的事情。之后，我们使用之前查询的宽度和高度值来居中目标矩形：

```cpp
m_dest.x -= m_dest.w / 2;
m_dest.y -= m_dest.h / 2;
```

然后，我们设置悬停、点击和活动状态标志：

```cpp
m_Hover = false;
m_Click = false;
m_Active = true;
```

# MouseMove 功能

我们需要一个函数来确定鼠标光标是否移动到我们的按钮上。我们从我们的输入函数中调用`MouseMove`函数，并传入当前鼠标光标的`x`和`y`坐标。我们检查这些坐标是否与我们的`m_dest`矩形重叠。如果是，我们将悬停标志设置为`true`。如果不是，我们将悬停标志设置为`false`：

```cpp
void UIButton::MouseMove(int x, int y) {
    if( x >= m_dest.x && x <= m_dest.x + m_dest.w &&
        y >= m_dest.y && y <= m_dest.y + m_dest.h ) {
        m_Hover = true;
    }
    else {
        m_Hover = false;
    }
}
```

# MouseClick 功能

`MouseClick`函数与`MouseMove`函数非常相似。当用户按下鼠标左键时，也会从我们的输入函数中调用。鼠标光标的`x`和`y`坐标被传入，函数使用`m_dest`矩形来查看鼠标光标在点击时是否在按钮上。如果是，我们将单击标志设置为`true`。如果不是，我们将单击标志设置为`false`：

```cpp
void UIButton::MouseClick(int x, int y) {
    if( x >= m_dest.x && x <= m_dest.x + m_dest.w &&
        y >= m_dest.y && y <= m_dest.y + m_dest.h ) {
        m_Click = true;
    }
    else {
        m_Click = false;
    }
}
```

# 鼠标弹起功能

当释放鼠标左键时，我们调用此功能。无论鼠标光标坐标如何，我们都希望将单击标志设置为`false`。如果鼠标在释放按钮时位于按钮上，并且按钮被点击，我们需要调用回调函数：

```cpp
void UIButton::MouseUp(int x, int y) {
    if( m_Click == true &&
        x >= m_dest.x && x <= m_dest.x + m_dest.w &&
        y >= m_dest.y && y <= m_dest.y + m_dest.h ) {
        if( m_Callback != NULL ) {
            m_Callback();
        }
    }
    m_Click = false;
}
```

# KeyDown 功能

我本可以使按键按下功能更加灵活。最好将热键设置为对象中设置的值。这将支持屏幕上不止一个按钮。目前，如果有人按下*Enter*键，屏幕上的所有按钮都将被点击。这对我们的游戏不是问题，因为我们不会在屏幕上放置多个按钮，但是如果您想改进热键功能，这应该不难。因为该函数将其检查的键硬编码为`SDLK_RETURN`。以下是我们的函数版本：

```cpp
void UIButton::KeyDown( SDL_Keycode key ) {
    if( key == SDLK_RETURN) {
        if( m_Callback != NULL ) {
            m_Callback();
        }
    }
}
```

# RenderUI 功能

`RenderUI`函数检查按钮中的各种状态标志，并根据这些值呈现正确的精灵。如果`m_Active`标志为`false`，函数将不呈现任何内容。以下是函数：

```cpp
void UIButton::RenderUI() {
    if( m_Active == false ) {
        return;
    }
    if( m_Click == true ) {
        render_manager->RenderUI( m_ClickTexture, NULL, &m_dest, 0.0,
                                    0xff, 0xff, 0xff, 0xff );
    }
    else if( m_Hover == true ) {
        render_manager->RenderUI( m_HoverTexture, NULL, &m_dest, 0.0,
                                    0xff, 0xff, 0xff, 0xff );
    }
    else {
        render_manager->RenderUI( m_SpriteTexture, NULL, &m_dest, 0.0,
                                    0xff, 0xff, 0xff, 0xff );
    }
}
```

在下一节中，我们将在我们的`ui_sprite.cpp`文件中定义函数。

# ui_sprite.cpp

`UISprite`类非常简单。它只有两个函数：一个构造函数和一个渲染函数。与项目中的每个其他 CPP 文件一样，我们必须首先包含`game.hpp`文件：

```cpp
#include "game.hpp"
```

# 定义构造函数

构造函数非常熟悉。它将`m_dest`矩形的`x`和`y`值设置为传入构造函数的值。它使用我们传入的`file_name`变量从虚拟文件系统加载纹理。最后，它使用`SDL_QueryTexture`函数检索的宽度和高度值来居中`m_dest`矩形。以下是构造函数的代码：

```cpp
UISprite::UISprite( int x, int y, char* file_name ) {
    m_dest.x = x;
    m_dest.y = y;
    SDL_Surface *temp_surface = IMG_Load( file_name );

    if( !temp_surface ) {
        printf("failed to load image: %s\n", IMG_GetError() );
        return;
    }
    else {
        printf("success creating ui button surface\n");
    }

    m_SpriteTexture = SDL_CreateTextureFromSurface( renderer, 
    temp_surface );

    if( !m_SpriteTexture ) {
        return;
    }
    SDL_QueryTexture( m_SpriteTexture,
                      NULL, NULL,
                      &m_dest.w, &m_dest.h );
    SDL_FreeSurface( temp_surface );
    m_dest.x -= m_dest.w / 2;
    m_dest.y -= m_dest.h / 2;
}
```

# RenderUI 函数

我们精灵的`RenderUI`函数也很简单。它检查精灵是否处于活动状态，如果是，则调用渲染管理器的`RenderUI`函数。以下是代码：

```cpp
void UISprite::RenderUI() {
    if( m_Active == false ) {
        return;
    }
    render_manager->RenderUI( m_SpriteTexture, NULL, &m_dest, 0.0,
                              0xff, 0xff, 0xff, 0xff );
}
```

# 编译 ui.html

现在我们已经为我们的游戏添加了用户界面，让我们编译它，从我们的 Web 服务器或 emrun 中提供它，并在 Web 浏览器中打开它。以下是我们需要编译`ui.html`文件的`em++`命令：

```cpp
em++ asteroid.cpp audio.cpp camera.cpp collider.cpp emitter.cpp enemy_ship.cpp finite_state_machine.cpp locator.cpp main.cpp particle.cpp player_ship.cpp projectile_pool.cpp projectile.cpp range.cpp render_manager.cpp shield.cpp ship.cpp star.cpp ui_button.cpp ui_sprite.cpp vector.cpp -o ui.html --preload-file audio --preload-file sprites -std=c++17 -s USE_WEBGL2=1 -s USE_SDL=2 -s USE_SDL_IMAGE=2 -s SDL2_IMAGE_FORMATS=["png"] -s USE_SDL_IMAGE=2 -s SDL2_IMAGE_FORMATS=["png"] 
```

新版本将打开到我们的开始屏幕。如果您想玩游戏，现在需要点击*播放*按钮。这是一个截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/af0aed53-ba7c-4980-82e7-52d72d32ed5a.png)

图 14.6：开场画面

您会注意到*开场画面*上有关于如何玩游戏的说明。在面向动作的网络游戏中通常很好有一个开场画面，因为玩家加载页面时并不总是准备好玩。并非所有网络游戏都需要开场画面。我的网站[classicsolitaire.com](https://www.classicsolitaire.com/)没有一个。这是因为纸牌是一种回合制游戏，玩家并不会立即投入行动。您的游戏的用户界面需求可能与我们为本书编写的游戏不同。因此，请绘制一个故事板，并花时间收集需求。您会为此感到高兴的。

# 摘要

在本章中，我们花了一些时间收集用户界面的要求。我们创建了一个故事板，帮助我们思考我们的游戏需要哪些屏幕以及它们可能的外观。我们讨论了开场画面的布局，以及为什么我们需要它。然后，我们将原本是整个游戏的屏幕分解为播放屏幕。然后，我们讨论了游戏结束屏幕的布局以及我们需要的 UI 元素，并学习了如何使用 SDL 检索鼠标输入。我们还创建了一个按钮类作为我们用户界面的一部分，以及一个用于我们屏幕状态的枚举，并讨论了这些状态之间的转换。然后，我们添加了一个精灵用户界面对象，然后修改了我们的渲染管理器，以便我们可以渲染开始屏幕的背景图像。最后，我们对代码进行了更改，以支持多个游戏屏幕。

在下一章中，我们将学习如何编写新的着色器并使用 WebAssembly 的 OpenGL API 实现它们。


# 第十五章：着色器和 2D 光照

我们已经在第三章中介绍了着色器，*WebGL 简介*。不幸的是，SDL 不允许用户在不深入库的源代码并在那里修改的情况下自定义其着色器。这种修改超出了本书的范围。

本书的范围。在使用 SDL 与 OpenGL 的组合是很常见的。SDL 可用于渲染游戏的用户界面，而 OpenGL 则渲染游戏对象。本章将与之前的许多章节有所不同，因为我们将不会直接在我们一直在编写的游戏中混合 SDL 和 OpenGL。更新游戏以支持 OpenGL 2D 渲染引擎将需要对游戏进行完全的重新设计。然而，我想为那些有兴趣创建更高级的 2D 渲染引擎的人提供一个章节，让他们尝试结合 OpenGL 和 SDL，并为该引擎编写着色器。

您需要在构建中包含几个图像才能使这个项目工作。确保您包含了这个项目的 GitHub 存储库中的`/Chapter15/sprites/`文件夹。如果您还没有下载 GitHub 项目，可以在这里在线获取：[`github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly`](https://github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly)。

在本章中，我们将做以下事情：

+   使用 SDL 和 OpenGL 为 WebAssembly 重新创建我们在[第三章](https://cdp.packtpub.com/hands_on_game_development_with_webassembly/wp-admin/post.php?post=38&action=edit#post_26)中制作的应用程序，*WebGL 简介*。

+   学习如何创建一个新的着色器，加载并渲染多个纹理到一个四边形

+   了解法向图以及它们如何用于在 2D 游戏对象上创建深度的错觉

+   学习如何在 OpenGL 和 WebAssembly 中使用法向图来近似 2D 中的冯氏光照模型

# 使用 OpenGL 和 WebAssembly

Emscripten 能够编译使用 OpenGL ES 2.0 或 OpenGL ES 3.0 的 C/C++代码，通过将这些调用映射到 WebGL 或 WebGL 2 调用来实现。因此，Emscripten 只支持与您使用的 WebGL 库内可用的 OpenGL ES 命令的子集。例如，如果您想使用 OpenGL ES 3.0，您需要在编译时通过向 Emscripten 编译器传递`-s USE_WEBGL2=1`参数来包含 WebGL 2。在本章中，我们将使用 OpenGL ES 2.0 与 SDL 结合使用着色器来渲染精灵，稍后我们将使用 SDL 来渲染代表应用程序中光源位置的图标。SDL 提供了许多 OpenGL 所没有的功能，如音频库、图像加载库以及鼠标和键盘输入库。在许多方面，SDL 更适合于渲染游戏的用户界面，因为它将对象渲染到屏幕坐标而不是 OpenGL 剪辑空间。在幕后，WebAssembly 版本的 SDL 也使用了 Emscripten 的 OpenGL ES 实现，依赖于 WebGL。因此，更好地了解 WebAssembly 的 OpenGL 实现可以帮助我们将游戏开发技能提升到更高的水平，即使我们在本书中开发的游戏中不会使用这些技能。

# 更多关于着色器的知识

我们在《HTML5 和 WebAssembly》的第二章中简要介绍了着色器的概念。着色器是现代 3D 图形渲染的关键部分。在计算机和视频游戏的早期，图形都是 2D 的，图形渲染的速度取决于系统能够将像素从一个数据缓冲区移动到另一个数据缓冲区的速度。这个过程称为*blitting*。在早期，一个重要的进步是任天堂在他们的任天堂娱乐系统中添加了一个**图片处理单元**（**PPU**）。这是一个早期的硬件，旨在通过在不使用游戏系统 CPU 的情况下移动像素来加速图形处理。康柏 Amiga 也是这些早期 2D 图形协处理器的先驱，到了 20 世纪 90 年代中期，blitting 的硬件成为了计算机行业的标准。1996 年，像《奇兵》这样的游戏开始对消费者 3D 图形处理提出需求，早期的图形卡开始提供具有固定功能管线的 GPU。这允许应用程序加载几何数据并在该几何体上执行不可编程的纹理和光照功能。在 21 世纪初，Nvidia 推出了 GeForce 3。这是第一个支持可编程管线的 GPU。最终，这些可编程管线的 GPU 开始围绕*统一着色器模型*进行标准化，这允许程序员为支持该语言的所有图形卡编写 GLSL 等着色器语言。

# GLSL ES 1.0 和 3.0

我们将使用的语言来编写我们的着色器是 GLSL 着色器语言的一个子集，称为 GLSL ES。这个着色器语言恰好适用于 WebGL，因此受到了被移植到 WebAssembly 的 OpenGL ES 版本的支持。我们编写的代码将在 GLSL ES 1.0 和 3.0 上运行，这是 WebAssembly 支持的 GLSL ES 的两个版本。

如果你想知道为什么不支持 GLSL ES 2.0，那是因为它根本不存在。OpenGL ES 1.0 使用了固定功能管线，因此没有与之相关的着色器语言。当 Khronos Group 创建了 OpenGL ES 2.0 时，他们创建了 GLSL ES 1.0 作为与之配套的着色器语言。当他们发布了 OpenGL ES 3.0 时，他们决定希望着色器语言的版本号与 API 的版本号相同。因此，所有新版本的 OpenGL ES 都将配备与之版本号相同的 GLSL 版本。

GLSL 是一种非常类似于 C 的语言。每个着色器都有一个`main`函数作为其入口点。GLSL ES 2.0 只支持两种着色器类型：*顶点着色器*和*片段着色器*。这些着色器的执行是高度并行的。如果你习惯于单线程思维，你需要调整你的思维方式。着色器通常同时处理成千上万个顶点和像素。

我在《WebGL 入门》的第三章中简要讨论了顶点和片段的定义。顶点是空间中的一个点，一组顶点定义了我们的图形卡用来渲染屏幕的几何形状。片段是像素候选。通常需要多个片段来确定像素输出。

传递给顶点着色器的几何图形的每个顶点都由该着色器处理。然后使用*varying 变量*传递值给大量处理单个像素的线程，通过片段着色器。片段着色器接收一个值，该值在多个顶点着色器的输出之间进行插值。片段着色器的输出是一个*片段*，它是一个像素候选。并非所有片段都成为像素。有些片段被丢弃，这意味着它们根本不会渲染。其他片段被混合以形成完全不同的像素颜色。在第三章中，*WebGL 简介*中，我们为我们的 WebGL 应用程序创建了一个顶点着色器和一个片段着色器。让我们开始将该应用程序转换为一个 OpenGL/WebAssembly 应用程序。一旦我们有一个工作的应用程序，我们可以进一步讨论着色器和我们可以编写这些着色器的新方法，以改进我们的 2D WebAssembly 游戏。

# WebGL 应用程序重现

现在我们将逐步介绍如何重写我们在第三章中制作的 WebGL 应用程序，使用 SDL 和 OpenGL。如果你不记得了，这是一个非常简单的应用程序，每帧都在我们的画布上绘制一艘飞船，并将其向左移动 2 个像素，向上移动一个像素。我们制作这个应用程序的原因是，这是我能想到的在 WebGL 中做的比绘制一个三角形更有趣的最简单的事情。出于同样的原因，这将是我们将使用 OpenGL 进行 WebAssembly 的第一件事情。现在，创建一个名为`webgl-redux.c`的新文件并打开它。现在，让我们开始添加一些代码。我们需要的第一部分代码是我们的`#include`命令，以引入我们这个应用程序所需的所有库：

```cpp
#include <SDL2/SDL.h>
#include <SDL2/SDL_image.h>
#include <SDL_opengl.h>
#include <GLES2/gl2.h>
#include <stdlib.h>
#include <emscripten.h>
```

第一行包括标准的 SDL2 库。第二个库`SDL_image.h`是我们用来加载图像文件的库。这个文件的第三行包括`SDL_opengl.h`，这是一个允许我们混合 SDL 和 OpenGL 调用的库。包括`GLES2/gl2.h`让我们可以使用 OpenGL ES 2.0 的所有 OpenGL 命令。和往常一样，我们包括`stdlib.h`让我们可以使用`printf`命令，`emscripten.h`为我们提供了使用 Emscripten 编译器编译为 WebAssembly 目标所需的函数。

在我们的`#include`命令之后，我们有一系列`#define`宏，用于定义我们游戏所需的常量：

```cpp
#define CANVAS_WIDTH 800
#define CANVAS_HEIGHT 600
#define FLOAT32_BYTE_SIZE 4
#define STRIDE FLOAT32_BYTE_SIZE*4
```

前两个定义了我们画布的宽度和高度。其余的`#define`调用用于设置我们在定义顶点缓冲区时将要使用的值。在这些`#define`宏之后，我们定义了我们着色器的代码。

# 着色器代码

接下来我将要展示的几个代码块将定义我们需要创建 2D 光照效果的着色器。以下是顶点着色器代码：

```cpp
const GLchar* vertex_shader_code[] = {
    "precision mediump float; \n"
    "attribute vec4 a_position; \n"
    "attribute vec2 a_texcoord; \n"

    "uniform vec4 u_translate; \n"

    "varying vec2 v_texcoord; \n"

    "void main() { \n"
        "gl_Position = u_translate + a_position; \n"
        "v_texcoord = a_texcoord; \n"
    "} \n"
};
```

这是我们创建 WebGL 版本应用时使用的相同着色器代码。它在 C 中看起来有点不同，因为 JavaScript 可以使用多行字符串，使得代码更加清晰易读。与 WebGL 版本一样，我们使用精度调用将浮点精度设置为中等。我们设置属性来接收位置和 UV 纹理坐标数据作为向量。我们将使用顶点缓冲对象传递这些向量。我们定义一个 uniform 变量`translate`，它将是所有顶点使用的相同值，这通常不是我们在游戏中做的方式，但对于这个应用来说完全可以。最后，我们定义一个 varying `v_texcoord`变量。这个变量将代表我们从顶点着色器传递到片段着色器的纹理坐标值。这个顶点着色器中的`main()`函数非常简单。它将`u_translate` uniform 变量传递到顶点着色器中，将通过`a_position`传递的顶点属性位置添加到最终顶点位置，然后使用`gl_Position`变量设置。之后，通过将`v_texcoord` varying 变量设置为`a_texcoord`，我们将顶点的纹理坐标传递到片段着色器中。

在定义了我们的顶点着色器之后，我们创建了定义我们片段着色器的字符串。片段着色器接收到了`v_texcoord`的插值版本，这是从我们的顶点着色器传递出来的 varying 变量。你需要暂时戴上并行处理的帽子来理解这是如何工作的。当 GPU 处理我们的顶点着色器和片段着色器时，它不是一次处理一个，而是可能一次处理成千上万个顶点和片段。片段着色器也不是接收来自单个线程的输出，而是来自当前正在处理的多个顶点的混合值。

例如，如果你的顶点着色器有一个名为 X 的 varying 变量作为输出，并且你的片段着色器处于 X 为 0 和 X 为 10 的两个顶点之间的中间位置，那么进入片段的 varying 变量中的值将是 5。这是因为 5 是 0 和 10 两个顶点值之间的中间值。同样，如果片段在两个点之间的 30%位置，X 中的值将是 3。

以下是我们片段着色器代码的定义：

```cpp
const GLchar* fragment_shader_code[] = {
    "precision mediump float; \n"
    "varying vec2 v_texcoord; \n"

    "uniform sampler2D u_texture; \n"

    "void main() { \n"
        "gl_FragColor = texture2D(u_texture, v_texcoord); \n"
    "} \n"
 };
```

与我们的顶点着色器一样，我们首先设置精度。之后，我们有一个 varying 变量，这是我们纹理坐标的插值值。这个值存储在`v_texcoord`中，并将用于将纹理映射到像素颜色上。最后一个变量是一个`sampler2D`类型的 uniform 变量。这是一个内存块，我们在其中加载了我们的纹理。这个片段着色器的主要功能是使用内置的`texture2D`函数，使用我们传递到片段着色器中的纹理坐标来获取纹理中的像素颜色。

# OpenGL 全局变量

在定义了我们的着色器之后，我们需要在 C 中定义几个变量，用于与它们进行交互：

```cpp
GLuint program = 0;
GLuint texture;

GLint a_texcoord_location = -1;
GLint a_position_location = -1;

GLint u_texture_location = -1;
GLint u_translate_location = -1;

GLuint vertex_texture_buffer;
```

OpenGL 使用引用变量与 GPU 进行交互。这些变量中的前两个是`GLuint`类型。`GLuint`是无符号整数，使用`GLuint`类型只是 OpenGL 类型的一种。看到`GLuint`而不是`unsigned int`是给阅读你的代码的人一个提示，表明你正在使用这个变量与 OpenGL 进行交互。程序变量最终将保存一个由你的着色器定义的程序的引用，而纹理变量将保存一个已加载到 GPU 中的纹理的引用。在对程序和纹理的引用之后，我们有两个变量，用于引用着色器程序属性。`a_texcoord_location`变量将是对`a_texcoord`着色器属性的引用，而`a_position_location`变量将是对`a_position`着色器属性值的引用。属性引用后面是两个统一变量引用。如果你想知道统一变量和属性变量之间的区别，统一变量对于所有顶点保持相同的值，而属性变量是特定于顶点的。最后，我们在`vertex_texture_buffer`变量中有一个对顶点纹理缓冲区的引用。

在定义这些值之后，我们需要定义我们的四边形。你可能还记得，我们的四边形由六个顶点组成。这是因为它由两个三角形组成。我在第三章中讨论了为什么我们以这种方式设置顶点数据，*WebGL 入门*。如果你觉得这很困惑，你可能需要回到那一章进行一些复习。以下是`vertex_texture_data`数组的定义：

```cpp
float vertex_texture_data[] = {
    // x,   y,        u,   v
    0.167,  0.213,    1.0, 1.0,
   -0.167,  0.213,    0.0, 1.0,
    0.167, -0.213,    1.0, 0.0,
   -0.167, -0.213,    0.0, 0.0,
   -0.167,  0.213,    0.0, 1.0,
    0.167, -0.213,    1.0, 0.0
};
```

# SDL 全局变量

我们仍然将使用 SDL 来初始化我们的 OpenGL 渲染画布。我们还将使用 SDL 从虚拟文件系统加载图像数据。因此，我们需要定义以下与 SDL 相关的全局变量：

```cpp
SDL_Window *window;
SDL_Renderer *renderer;
SDL_Texture* sprite_texture;
SDL_Surface* sprite_surface;
```

之后，当我们使用 SDL 加载图像时，我们需要变量来保存我们的精灵宽度和高度值：

```cpp
int sprite_width;
int sprite_height;
```

当我们将飞船绘制到画布上时，我们将需要该飞船的`x`和`y`坐标，因此我们将创建一些全局变量来保存这些值：

```cpp
float ship_x = 0.0;
float ship_y = 0.0;
```

最后，我们将创建一个游戏循环的函数原型。我想在定义主函数之后定义我们的游戏循环，因为我想先逐步进行初始化。以下是我们游戏循环的函数原型：

```cpp
void game_loop();
```

# 主函数

现在，我们来到了我们的`main`函数。我们需要做一些初始化工作。我们不仅需要像创建游戏时那样初始化 SDL，还需要对 OpenGL 进行几个初始化步骤。以下是完整的`main`函数：

```cpp
int main() {
 SDL_Init( SDL_INIT_VIDEO );
 SDL_CreateWindowAndRenderer( CANVAS_WIDTH, CANVAS_HEIGHT, 0, &window, &renderer );
    SDL_SetRenderDrawColor( renderer, 0, 0, 0, 255 );
    SDL_RenderClear( renderer );
    GLuint vertex_shader = glCreateShader(GL_VERTEX_SHADER);
    glShaderSource( vertex_shader,1,vertex_shader_code,0);
    glCompileShader(vertex_shader);
    GLint compile_success = 0;
    glGetShaderiv(vertex_shader, GL_COMPILE_STATUS, &compile_success);
    if(compile_success == GL_FALSE)
    {
        printf("failed to compile vertex shader\n");
        glDeleteShader(vertex_shader);
        return 0;
    }
    GLuint fragment_shader = glCreateShader(GL_FRAGMENT_SHADER);
    glShaderSource( fragment_shader,1,fragment_shader_code,0);
    glCompileShader(fragment_shader);
    glGetShaderiv(fragment_shader, GL_COMPILE_STATUS,&compile_success);
    if(compile_success == GL_FALSE)
    {
        printf("failed to compile fragment shader\n");
        glDeleteShader(fragment_shader);
        return 0;
    }
    program = glCreateProgram();
    glAttachShader( program,vertex_shader);
    glAttachShader( program,fragment_shader);
    glLinkProgram(program);
    GLint link_success = 0;
    glGetProgramiv(program, GL_LINK_STATUS, &link_success);
    if (link_success == GL_FALSE)
    {
        printf("failed to link program\n");
        glDeleteProgram(program);
        return 0;
    }
    glUseProgram(program);
    u_texture_location = glGetUniformLocation(program, "u_texture");
    u_translate_location = glGetUniformLocation(program,"u_translate");
    a_position_location = glGetAttribLocation(program, "a_position");
    a_texcoord_location = glGetAttribLocation(program, "a_texcoord");
    glGenBuffers(1, &vertex_texture_buffer);
    glBindBuffer( GL_ARRAY_BUFFER, vertex_texture_buffer );
    glBufferData(GL_ARRAY_BUFFER, 
    sizeof(vertex_texture_data),vertex_texture_data, GL_STATIC_DRAW);
    sprite_surface = IMG_Load( "/sprites/spaceship.png" );
    if( !sprite_surface ) {
        printf("failed to load image: %s\n", IMG_GetError() );
        return 0;
    }
    sprite_texture = SDL_CreateTextureFromSurface( renderer, 
    sprite_surface );
    if( !sprite_texture ) {
        printf("failed to create texture: %s\n", IMG_GetError() );
        return 0;
    }
    SDL_QueryTexture( sprite_texture,NULL, NULL,&sprite_width, &sprite_height );
    glTexImage2D( GL_TEXTURE_2D,0,GL_RGBA,sprite_width,sprite_height,
                  0,GL_RGBA,GL_UNSIGNED_BYTE,sprite_surface );
    SDL_FreeSurface( sprite_surface );
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    glEnable(GL_BLEND);
    glEnableVertexAttribArray(a_position_location);
    glEnableVertexAttribArray(a_texcoord_location);
    glVertexAttribPointer(a_position_location,2,GL_FLOAT,GL_FALSE,4 * 
    sizeof(float),(void*)0 );
    glVertexAttribPointer(a_texcoord_location,2,GL_FLOAT,GL_FALSE,
                          4 * sizeof(float),(void*)(2 * sizeof(float)));
    emscripten_set_main_loop(game_loop, 0, 0);
}
```

让我把它分成一些更容易理解的部分。在我们的`main`函数中，我们需要做的第一件事是标准的 SDL 初始化工作。我们需要初始化视频模块，创建一个渲染器，并设置绘制和清除颜色。到现在为止，这段代码应该对你来说已经很熟悉了：

```cpp
SDL_Init( SDL_INIT_VIDEO );
SDL_CreateWindowAndRenderer( CANVAS_WIDTH, CANVAS_HEIGHT, 0, &window, &renderer );
SDL_SetRenderDrawColor( renderer, 0, 0, 0, 255 );
SDL_RenderClear( renderer );
```

接下来，我们需要创建和编译我们的顶点着色器。这需要几个步骤。我们需要创建我们的着色器，将源代码加载到着色器中，编译着色器，然后检查编译时是否出现错误。基本上，这些步骤将你的代码编译，然后将编译后的代码加载到视频卡中以便以后执行。以下是编译顶点着色器所需执行的所有步骤：

```cpp
GLuint vertex_shader = glCreateShader(GL_VERTEX_SHADER);
glShaderSource( vertex_shader,
                1,
                vertex_shader_code,
                0);

glCompileShader(vertex_shader);

GLint compile_success = 0;1
glGetShaderiv(vertex_shader, GL_COMPILE_STATUS, &compile_success);
if(compile_success == GL_FALSE)
{
    printf("failed to compile vertex shader\n");
    glDeleteShader(vertex_shader);
    return 0;
}
```

在编译顶点着色器之后，我们需要编译片段着色器。这是相同的过程。我们首先调用`glCreateShader`来创建一个片段着色器。然后，我们使用`glShaderSource`加载我们的片段着色器源代码。之后，我们调用`glCompileShader`来编译我们的片段着色器。最后，我们调用`glGetShaderiv`来查看在尝试编译我们的片段着色器时是否发生了编译器错误：

```cpp
GLuint fragment_shader = glCreateShader(GL_FRAGMENT_SHADER);
glShaderSource( fragment_shader,
                1,
                fragment_shader_code,
                0);

glCompileShader(fragment_shader);
glGetShaderiv(fragment_shader, GL_COMPILE_STATUS, &compile_success);

if(compile_success == GL_FALSE)
{
    printf("failed to compile fragment shader\n");
    glDeleteShader(fragment_shader);
    return 0;
}
```

为了简单起见，当着色器编译失败时，我保持了错误消息的模糊性。它只告诉你哪个着色器编译失败了。在本章的后面，我将向你展示如何从着色器编译器中获取更详细的错误消息。

现在我们已经编译了我们的着色器，我们需要将我们的着色器链接到一个程序中，然后告诉 OpenGL 这是我们想要使用的程序。如果你正在使用 OpenGL 编写游戏，很有可能你会使用多个程序。例如，你可能希望在游戏中的某些对象上使用光照效果，而在其他对象上不使用。一些游戏对象可能需要旋转和缩放，而其他对象可能不需要。

正如你将在下一章中学到的那样，在 WebGL 中使用多个程序比在本机 OpenGL 应用程序中有更高的 CPU 负担。这与 Web 浏览器的安全检查有关。

对于这个应用程序，我们将使用一个单独的程序，并使用以下代码来附加我们的着色器并将它们链接到程序中：

```cpp
program = glCreateProgram();
glAttachShader( program,
                vertex_shader);

glAttachShader( program,
                fragment_shader);

glLinkProgram(program);

GLint link_success = 0;

glGetProgramiv(program, GL_LINK_STATUS, &link_success);

if (link_success == GL_FALSE)
{
    printf("failed to link program\n");
    glDeleteProgram(program);
    return 0;
}
glUseProgram(program);
```

`glCreateProgram`函数创建一个新的程序并返回一个引用 ID。我们将把这个引用 ID 存储在我们的程序变量中。我们调用`glAttachShader`两次，将我们的顶点着色器和片元着色器附加到我们刚刚创建的程序上。然后我们调用`glLinkProgram`将程序着色器链接在一起。我们调用`glGetProgramiv`来验证程序成功链接。最后，我们调用`glUseProgram`告诉 OpenGL 这是我们想要使用的程序。

现在我们正在使用一个特定的程序，我们可以使用以下代码来检索该程序中属性和统一变量的引用：

```cpp
u_texture_location = glGetUniformLocation(program, "u_texture");
u_translate_location = glGetUniformLocation(program, "u_translate");

a_position_location = glGetAttribLocation(program, "a_position");
a_texcoord_location = glGetAttribLocation(program, "a_texcoord");
```

第一行检索到`u_texture`统一变量的引用，第二行检索到`u_translate`统一变量的引用。我们可以稍后使用这些引用在我们的着色器中设置这些值。之后的两行用于检索到我们着色器中的`a_position`位置属性和`a_texcoord`纹理坐标属性的引用。像统一变量一样，我们稍后将使用这些引用来设置着色器中的值。

现在，我们需要创建并加载数据到一个顶点缓冲区。顶点缓冲区保存了我们将要渲染的每个顶点的属性数据。如果我们要渲染一个 3D 模型，我们需要用从外部检索到的模型数据加载它。幸运的是，对于我们来说，我们只需要渲染一些二维的四边形。四边形足够简单，我们之前能够在一个数组中定义它们。

在我们可以将数据加载到缓冲区之前，我们需要使用`glGenBuffers`来生成该缓冲区。然后我们需要使用`glBindBuffer`来*绑定*缓冲区。绑定缓冲区只是告诉 OpenGL 你当前正在处理哪些缓冲区。以下是生成然后绑定我们的顶点缓冲区的代码：

```cpp
glGenBuffers(1, &vertex_texture_buffer);
glBindBuffer( GL_ARRAY_BUFFER, vertex_texture_buffer );
```

现在我们已经选择了一个缓冲区，我们可以使用`glBufferData`来向缓冲区中放入数据。我们将传入我们之前定义的`vertex_texture_data`。它定义了我们四边形顶点的`x`和`y`坐标以及这些顶点的 UV 映射数据。

```cpp
glBufferData(GL_ARRAY_BUFFER, sizeof(vertex_texture_data),
                vertex_texture_data, GL_STATIC_DRAW);
```

在缓冲我们的数据之后，我们将使用 SDL 来加载一个精灵表面。然后，我们将从该表面创建一个纹理，我们可以用它来找到刚刚加载的图像的宽度和高度。之后，我们调用`glTexImage2D`从 SDL 表面创建一个 OpenGL 纹理。以下是代码：

```cpp
sprite_surface = IMG_Load( "/sprites/spaceship.png" );

if( !sprite_surface ) {
    printf("failed to load image: %s\n", IMG_GetError() );
    return 0;
}

sprite_texture = SDL_CreateTextureFromSurface( renderer, sprite_surface );

if( !sprite_texture ) {
    printf("failed to create texture: %s\n", IMG_GetError() );
    return 0;
}

SDL_QueryTexture( sprite_texture,
                    NULL, NULL,
                    &sprite_width, &sprite_height );

glTexImage2D( GL_TEXTURE_2D,
                0,
                GL_RGBA,
                sprite_width,
                sprite_height,
                0,
                GL_RGBA,
                GL_UNSIGNED_BYTE,
                sprite_surface );

SDL_FreeSurface( sprite_surface );
```

大部分之前的代码应该看起来很熟悉。我们已经使用`IMG_Load`一段时间从虚拟文件系统中加载 SDL 表面。然后我们使用`SDL_CreateTextureFromSurface`创建了一个 SDL 纹理。一旦我们有了纹理，我们使用`SDL_QueryTexture`来找出图像的宽度和高度，并将这些值存储在`sprite_width`和`sprite_height`中。下一个函数调用是新的。`GlTexImage2D`函数用于创建一个新的 OpenGL 纹理图像。我们将`sprite_surface`作为我们的图像数据传入，这是我们几行前加载的图像数据。最后一行使用`SDL_FreeSurface`释放表面。

然后我们添加了两行代码在游戏中启用 alpha 混合：

```cpp
glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
glEnable(GL_BLEND);
```

启用 alpha 混合后，我们有几行代码在着色器中设置属性：

```cpp
glEnableVertexAttribArray(a_position_location);
glEnableVertexAttribArray(a_texcoord_location);

glVertexAttribPointer(
        a_position_location,     // set up the a_position attribute
        2,                       // how many attributes in the position
        GL_FLOAT,                // data type of float
        GL_FALSE,                // the data is not normalized
        4 * sizeof(float),       // stride (how many array items until 
                                 //the next position)
        (void*)0                 // starting point for attribute
);

glVertexAttribPointer(
        a_texcoord_location,         // set up the a_texcoord attribute
        2,                           // how many attributes in the 
                                     //texture coordinates
        GL_FLOAT,                    // data type of float
        GL_FALSE,                    // the data is not normalized
        4 * sizeof(float),           // stride (how many array items 
                                     //until the next position)
        (void*)(2 * sizeof(float))   // starting point for attribute
);
```

游戏循环的前两行启用了着色器中的`a_position`和`a_texcoord`属性。之后，我们调用了两次`glVertexAttribPointer`。这些调用用于告诉着色器每个特定属性分配的数据在顶点缓冲区中的位置。我们用 32 位浮点变量填充了顶点缓冲区。第一次调用`glVertexAttribPointer`设置了`a_position`属性分配的值的位置，使用了我们在`a_position_location`中创建的引用变量。然后我们传入了用于此属性的值的数量。在位置的情况下，我们传入了`x`和`y`坐标，所以这个值是 2。我们传入了缓冲区数组的数据类型，即浮点数据类型。我们告诉函数我们不对数据进行归一化。`stride`值是倒数第二个参数。这是在此缓冲区中用于一个顶点的字节数。因为缓冲区中的每个顶点都使用了四个浮点值，所以我们传入了`4 * sizeof(float)`作为我们的 stride。最后，我们传入的最后一个值是字节偏移量，用于填充此属性的数据。对于`a_position`属性，这个值是`0`，因为位置位于开头。对于`a_texcoord`属性，这个值是`2 * sizeof(float)`，因为在我们的`a_texcoord`数据之前使用了两个浮点值来填充`a_position`。

`main`函数中的最后一行设置了游戏循环回调：

```cpp
emscripten_set_main_loop(game_loop, 0, 0);
```

# 游戏循环

我们的游戏循环非常简单。在游戏循环中，我们将使用 OpenGL 清除画布，移动我们的飞船，并将我们的飞船渲染到画布上。以下是代码：

```cpp
void game_loop() {
    glClearColor( 0, 0, 0, 1 );
    glClear( GL_COLOR_BUFFER_BIT|GL_DEPTH_BUFFER_BIT );

    ship_x += 0.002;
    ship_y += 0.001;

    if( ship_x >= 1.16 ) {
        ship_x = -1.16;
    }

    if( ship_y >= 1.21 ) {
        ship_y = -1.21;
    }

    glUniform4f(u_translate_location,
                ship_x, ship_y, 0, 0 );

    glDrawArrays(GL_TRIANGLES, 0, 6);
}
```

游戏循环的前两行清除画布：

```cpp
glClearColor( 0, 0, 0, 1 );
glClear( GL_COLOR_BUFFER_BIT|GL_DEPTH_BUFFER_BIT );
```

之后，我们有几行代码更新飞船的`x`和`y`坐标，然后在着色器中设置新的坐标：

```cpp
ship_x += 0.002;
ship_y += 0.001;

if( ship_x >= 1.16 ) {
    ship_x = -1.16;
}

if( ship_y >= 1.21 ) {
    ship_y = -1.21;
}

glUniform4f(u_translate_location,
            ship_x, ship_y, 0, 0 );
```

最后，游戏循环使用`glDrawArrays`将我们的飞船绘制到画布上：

```cpp
glDrawArrays(GL_TRIANGLES, 0, 6);
```

# 编译和运行我们的代码

您需要从 GitHub 项目中下载 sprites 文件夹，以便包含我们编译和运行此项目所需的图像文件。一旦您拥有这些图像并将我们刚刚编写的代码保存到`webgl-redux.c`文件中，我们就可以编译和测试这个新应用程序。如果成功，它应该看起来就像第三章中的*WebGL 简介*，WebGL 版本。运行以下`emcc`命令来编译应用程序：

```cpp
emcc webgl-redux.c -o redux.html --preload-file sprites -s USE_WEBGL2=1 -s USE_SDL=2 -s USE_SDL_IMAGE=2 -s SDL2_IMAGE_FORMATS=["png"]
```

如果应用程序成功运行，您应该会看到一艘飞船从左到右并上升到 HTML 画布上。以下是应用程序的工作版本的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/57930775-44b4-4d64-a0ff-01e41f2688e0.png)

图 15.1：OpenGL 和 SDL 应用程序的屏幕截图

在下一节中，我们将学习如何在着色器中混合纹理。

# 混合纹理以产生发光效果

现在，我们将花一些时间学习如何将多个纹理加载到我们的程序中。我们将添加这两个纹理的颜色以创建脉动的光晕效果。为此，我们需要修改我们的片段着色器，以接收第二个纹理和一个时间统一变量。我们将把该变量传递给一个正弦波函数，该函数将用它来计算我们发光引擎的强度。我们需要添加一些代码来跟踪经过的时间，以及一些新的初始化代码来加载第二个纹理。我们可以通过将`webgl-redux.c`复制到一个名为`glow.c`的新文件来开始。现在我们有了新的`glow.c`文件，我们可以逐步了解我们需要做的更改，以实现我们发光引擎的效果。第一个代码更改是添加一个新的`#define`宏，用于定义`2π`的值。

我们将使用一个从`0`到`2π`循环的值，并将其输入正弦波函数，以在我们的引擎光晕上创建脉动效果。以下是我们应该在`glow.c`文件开头附近添加的`#define`：

```cpp
#define TWOPI 6.2831853 // 2π
```

# 片段着色器更改

在添加了新的宏之后，我们需要对我们的片段着色器代码进行一些更改。我们的顶点着色器代码将保持不变，因为确定顶点位置的过程与应用程序先前版本中的过程没有任何不同。以下是片段着色器的更新版本：

```cpp
const GLchar* fragment_shader_code[] = {
    "precision mediump float; \n"
    "varying vec2 v_texcoord; \n"

    "uniform float u_time; \n"
    "uniform sampler2D u_texture; \n"
    "uniform sampler2D u_glow; \n"

    "void main() { \n"
        "float cycle = (sin(u_time) + 1.0) / 2.0; \n"
        "vec4 tex = texture2D(u_texture, v_texcoord); \n"
        "vec4 glow = texture2D(u_glow, v_texcoord); \n"
        "glow.rgb *= glow.aaa; \n"
        "glow *= cycle; \n"
        "gl_FragColor = tex + glow; \n"
    "} \n"
};
```

我们添加了一个名为`u_time`的新统一变量，用于传递一个基于时间的变量，该变量将在`0`和`2π`之间循环。我们还添加了第二个`sampler2D`统一变量，称为`u_glow`，它将保存我们的新光晕纹理。`main`函数的第一行根据`u_time`中的值计算出`0.0`到`1.0`之间的值。我们使用内置的`texture2D`函数从`u_texture`和`u_glow`中检索采样值。这一次，我们不是直接将纹理的值存储到`gl_FragColor`中，而是将这两个值保存到名为`tex`和`glow`的`vec4`变量中。我们将这两个值相加，为了避免所有地方都变得太亮，我们将`glow`样本颜色中的`rgb`（红绿蓝）值乘以 alpha 通道。之后，我们将`glow`颜色中的所有值乘以我们之前计算的`cycle`值。

`cycle`中的值将遵循一个正弦波，在`0.0`和`1.0`之间振荡。这将导致我们的`glow`值随时间上下循环。然后，我们通过将`tex`颜色添加到`glow`颜色来计算我们的片段颜色。然后，我们将输出值存储在`gl_FragColor`中。

# OpenGL 全局变量更改

接下来，我们需要更新与 OpenGL 相关的变量，以便我们可以添加三个新的全局变量。我们需要一个名为`glow_tex`的新变量，我们将用它来存储对光晕纹理的引用。我们还需要两个新的引用变量，用于我们着色器中的两个新的统一变量，称为`u_time_location`和`u_glow_location`。一旦我们添加了这三行，新的 OpenGL 变量块将如下所示：

```cpp
GLuint program = 0;
GLuint texture;
GLuint glow_tex;

GLint a_texcoord_location = -1;
GLint a_position_location = -1;
GLint u_texture_location = -1;
GLint u_glow_location = -1;
GLint u_time_location = -1;

GLint u_translate_location = -1;
GLuint vertex_texture_buffer;
```

# 其他全局变量更改

在我们的 OpenGL 全局变量之后，我们需要添加一个新的与时间相关的全局变量块。我们需要它们来使我们的着色器循环通过值来实现引擎光晕。这些与时间相关的变量应该看起来很熟悉。我们在开发的游戏中使用了类似于我们即将在游戏中使用的技术。以下是这些全局时间变量：

```cpp
float time_cycle = 0;
float delta_time = 0.0;
int diff_time = 0;

Uint32 last_time;
Uint32 last_frame_time;
Uint32 current_time;
```

我们需要添加一个与 SDL 相关的全局表面变量，我们将用它来加载我们的光晕纹理。在`main`函数之前的全局变量块附近添加以下行：

```cpp
SDL_Surface* glow_surface;
```

# `main`函数的更改

我们将对我们在`main`函数中进行的初始化进行一些重大修改。让我先展示整个函数。然后，我们将逐一讲解所有的更改：

```cpp
int main() {
    last_frame_time = last_time = SDL_GetTicks();

    SDL_Init( SDL_INIT_VIDEO );

    SDL_CreateWindowAndRenderer( CANVAS_WIDTH, CANVAS_HEIGHT, 0, 
    &window, &renderer );

    SDL_SetRenderDrawColor( renderer, 0, 0, 0, 255 );
    SDL_RenderClear( renderer );

    GLuint vertex_shader = glCreateShader(GL_VERTEX_SHADER);

    glShaderSource( vertex_shader,
                    1,
                    vertex_shader_code,
                    0);

    glCompileShader(vertex_shader);

    GLint compile_success = 0;
    glGetShaderiv(vertex_shader, GL_COMPILE_STATUS, &compile_success);

    if(compile_success == GL_FALSE)
    {
        printf("failed to compile vertex shader\n");
        glDeleteShader(vertex_shader);
        return 0;
    }

    GLuint fragment_shader = glCreateShader(GL_FRAGMENT_SHADER);

    glShaderSource( fragment_shader,
                    1,
                    fragment_shader_code,
                    0);

    glCompileShader(fragment_shader);
    glGetShaderiv(fragment_shader, GL_COMPILE_STATUS, 
    &compile_success);

    if(compile_success == GL_FALSE)
    {
        printf("failed to compile fragment shader\n");
        glDeleteShader(fragment_shader);
        return 0;
    }

    program = glCreateProgram();
    glAttachShader( program,
                    vertex_shader);

    glAttachShader( program,
                    fragment_shader);

    glLinkProgram(program);

    GLint link_success = 0;

    glGetProgramiv(program, GL_LINK_STATUS, &link_success);

    if (link_success == GL_FALSE)
    {
        printf("failed to link program\n");
        glDeleteProgram(program);
        return 0;
    }

    glUseProgram(program);

    u_glow_location = glGetUniformLocation(program, "u_glow");
    u_time_location = glGetUniformLocation(program, "u_time");

    u_texture_location = glGetUniformLocation(program, "u_texture");
    u_translate_location = glGetUniformLocation(program, 
    "u_translate");

    a_position_location = glGetAttribLocation(program, "a_position");
    a_texcoord_location = glGetAttribLocation(program, "a_texcoord");

    glGenBuffers(1, &vertex_texture_buffer);

glBindBuffer( GL_ARRAY_BUFFER, vertex_texture_buffer );
 glBufferData(GL_ARRAY_BUFFER, sizeof(vertex_texture_data),
 vertex_texture_data, GL_STATIC_DRAW);

sprite_surface = IMG_Load( "/sprites/spaceship.png" );

    if( !sprite_surface ) {
        printf("failed to load image: %s\n", IMG_GetError() );
        return 0;
    }

    sprite_texture = SDL_CreateTextureFromSurface( renderer, 
    sprite_surface );

    if( !sprite_texture ) {
        printf("failed to create texture: %s\n", IMG_GetError() );
        return 0;
    }

    SDL_QueryTexture( sprite_texture,
                        NULL, NULL,
                        &sprite_width, &sprite_height );

    glTexImage2D( GL_TEXTURE_2D,
                    0,
                    GL_RGBA,
                    sprite_width,
                    sprite_height,
                    0,
                    GL_RGBA,
                    GL_UNSIGNED_BYTE,
                    sprite_surface );

    SDL_FreeSurface( sprite_surface );

    glGenTextures( 1,
                    &glow_tex);

    glActiveTexture(GL_TEXTURE1);
    glEnable(GL_TEXTURE_2D);
    glBindTexture(GL_TEXTURE_2D, glow_tex);

    glow_surface = IMG_Load( "/sprites/glow.png" );

    if( !glow_surface ) {
        printf("failed to load image: %s\n", IMG_GetError() );
        return 0;
    }

    glTexImage2D( GL_TEXTURE_2D,
                    0,
                    GL_RGBA,
                    sprite_width,
                    sprite_height,
                    0,
                    GL_RGBA,
                    GL_UNSIGNED_BYTE,
                    glow_surface );

    glGenerateMipmap(GL_TEXTURE_2D);

    SDL_FreeSurface( glow_surface );

    glUniform1i(u_texture_location, 0);
    glUniform1i(u_glow_location, 1);

    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    glEnable(GL_BLEND);

    glEnableVertexAttribArray(a_position_location);
    glEnableVertexAttribArray(a_texcoord_location);

    glVertexAttribPointer(
        a_position_location,     // set up the a_position attribute
        2,                       // how many attributes in the position
        GL_FLOAT,                // data type of float
        GL_FALSE,                // the data is not normalized
        4 * sizeof(float),       // stride (how many array items until 
                                 //the next position)
        (void*)0                 // starting point for attribute
    );

    glVertexAttribPointer(
        a_texcoord_location,       // set up the a_texcoord attribute
        2,                         // how many attributes in the 
                                   //texture coordinates
        GL_FLOAT,                  // data type of float
        GL_FALSE,                  // the data is not normalized
        4 * sizeof(float),         // stride (how many array items 
                                   //until the next position)
        (void*)(2 * sizeof(float)) // starting point for attribute
    );

    emscripten_set_main_loop(game_loop, 0, 0);
}
```

我们`main`函数中的第一行是新的。我们使用该行将`last_frame_time`和`last_time`设置为系统时间，我们使用`SDL_GetTicks()`来获取系统时间：

```cpp
last_frame_time = last_time = SDL_GetTicks();
```

之后，直到我们到达检索统一位置的代码部分之前，我们将不进行任何更改。我们需要从我们的程序中检索另外两个统一位置，因此在我们调用`glUseProgram`之后，我们应该进行以下调用以获取`u_glow`和`u_time`的统一位置：

```cpp
u_glow_location = glGetUniformLocation(program, "u_glow");
u_time_location = glGetUniformLocation(program, "u_time");
```

在我们调用`SDL_FreeSurface`释放`sprite_surface`变量之后必须添加以下代码块。此代码块将生成一个新的纹理，激活它，绑定它，并将`glow.png`图像加载到该纹理中。然后释放 SDL 表面并为我们的纹理生成 mipmaps。最后，我们使用`glUniform1i`设置纹理的统一位置。以下是我们用来加载新纹理的代码：

```cpp
glGenTextures( 1,
                &glow_tex);

glActiveTexture(GL_TEXTURE1);
glEnable(GL_TEXTURE_2D);
glBindTexture(GL_TEXTURE_2D, glow_tex);

glow_surface = IMG_Load( "/sprites/glow.png" );

if( !glow_surface ) {
    printf("failed to load image: %s\n", IMG_GetError() );
    return 0;
}

glTexImage2D( GL_TEXTURE_2D,
                0,
                GL_RGBA,
                sprite_width,
                sprite_height,
                0,
                GL_RGBA,
                GL_UNSIGNED_BYTE,
                glow_surface );

SDL_FreeSurface( glow_surface );

glGenerateMipmap(GL_TEXTURE_2D);

glUniform1i(u_texture_location, 0);
glUniform1i(u_glow_location, 1);
```

如果您对 Mipmaps 不熟悉，您可能会想知道`glGenerateMipmap(GL_TEXTURE_2D);`这一行是做什么的。当您使用 OpenGL 缩放纹理时，这些纹理需要时间来生成。 Mipmaps 是一种通过在游戏初始化时执行一些二次幂缩放版本的图像来加速缩放的方法。这将减少在运行时缩放这些图像所需的时间。

# 更新 game_loop()

为了循环飞船引擎的发光效果，我们需要在我们的游戏循环中添加一些代码，该代码将从`0.0`循环到`2π`。然后，我们将这个值作为`u_time`统一变量传递到着色器中。我们需要将这个新的代码块添加到游戏循环函数的开头：

```cpp
current_time = SDL_GetTicks();

diff_time = current_time - last_time;

delta_time = diff_time / 1000.0;
last_time = current_time;

time_cycle += delta_time * 4;

if( time_cycle >= TWOPI ) {
    time_cycle -= TWOPI;
}

glUniform1f( u_time_location, time_cycle );
```

第一行使用`SDL_GetTicks()`来检索当前时钟时间。然后我们从当前时间中减去上次时间以获得`diff_time`变量的值。这将告诉我们在此帧和上一帧之间生成的毫秒数。之后，我们计算`delta_time`，这将是此帧和上一帧之间的秒数。在我们计算出`diff_time`和`delta_time`之后，我们将`last_time`变量设置为`current_time`。

我们这样做是为了在下次循环游戏时，我们将知道此帧的运行时间。所有这些行都在我们代码的先前版本中。现在，让我们获取`time_cycle`的值，然后将其传递到我们的片段着色器中的`u_time`统一变量中。首先，使用以下行将`delta-time * 4`添加到时间周期中：

```cpp
time_cycle += delta_time * 4;
```

您可能想知道为什么我要将其乘以`4`。最初，我没有添加倍数，这意味着引擎的发光大约每 6 秒循环一次。这感觉循环时间太长。尝试不同的数字，4 的倍数对我来说感觉刚刚好，但如果您希望引擎的循环速度更快或更慢，您无需坚持使用这个特定的倍数。

因为我们使用正弦函数来循环我们的发光级别，所以当我们的时间周期达到`TWOPI`时，我们需要从我们的`time_cycle`变量中减去`TWOPI`：

```cpp
if( time_cycle >= TWOPI ) {
    time_cycle -= TWOPI;
}
```

现在我们已经计算出周期的值，我们使用`u_time_location`引用变量通过调用`glUniform1f`来设置该值：

```cpp
glUniform1f( u_time_location, time_cycle );
```

# 编译和运行我们的代码

现在我们已经做出了所有需要的代码更改，我们可以继续编译和运行我们应用的新版本。通过运行以下`emcc`命令来编译`glow.c`文件：

```cpp
emcc glow.c -o glow.html --preload-file sprites -s USE_WEBGL2=1 -s USE_SDL=2 -s USE_SDL_IMAGE=2 -s SDL2_IMAGE_FORMATS=["png"]
```

如果构建成功，在 Web 浏览器中运行`glow.html`应该显示飞船移动的方式与之前相同。但是现在，引擎上会有一个发光效果。这种发光会上下循环，并在引擎达到最大发光时如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/b7146f36-42c8-4a69-860d-7d08556afe4f.png)

图 15.2：发光着色器应用的屏幕截图

在下一节中，我们将讨论 Phong 3D 光照模型。

# 3D 光照

我想简要讨论一下 3D 光照，因为我们将用 2D 光照效果来近似它。冯氏光照模型是计算机图形学中三维光照模型的标准。它是由 Bui Tuong Phong 于 1975 年在犹他大学创建的光照模型，但直到 20 世纪 90 年代末，台式电脑才足够快速地实现该模型在游戏中的应用。自那时起，这种光照模型已成为 3D 游戏开发的标准。它结合了环境光、漫反射光和镜面光来渲染几何图形。我们无法实现光照模型的正确版本，因为我们不是在写一个 3D 游戏。然而，我们可以通过使用 2D 精灵和法线贴图来近似该模型。

# 环境光

在现实世界中，有一定量的光会随机地反射到周围的表面上。这会产生均匀照亮一切的光线。如果没有环境光，一个物体在另一个物体的阴影下会完全变黑。环境光的数量根据环境而异。在游戏中，环境光的数量通常是根据游戏设计师试图实现的情绪和外观来决定的。对于 2D 游戏，环境光可能是我们唯一有效的光照。在 3D 游戏中，完全依赖环境光会产生看起来平坦的模型：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/312e7693-39ef-4252-9d53-dc284d0a7f31.png)

图 15.3：只有环境光的球

# 漫反射光

漫反射光是来自特定方向的光。如果你在现实世界中看一个三维物体，朝向光源的一面会比背对光源的一面看起来更亮。这给了 3D 环境中的物体一个真正的 3D 外观。在许多 2D 游戏中，漫反射光不是通过着色器创建的，而是由创建精灵的艺术家包含在精灵中。例如，在平台游戏中，艺术家可能会假设游戏对象上方有一个光源。艺术家会通过改变艺术作品中像素的颜色来设计游戏对象具有一种漫反射光。对于许多 2D 游戏来说，这样做完全没问题。然而，如果你想在游戏中加入一个火炬，让它在移动时改变游戏对象的外观，你需要设计能够完成这项工作的着色器：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/26581e91-5ca6-408c-9fb6-319303979dee.png)

图 15.4：有漫反射光的球

# 镜面光

一些物体是有光泽的，并且有反射区域，会产生明亮的高光。当光线照射到表面上时，会有一个基于光线照射表面的角度相对于表面法线的反射向量。镜面高光的强度取决于表面的反射性，以及相对于反射光角度的视角。游戏对象上的镜面高光可以使其看起来光滑或抛光。并非所有游戏对象都需要这种类型的光照，但它在你想要发光的物体上看起来很棒：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/2e8a12b9-f654-49cb-b1bf-ce46a269680d.png)

图 15.5：有镜面光的球

在下一节中，我们将讨论法线贴图及其在现代游戏中的应用。

# 法线贴图

法线贴图是一种在 3D 游戏中使用相对较低的多边形数量创建非常详细模型的方法。其思想是，游戏引擎可以使用一个法线贴图的低多边形模型，其中法线贴图中的每个像素都包含使用图像的红色、绿色和蓝色值的法线的 x、y 和 z 值，而不是创建一个具有大量多边形的表面。在着色器内部，我们可以像对其他纹理贴图进行采样一样采样法线贴图纹理。然而，我们可以使用法线数据来帮助我们计算精灵的光照效果。如果在我们的游戏中，我们希望我们的太空飞船始终相对于游戏区域中心的星星照亮，我们可以为我们的太空飞船创建一个法线贴图，并在游戏中心创建一个光源。我们现在将创建一个应用程序来演示 2D 照明中法线贴图的使用。

# 创建一个 2D 照明演示应用程序

我们可以通过创建一个名为`lighting.c`的新 C 文件来启动我们的照明应用程序。`lighting.c`开头的宏与我们在`glow.c`中使用的宏相同，但我们可以删除`#define TWOPI`宏，因为它不再需要。以下是我们将在`lighting.c`文件中使用的宏：

```cpp
#include <SDL2/SDL.h>
#include <SDL2/SDL_image.h>
#include <SDL_opengl.h>

#include <GLES3/gl3.h>
#include <stdlib.h>
#include <emscripten.h>

#define CANVAS_WIDTH 800
#define CANVAS_HEIGHT 600
#define FLOAT32_BYTE_SIZE 4
#define STRIDE FLOAT32_BYTE_SIZE*4
```

此文件中的顶点着色器代码将与我们在`glow.c`文件中的顶点着色器代码非常相似。我们将做出的一个改变是删除`u_translate`统一变量。我们这样做是因为我们将把我们的阴影精灵图像居中，并允许用户在画布上移动光源。以下是顶点着色器的新版本：

```cpp
const GLchar* vertex_shader_code[] = {
    "precision mediump float; \n"
    "attribute vec4 a_position; \n"
    "attribute vec2 a_texcoord; \n"
    "varying vec2 v_texcoord; \n"

    "void main() { \n"
        "gl_Position = a_position; \n"
        "v_texcoord = a_texcoord; \n"
    "} \n"
};
```

# 片段着色器更新

现在，我们需要创建我们的片段着色器的新版本。这个着色器将加载一个法线贴图以及原始加载的纹理。这个法线贴图将用于计算我们游戏对象的光照法线。这个着色器版本将使用 Phong 光照模型的 2D 形式，我们将计算我们正在渲染的精灵的环境、漫反射和法线光照。以下是我们新片段着色器的代码：

```cpp
const GLchar* fragment_shader_code[] = {
    "precision mediump float; \n"

    "varying vec2 v_texcoord; \n"

    "uniform sampler2D u_texture; \n"
    "uniform sampler2D u_normal; \n"
    "uniform vec3 u_light_pos; \n"

    "const float ambient = 0.6; \n"
    "const float specular = 32.0; \n"
    "const vec3 view_pos = vec3(400, 300,-100); \n"
    "const vec4 light_color = vec4( 0.6, 0.6, 0.6, 0.0); \n"

    "void main() { \n"
        "vec4 tex = texture2D(u_texture, v_texcoord); \n"

        "vec4 ambient_frag = tex * ambient; \n"
        "ambient_frag.rgb *= light_color.rgb; \n"

        "vec3 norm = vec3(texture2D(u_normal, v_texcoord)); \n"
        "norm.xyz *= 2.0; \n"
        "norm.xyz -= 1.0; \n"

        "vec3 light_dir = normalize(gl_FragCoord.xyz - u_light_pos); \n"

        "vec3 view_dir = normalize(view_pos - gl_FragCoord.xyz); \n"
        "vec3 reflect_dir = reflect(light_dir, norm); \n"

        "float reflect_dot = max( dot(view_dir, reflect_dir), 0.0 ); \n"
        "float spec = pow(reflect_dot, specular); \n"
        "vec4 specular_frag = spec * light_color; \n"

        "float diffuse = max(dot(norm, light_dir), 0.0); \n"
        "vec4 diffuse_frag = vec4( diffuse*light_color.r, 
         diffuse*light_color.g, "
                                    "diffuse*light_color.b,  0.0);    \n"
        "gl_FragColor = ambient_frag + diffuse_frag + specular_frag; \n"
    "} \n"
};
```

让我们分解一下新版本片段着色器内部发生的事情。你会注意到的第一件事是，我们有两个`sampler2D`统一变量；第二个称为`u_normal`，用于对我们图像的法线贴图进行采样：

```cpp
"uniform sampler2D u_texture; \n"
"uniform sampler2D u_normal; \n"
```

在我们的采样器之后，我们需要一个`uniform vec3`变量，它保存我们光源的位置。我们称之为`u_light_pos`：

```cpp
"uniform vec3 u_light_pos; \n"
```

在我们的新片段着色器中，我们将使用几个常量。我们将需要环境和镜面光照的因子，以及视图位置和光颜色。我们将在以下四行代码中定义这些常量：

```cpp
"const float ambient = 0.6; \n"
"const float specular = 0.8; \n"
"const vec3 view_pos = vec3(400, 300,-100); \n"
"const vec4 light_color = vec4( 0.6, 0.6, 0.6, 0.0); \n"
```

在我们的`main`函数内，我们需要做的第一件事是获取环境片段颜色。确定环境颜色非常容易。你只需要将纹理颜色乘以环境因子，然后再乘以光颜色。以下是计算片段环境分量值的代码：

```cpp
"vec4 tex = texture2D(u_texture, v_texcoord); \n"
"vec4 ambient_frag = tex * ambient; \n"

"ambient_frag.rgb *= light_color.rgb; \n"
```

计算完我们的环境颜色分量后，我们需要计算我们片段的法线，从我们传递到着色器的法线贴图纹理中。纹理使用红色表示法线的`x`值。绿色表示`y`值。最后，蓝色表示`z`值。颜色都是从`0.0`到`1.0`的浮点数，所以我们需要修改法线的`x`、`y`和`z`分量，使其从`-1.0`到`+1.0`。以下是我们用来定义法线的代码：

```cpp
"vec3 norm = vec3(texture2D(u_normal, v_texcoord)); \n"
"norm.xyz *= 2.0; \n"
"norm.xyz -= 1.0; \n"
```

为了将`norm`向量中的值从`0.0`转换为`1.0`，`-1.0`和`+1.0`，我们需要将法线向量中的值乘以 2，然后减去 1。计算法线值后，我们需要找到我们光源的方向：

```cpp
"vec3 light_dir = normalize(gl_FragCoord.xyz - u_light_pos); \n"
```

我们使用 normalize GLSL 函数对值进行归一化，因为在这个应用程序中我们不会有任何光线衰减。如果你有一个带火炬的游戏，你可能希望基于与光源距离的平方的尖锐衰减。对于这个应用程序，我们假设光源具有无限范围。对于我们的镜面光照，我们需要计算我们的视图方向：

```cpp
"vec3 view_dir = normalize(view_pos - gl_FragCoord.xyz); \n"
```

我们将`view_pos`向量设置为画布的中心，因此当我们的光源也在画布的中心时，我们的镜面光照应该最大。当您编译应用程序时，您将能够测试这一点。在计算视图方向之后，我们需要计算反射向量，这也将用于我们的镜面光照计算：

```cpp
"vec3 reflect_dir = reflect(light_dir, norm); \n"
```

然后我们可以计算这两个向量的点积，并将它们提升到我们的镜面因子（之前定义为 32）的幂，以计算我们需要为这个片段的镜面光照的数量：

```cpp
"float reflect_dot = max( dot(view_dir, reflect_dir), 0.0 ); \n"
"float spec = pow(reflect_dot, specular); \n"
"vec4 specular_frag = spec * light_color; \n"
```

之后，我们使用法线和光线方向的点积来计算片段的漫反射分量。我们将其与光颜色结合以获得我们的漫反射分量值：

```cpp
"float diffuse = max(dot(norm, light_dir), 0.0); \n"
"vec4 diffuse_frag = vec4(diffuse*light_color.r, diffuse*light_color.g, diffuse*light_color.b, 0.0); \n"
```

最后，我们将所有这些值相加以找到我们的片段值：

```cpp
"gl_FragColor = ambient_frag + diffuse_frag + specular_frag; \n"
```

# OpenGL 全局变量

在定义了我们的片段着色器之后，我们需要定义一系列与 OpenGL 相关的全局变量。这些变量应该对你来说是熟悉的，因为它们来自这个应用程序的前两个版本。有一些新变量需要注意。我们将不再只有一个程序 ID。SDL 使用自己的程序，我们也需要一个该程序的 ID。我们将称这个变量为`sdl_program`。我们还需要新的纹理引用。此外，我们还需要新的引用传递给我们的着色器的统一变量。以下是我们的 OpenGL 全局变量代码的新版本：

```cpp
GLuint program = 0;
GLint sdl_program = 0;
GLuint circle_tex, normal_tex, light_tex;
GLuint normal_map;

GLint a_texcoord_location = -1;
GLint a_position_location = -1;
GLint u_texture_location = -1;
GLint u_normal_location = -1;
GLint u_light_pos_location = -1;

GLint u_translate_location = -1;
GLuint vertex_texture_buffer;

float vertex_texture_data[] = {
    // x,    y,         u,   v
     0.167,  0.213,     1.0, 1.0,
    -0.167,  0.213,     0.0, 1.0,
     0.167, -0.213,     1.0, 0.0,
    -0.167, -0.213,     0.0, 0.0,
    -0.167,  0.213,     0.0, 1.0,
     0.167, -0.213,     1.0, 0.0
};
```

# SDL 全局变量

一些 SDL 变量与我们在本章为此创建的先前应用程序中使用的变量相同。用于光照和法线的其他变量是这一部分的新内容。以下是我们在这个应用程序中需要的与 SDL 相关的全局变量：

```cpp
SDL_Window *window;
SDL_Renderer *renderer;

SDL_Texture* light_texture;

SDL_Surface* surface;

int light_width;
int light_height;

int light_x = 600;
int light_y = 200;
int light_z = -300;
```

我们需要声明一个名为`light_texture`的`SDL_Texture`变量，我们将使用它来保存我们光标图标的 SDL 纹理。我们将使用 SDL 来绘制我们的光标图标，而不是使用 OpenGL 来绘制它。我们将使用一个表面指针变量来加载所有的纹理，然后立即释放该表面。我们需要宽度和高度值来跟踪我们光标图标的宽度和高度。我们还需要值来跟踪我们光源的`x`、`y`和`z`坐标。

# 函数原型

因为我想把`main`函数的代码放在其他函数之前，我们需要一些函数原型。在这个应用程序中，我们将有一个游戏循环函数，一个通过 SDL 检索鼠标输入的函数，以及一个使用 SDL 绘制我们的光标图标的函数。以下是这些函数原型的样子：

```cpp
void game_loop();
void input();
void draw_light_icon();
```

# 主函数

就像我们在本章中创建的其他应用程序一样，我们的`main`函数将需要初始化 SDL 和 OpenGL 变量。`main`函数的开头与我们的 glow 应用程序的开头相同。它初始化 SDL，然后编译和链接 OpenGL 着色器并创建一个新的 OpenGL 程序：

```cpp
int main() {
    SDL_Init( SDL_INIT_VIDEO );
    SDL_CreateWindowAndRenderer( CANVAS_WIDTH, CANVAS_HEIGHT, 0, 
    &window, &renderer );
    SDL_SetRenderDrawColor( renderer, 0, 0, 0, 255 );
    SDL_RenderClear( renderer );

    GLuint vertex_shader = glCreateShader(GL_VERTEX_SHADER);

    glShaderSource( vertex_shader,
                    1,
                    vertex_shader_code,
                    0);

    glCompileShader(vertex_shader);

    GLint compile_success = 0;
    glGetShaderiv(vertex_shader, GL_COMPILE_STATUS, &compile_success);

    if(compile_success == GL_FALSE)
    {
        printf("failed to compile vertex shader\n");
        glDeleteShader(vertex_shader);
        return 0;
    }

    GLuint fragment_shader = glCreateShader(GL_FRAGMENT_SHADER);

    glShaderSource( fragment_shader,
                    1,
                    fragment_shader_code,
                    0);

    glCompileShader(fragment_shader);
    glGetShaderiv(fragment_shader, GL_COMPILE_STATUS, 
    &compile_success);

    if(compile_success == GL_FALSE)
    {
        printf("failed to compile fragment shader\n");

        GLint maxLength = 0;
        glGetShaderiv(fragment_shader, GL_INFO_LOG_LENGTH, &maxLength);

        GLchar* errorLog = malloc(maxLength);
        glGetShaderInfoLog(fragment_shader, maxLength, &maxLength, 
        &errorLog[0]);
        printf("error: %s\n", errorLog);

        glDeleteShader(fragment_shader);
        return 0;
    }

    program = glCreateProgram();
    glAttachShader( program,
                    vertex_shader);

    glAttachShader( program,
                    fragment_shader);

    glLinkProgram(program);

    GLint link_success = 0;

    glGetProgramiv(program, GL_LINK_STATUS, &link_success);

    if (link_success == GL_FALSE)
    {
        printf("failed to link program\n");
        glDeleteProgram(program);
        return 0;
    }

    glDeleteShader(vertex_shader);
    glDeleteShader(fragment_shader);
    glUseProgram(program);
```

在初始化 SDL 并创建 OpenGL 着色器程序之后，我们需要获取我们的 OpenGL 着色器程序的统一变量引用。其中两个引用是这个程序版本的新内容。`u_normal_location`变量将是对`u_normal`采样器统一变量的引用，`u_light_pos_location`变量将是对`u_light_pos`统一变量的引用。这是我们引用的新版本：

```cpp
u_texture_location = glGetUniformLocation(program, "u_texture");
u_normal_location = glGetUniformLocation(program, "u_normal");
u_light_pos_location = glGetUniformLocation(program, "u_light_pos");
u_translate_location = glGetUniformLocation(program, "u_translate");
```

在获取了我们统一变量的引用之后，我们需要对我们的属性做同样的事情：

```cpp
a_position_location = glGetAttribLocation(program, "a_position");
a_texcoord_location = glGetAttribLocation(program, "a_texcoord");
```

然后，我们需要生成顶点缓冲区，绑定它，并缓冲我们之前创建的数组中的数据。这应该是我们在`glow.c`文件中的相同代码：

```cpp
glGenBuffers(1, &vertex_texture_buffer);

glBindBuffer( GL_ARRAY_BUFFER, vertex_texture_buffer );
glBufferData( GL_ARRAY_BUFFER, sizeof(vertex_texture_data),
              vertex_texture_data, GL_STATIC_DRAW);
```

接下来，我们需要设置所有的纹理。其中两个将使用 OpenGL 进行渲染，而另一个将使用 SDL 进行渲染。以下是这三个纹理的初始化代码：

```cpp
glGenTextures( 1,
                &circle_tex);

glActiveTexture(GL_TEXTURE0);
glBindTexture(GL_TEXTURE_2D, circle_tex);

surface = IMG_Load( "/sprites/circle.png" );
if( !surface ) {
    printf("failed to load image: %s\n", IMG_GetError() );
    return 0;
}

glTexImage2D( GL_TEXTURE_2D,
                0,
                GL_RGBA,
                128, // sprite width
                128, // sprite height
                0,
                GL_RGBA,
                GL_UNSIGNED_BYTE,
                surface );

glUniform1i(u_texture_location, 1);
glGenerateMipmap(GL_TEXTURE_2D);

SDL_FreeSurface( surface );

glGenTextures( 1,
                &normal_tex);

glActiveTexture(GL_TEXTURE1);
glBindTexture(GL_TEXTURE_2D, normal_tex);

surface = IMG_Load( "/sprites/ball-normal.png" );

if( !surface ) {
    printf("failed to load image: %s\n", IMG_GetError() );
    return 0;
}

glTexImage2D( GL_TEXTURE_2D,
                0,
                GL_RGBA,
                128, // sprite width
                128, // sprite height
                0,
                GL_RGBA,
                GL_UNSIGNED_BYTE,
                surface );

glUniform1i(u_normal_location, 1);
glGenerateMipmap(GL_TEXTURE_2D);

SDL_FreeSurface( surface );

surface = IMG_Load( "/sprites/light.png" );

if( !surface ) {
    printf("failed to load image: %s\n", IMG_GetError() );
    return 0;
}

light_texture = SDL_CreateTextureFromSurface( renderer, surface );

if( !light_texture ) {
    printf("failed to create light texture: %s\n", IMG_GetError() );
    return 0;
}

SDL_QueryTexture( light_texture,
                    NULL, NULL,
                    &light_width, &light_height );

SDL_FreeSurface( surface );
```

这是一个相当大的代码块，让我一步一步地解释。前三行生成、激活和绑定圆形纹理，以便我们可以开始更新它：

```cpp
glGenTextures( 1,
                &circle_tex);

glActiveTexture(GL_TEXTURE0);
glBindTexture(GL_TEXTURE_2D, circle_tex);
```

现在我们已经准备好更新圆形纹理，我们可以使用 SDL 加载图像文件：

```cpp
surface = IMG_Load( "/sprites/circle.png" );

if( !surface ) {
    printf("failed to load image: %s\n", IMG_GetError() );
    return 0;
}
```

接下来，我们需要将数据加载到我们绑定的纹理中：

```cpp
glTexImage2D( GL_TEXTURE_2D,
                0,
                GL_RGBA,
                128, // sprite width
                128, // sprite height
                0,
                GL_RGBA,
                GL_UNSIGNED_BYTE,
                surface );
```

然后，我们可以激活该纹理，生成 mipmaps，并释放表面：

```cpp
glUniform1i(u_texture_location, 1);
glGenerateMipmap(GL_TEXTURE_2D);

SDL_FreeSurface( surface );
```

在为我们的圆形纹理做完这些之后，我们需要为我们的法线贴图做同样一系列的步骤：

```cpp
glGenTextures( 1,
                &normal_tex);

glActiveTexture(GL_TEXTURE1);
glBindTexture(GL_TEXTURE_2D, normal_tex);
surface = IMG_Load( "/sprites/ball-normal.png" );

if( !surface ) {
    printf("failed to load image: %s\n", IMG_GetError() );
    return 0;
}

glTexImage2D( GL_TEXTURE_2D,
    0,
    GL_RGBA,
    128, // sprite width
    128, // sprite height
    0,
    GL_RGBA,
    GL_UNSIGNED_BYTE,
    surface );

glUniform1i(u_normal_location, 1);
glGenerateMipmap(GL_TEXTURE_2D);

SDL_FreeSurface( surface );
```

我们将以不同的方式处理最终的纹理，因为它只会使用 SDL 进行渲染。现在你应该对这个很熟悉了。我们需要从图像文件加载表面，从表面创建纹理，查询该纹理的大小，然后释放原始表面：

```cpp
surface = IMG_Load( "/sprites/light.png" );

if( !surface ) {
    printf("failed to load image: %s\n", IMG_GetError() );
    return 0;
}

light_texture = SDL_CreateTextureFromSurface( renderer, surface );

if( !light_texture ) {
    printf("failed to create light texture: %s\n", IMG_GetError() );
    return 0;
}

SDL_QueryTexture( light_texture,
                    NULL, NULL,
                    &light_width, &light_height );

SDL_FreeSurface( surface );
```

现在我们已经创建了我们的纹理，我们应该设置我们的 alpha 混合：

```cpp
glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
glEnable(GL_BLEND);
```

`main`函数的最后一行使用 Emscripten 调用游戏循环：

```cpp
emscripten_set_main_loop(game_loop, 0, 0);
```

# 游戏循环函数

现在我们已经定义了`main`函数，我们需要定义我们的`game_loop`。因为`game_loop`函数同时使用 SDL 和 OpenGL 进行渲染，所以我们需要在每次循环之前设置顶点属性指针，然后在 OpenGL 中进行渲染。我们还需要在多个 OpenGL 程序之间切换，因为 SDL 使用的着色程序与我们用于 OpenGL 的着色程序不同。让我先向您展示整个函数，然后我们可以一步一步地解释它：

```cpp
void game_loop() {
    input();

    glGetIntegerv(GL_CURRENT_PROGRAM,&sdl_program);
    glUseProgram(program);

    glClearColor( 0, 0, 0, 1 );
    glClear( GL_COLOR_BUFFER_BIT|GL_DEPTH_BUFFER_BIT );

    glBindBuffer(GL_ARRAY_BUFFER, vertex_texture_buffer);
    glVertexAttribPointer(
        a_position_location,       // set up the a_position attribute
        2,                         // how many attributes in the 
                                   //position
        GL_FLOAT,                  // data type of float
        GL_FALSE,                  // the data is not normalized
        4 * sizeof(float),         // stride (how many array items 
                                   //until the next position)
        (void*)0                   // starting point for attribute
     );

    glEnableVertexAttribArray(a_texcoord_location);
    glBindBuffer(GL_ARRAY_BUFFER, vertex_texture_buffer);
    glVertexAttribPointer(
        a_texcoord_location,     // set up the a_texcoord attribute
        2,                       // how many attributes in the texture 
                                 //coordinates
        GL_FLOAT,                // data type of float
        GL_FALSE,                // the data is not normalized
        4 * sizeof(float),       // stride (how many array items until 
                                 //the next position)
        (void*)(2 * sizeof(float)) // starting point for attribute
    );

    glUniform3f( u_light_pos_location,
                (float)(light_x), (float)(600-light_y), (float)(light_z) );

    glDrawArrays(GL_TRIANGLES, 0, 6);

    glUseProgram(sdl_program);
    draw_light_icon();
}

```

游戏循环的第一行调用了`input`函数。这个函数将使用鼠标输入来设置光源位置。第二和第三行检索 SDL 着色程序并将其保存到`sdl_program`变量中。然后，它通过调用`glUseProgram`切换到自定义的 OpenGL 着色程序。以下是我们调用以保存当前程序并设置新程序的两行代码：

```cpp
glGetIntegerv(GL_CURRENT_PROGRAM,&sdl_program);
glUseProgram(program);
```

之后，我们调用 OpenGL 来清除画布：

```cpp
glClearColor( 0, 0, 0, 1 );
glClear( GL_COLOR_BUFFER_BIT|GL_DEPTH_BUFFER_BIT );
```

接下来，我们需要设置我们的几何形状：

```cpp
glBindBuffer(GL_ARRAY_BUFFER, vertex_texture_buffer);
glVertexAttribPointer(
            a_position_location,   // set up the a_position attribute
            2,                     // how many attributes in the 
                                   //position
            GL_FLOAT,              // data type of float
            GL_FALSE,              // the data is not normalized
            4 * sizeof(float),     // stride (how many array items 
                                   //until the next position)
            (void*)0               // starting point for attribute
);

glEnableVertexAttribArray(a_texcoord_location);
glBindBuffer(GL_ARRAY_BUFFER, vertex_texture_buffer);
glVertexAttribPointer(
    a_texcoord_location,          // set up the a_texcoord attribute
    2,                            // how many attributes in the texture 
                                  //coordinates
    GL_FLOAT,                     // data type of float
    GL_FALSE,                     // the data is not normalized
    4 * sizeof(float),            // stride (how many array items until 
                                  //the next position)
    (void*)(2 * sizeof(float))    // starting point for attribute
);
```

然后，我们使用`glUniform3f`调用将`vec3 uniform u_light_pos`变量设置为我们之前定义的`light_x`、`light_y`和`light_z`全局变量。这些光源位置可以通过鼠标移动。允许用户移动光源的代码将在我们编写`input`函数时定义。设置完光源位置的值后，我们可以使用 OpenGL 绘制我们的三角形：

```cpp
glDrawArrays(GL_TRIANGLES, 0, 6);
```

最后，我们需要切换回我们的 SDL 程序并调用`draw_light_icon`函数，这将使用 SDL 绘制我们的光标图标：

```cpp
glUseProgram(sdl_program);
draw_light_icon();
```

# 输入函数

现在我们已经定义了我们的游戏循环，我们需要编写一个函数来捕获鼠标输入。我希望能够点击我们的画布，让光标图标和光源移动到我刚刚点击的位置。我还希望能够按住鼠标按钮并拖动光标图标在画布上移动，以查看光源在画布上不同位置时阴影的效果。大部分代码看起来都很熟悉。我们使用`SDL_PollEvent`来检索事件，并查看左鼠标按钮是否按下，或用户是否移动了滚轮。如果用户转动了滚轮，`light_z`变量会改变，进而改变我们光源的`z`位置。我们使用`static int mouse_down`变量来跟踪用户是否按下了鼠标按钮。如果用户按下了鼠标按钮，我们将调用`SDL_GetMouseState`来检索`light_x`和`light_y`变量，这将修改我们光源的 x 和 y 位置。以下是输入函数的完整代码：

```cpp
void input() {
    SDL_Event event;
    static int mouse_down = 0;

    if(SDL_PollEvent( &event ) )
    {
        if(event.type == SDL_MOUSEWHEEL )
        {
            if( event.wheel.y > 0 ) {
                light_z+= 100;
            }
            else {
                light_z-=100;
            }

            if( light_z > 10000 ) {
                light_z = 10000;
            }
            else if( light_z < -10000 ) {
                light_z = -10000;
            }
        }
        else if(event.type == SDL_MOUSEMOTION )
        {
            if( mouse_down == 1 ) {
                SDL_GetMouseState( &light_x, &light_y );
            }
        }
        else if(event.type == SDL_MOUSEBUTTONDOWN )
        {
            if(event.button.button == SDL_BUTTON_LEFT)
            {
                SDL_GetMouseState( &light_x, &light_y );
                mouse_down = 1;
            }
        }
        else if(event.type == SDL_MOUSEBUTTONUP )
        {
            if(event.button.button == SDL_BUTTON_LEFT)
            {
                mouse_down = 0;
            }
        }
    }
}
```

# 绘制光标图标函数

我们需要在`lighting.c`文件中定义的最后一个函数是`draw_light_icon`函数。该函数将使用 SDL 根据`light_x`和`light_y`变量的值来绘制我们的光源图标。我们创建一个名为`dest`的`SDL_Rect`变量，并设置该结构的`x`、`y`、`w`和`h`属性。然后，我们调用`SDL_RenderCopy`在适当的位置渲染我们的光源图标。以下是该函数的代码：

```cpp
void draw_light_icon() {
    SDL_Rect dest;
    dest.x = light_x - light_width / 2 - 32;
    dest.y = light_y - light_height / 2;
    dest.w = light_width;
    dest.h = light_height;

    SDL_RenderCopy( renderer, light_texture, NULL, &dest );
}
```

# 编译和运行我们的照明应用

当我们编译和运行我们的照明应用时，我们应该能够在画布上单击并拖动我们的光源。我们有一个与法线贴图相关联的小圆圈。结合我们的着色和照明，它应该使得该圆圈看起来更像一个闪亮的按钮。在命令行上执行以下命令来编译`lighting.html`文件：

```cpp
emcc lighting.c -o lighting.html --preload-file sprites -s USE_SDL=2 -s USE_SDL_IMAGE=2 -s SDL2_IMAGE_FORMATS=["png"]
```

现在，您应该能够从 Web 服务器或 emrun 中提供`lighting.html`文件。如果一切顺利，应用程序应该如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/aade1966-f9f3-46d9-a525-75605d4672ca.png)

图 15.6：2D 照明应用的屏幕截图

# 摘要

在本章中，我们在第三章 *WebGL 简介*中介绍了着色器的概念后，更深入地研究了着色器。当我们构建了一个 WebGL 应用时，了解 WebGL 是有帮助的。当您在使用 OpenGL for WebAssembly 时，因为每次从 WebAssembly 调用 OpenGL 时，内部都会调用相应的 WebGL 函数。我们首先使用 OpenGL ES 和 C++中的 SDL 重新构建了该 WebGL 应用，并将其编译为 WebAssembly。然后，我们学习了如何使用 OpenGL 和着色器以有趣的方式混合不同的纹理。我们利用这些知识创建了一个围绕飞船引擎的脉动发光效果。最后，我们讨论了 3D 照明和法线贴图，然后开发了一个 2D 照明模型，并创建了一个允许我们使用该照明模型照亮简单圆圈的应用程序。该应用程序通过允许我们在 2D 圆圈上移动光源并使用法线贴图来展示 2D 照明的可能性，法线贴图用于赋予该 2D 表面深度的外观。

在下一章中，我们将讨论调试我们的 WebAssembly 应用程序以及我们可以用于性能测试的工具。
