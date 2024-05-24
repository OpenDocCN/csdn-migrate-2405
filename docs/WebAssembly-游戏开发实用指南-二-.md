# WebAssembly 游戏开发实用指南（二）

> 原文：[`annas-archive.org/md5/2bc11e3fb2b816b3a221f95dafc6aa63`](https://annas-archive.org/md5/2bc11e3fb2b816b3a221f95dafc6aa63)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：在 WebAssembly 中使用 SDL 进行精灵动画

在撰写本文时，Simple DirectMedia Layer（SDL）是唯一集成到 Emscripten 中供 WebAssembly 使用的 2D 渲染库。但是，即使更多的渲染库变得可用，SDL 也是一个得到广泛支持的渲染库，已经被移植到了大量平台，并且在可预见的未来仍将保持相关和有用，用于 WebAssembly 和 C++开发。使用 SDL 渲染到 WebGL 可以节省大量时间，因为我们不必自己编写 WebAssembly C++代码和 WebGL 之间的接口代码。庞大的社区还提供支持和文档。您可以在[libsdl.org](http://libsdl.org)上找到更多 SDL 资源。

您需要在构建中包含几个图像才能使此项目工作。确保包括项目的 GitHub 中的`/Chapter04/sprites/`和`/Chapter04/font/`文件夹。如果您还没有下载 GitHub 项目，可以从以下网址在线获取：[`github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly`](https://github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly)。

本章我们将涵盖以下主题：

+   在 WebAssembly 中使用 SDL

+   将精灵渲染到画布上

+   动画精灵

+   移动精灵

# 在 WebAssembly 中使用 SDL

到目前为止，我可以为 WebAssembly 模块和 JavaScript WebGL 库之间的交互自己开发系统。这将涉及使用函数表从 C++中调用 JavaScript WebGL 函数。幸运的是，Emscripten 团队已经完成了大部分工作。他们已经为我们创建了一个流行的 2D C++图形库的端口，可以实现这一点。SDL 是一个建立在大多数实现中的 OpenGL 之上的 2D 图形 API。有一个 Emscripten 端口，用于帮助我们在 WebGL 上渲染我们的 2D 图形。如果您想知道 Emscripten 集成了哪些其他库，请使用以下`emcc`命令：

```cpp
emcc --show-ports
```

如果您运行此命令，您会注意到显示了几个不同的 SDL 库。这些包括 SDL2、SDL2_image、SDL2_gfx、SDL2_ttf 和 SDL2_net。SDL 是以模块化设计创建的，允许用户只包含他们需要的 SDL 部分，从而使核心 SDL 库保持较小。如果您的目标是创建一个下载大小受限的网络游戏，这将非常有帮助。

我们将首先通过创建一个简单的“Hello World”应用程序来熟悉 SDL，该应用程序将一些文本写入 HTML5 画布元素。为此，我们需要包含我们运行`emcc --show-ports`命令时列出的 Emscripten 库中的两个。我们需要通过在 Emscripten 编译时添加`USE_SDL=2`标志来添加核心 SDL 库，还需要通过添加`USE_SDL_TTF=2`标志来添加 SDL TrueType 字体库。

将在 HTML 画布中显示消息`"HELLO SDL!"`的`.c`源代码相对简单：

```cpp
#include <SDL2/SDL.h>
#include <SDL2/SDL_ttf.h>
#include <emscripten.h>
#include <stdio.h>

#define MESSAGE "HELLO SDL!"
#define FONT_SIZE 16
#define FONT_FILE "font/Roboto-Black.ttf"

int main() {
    SDL_Window *window;
    SDL_Renderer *renderer;

    SDL_Rect dest = {.x = 160, .y = 100, .w = 0, .h = 0 };

    TTF_Font *font;
    SDL_Texture* texture;

    SDL_Init( SDL_INIT_VIDEO );
    TTF_Init();

    SDL_CreateWindowAndRenderer( 320, 200, 0, &window, &renderer );

    SDL_SetRenderDrawColor( renderer, 0, 0, 0, 255 );
    SDL_RenderClear( renderer );

    font = TTF_OpenFont( FONT_FILE, FONT_SIZE );

    SDL_Color font_color = {255, 255, 255, 255 }; // WHITE COLOR
    SDL_Surface *temp_surface = TTF_RenderText_Blended( font, 
                                                        MESSAGE, 
                                                       font_color );

    texture = SDL_CreateTextureFromSurface( renderer, temp_surface );

    SDL_FreeSurface( temp_surface );
    SDL_QueryTexture( texture,
                        NULL, NULL,
                        &dest.w, &dest.h ); // query the width and 
                                               height

    dest.x -= dest.w / 2;
    dest.y -= dest.h / 2;

    SDL_RenderCopy( renderer, texture, NULL, &dest );
    SDL_RenderPresent( renderer );

    return EXIT_SUCCESS;
}
```

让我来详细介绍一下这里发生了什么。代码的前四行是 SDL 头文件，以及 Emscripten 头文件：

```cpp
#include <SDL2/SDL.h>
#include <SDL2/SDL_ttf.h>
#include <emscripten.h>
#include <stdio.h>
```

在此之后，有三个预处理器定义。如果我们想快速更改消息或字体大小，我们将修改这前两行。第三个定义不太清楚。我们有一个叫做`FONT_FILE`的东西，它是一个看起来像是文件系统位置的字符串。这有点奇怪，因为 WebAssembly 无法访问本地文件系统。为了让 WebAssembly 模块访问 fonts 目录中的 TrueType 字体文件，我们将在编译`WASM`文件时使用`--preload-file`标志。这将从字体目录的内容生成一个`.data`文件。Web 浏览器将此数据文件加载到虚拟文件系统中，WebAssembly 模块可以访问该文件。这意味着我们编写的 C 代码将可以像访问本地文件系统一样访问此文件：

```cpp
#define MESSAGE "HELLO SDL!"
#define FONT_SIZE 16
#define FONT_FILE "font/Roboto-Black.ttf"
```

# 初始化 SDL

与 C/C++的其他目标一样，代码从`main`函数开始执行。我们将通过声明一些变量来启动我们的`main`函数：

```cpp
int main() {
    SDL_Window *window;
    SDL_Renderer *renderer;

    SDL_Rect dest = {.x = 160, .y = 100, .w = 0, .h = 0 };
    TTF_Font *font;

    SDL_Texture *texture;
```

前两个变量是`SDL_Window`和`SDL_Renderer`对象。`window`对象将定义应用程序窗口，如果我们为 Windows、Mac 或 Linux 系统编写代码，我们将渲染到该窗口中。当我们构建 WebAssembly 时，我们的 HTML 中有一个画布，但 SDL 仍然需要一个`window`对象指针来进行初始化和清理。所有对 SDL 的调用都使用`renderer`对象将图像渲染到画布上。

`SDL_Rect dest`变量是一个表示我们将要渲染到画布上的目标的矩形。我们将渲染到 320x200 画布的中心，所以我们将从`x`和`y`值`160`和`100`开始。我们还不知道我们将要渲染的文本的宽度和高度，所以在这一点上，我们将`w`和`h`设置为`0`。我们稍后会重置这个值，所以理论上，我们可以将它设置为任何值。

`TTF_Font *font`变量是指向`SDL_TTF`库的`font`对象的指针。稍后，我们将使用该对象从虚拟文件系统加载字体，并将该字体渲染到`SDL_Texture *texture`指针变量。`SDL_Texture`变量由 SDL 用于将精灵渲染到画布上。

接下来的几行用于在 SDL 中进行一些初始化工作：

```cpp
SDL_Init( SDL_INIT_VIDEO );
TTF_Init();

SDL_CreateWindowAndRenderer( 320, 200, 0, &window, &renderer );
```

`SDL_Init`函数使用单个标志调用，仅初始化视频子系统。顺便说一句，我不知道 SDL 的任何用例不需要视频子系统初始化。许多开发人员将 SDL 用作 OpenGL/WebGL 图形渲染系统；因此，除非您设计了一个仅音频的游戏，否则应始终传入`SDL_INIT_VIDEO`标志。如果您想初始化其他 SDL 子系统，您将使用布尔或`|`运算符传入这些子系统的标志，如下面的代码片段所示：

```cpp
 SDL_Init( SDL_INIT_VIDEO | SDL_INIT_AUDIO | SDL_INIT_HAPTIC );
```

如果我们使用上一行，SDL 也会初始化音频和触觉子系统，但我们现在不需要它们，所以我们不会进行更改。

`TTF_Init();`函数初始化我们的 TrueType 字体，`SDL_CreateWindowAndRenderer`向我们返回`window`和`renderer`对象。我们传入`320`作为画布的宽度，`200`作为高度。第三个变量是`window`标志。我们传入`0`作为该参数，表示我们不需要任何`window`标志。因为我们正在使用 SDL Emscripten 端口，我们无法控制窗口，所以这些标志不适用。

# 清除 SDL 渲染器

初始化完成后，我们需要清除渲染器。我们可以用任何颜色清除我们的渲染器。为了做到这一点，我们将调用`SDL_RenderDrawColor`函数：

```cpp
SDL_SetRenderDrawColor( renderer, 0, 0, 0, 255 );
SDL_RenderClear( renderer );
```

这将为渲染器设置绘图颜色为完全不透明的黑色。`0, 0, 0`是 RGB 颜色值，`255`是 alpha 不透明度。这些数字的范围都是从 0 到 255，其中 255 是颜色光谱上的全色。我们设置这样，这样当我们在下一行调用`SDL_RenderClear`函数时，它将用黑色清除渲染器。如果我们想要清除红色而不是黑色，我们需要修改以下调用方式：

```cpp
SDL_SetRenderDrawColor( renderer, 255, 0, 0, 255 );
```

这不是我们想要的，所以我们不会做出这种改变。我只是想指出我们可以用任何颜色清除渲染器。

# 使用 WebAssembly 虚拟文件系统

接下来的几行将在虚拟文件系统中打开 TrueType 字体文件，并将其渲染到`SDL_Texture`，这可以用来渲染到画布：

```cpp
font = TTF_OpenFont( FONT_FILE, FONT_SIZE );
SDL_Color font_color = {255, 255, 255, 255 }; // WHITE COLOR
SDL_Surface *temp_surface = TTF_RenderText_Blended( font, MESSAGE,
                                                    font_color );
texture = SDL_CreateTextureFromSurface( renderer, temp_surface );
SDL_FreeSurface( temp_surface ); 
```

在前面代码的第一行中，我们通过在程序顶部定义的 WebAssembly 虚拟文件系统中传递文件的位置来打开 TrueType 字体。我们还需要指定字体的点大小，这也在程序顶部定义为 16。接下来，我们创建一个`SDL_Color`变量，我们将用它来设置字体的颜色。这是一个 RGBA 颜色，我们将所有值设置为 255，这样它就是完全不透明的白色。做完这些之后，我们需要使用`TTF_RenderText_Blended`函数将文本渲染到一个表面上。我们传递了几行前打开的 TrueType 字体，`MESSAGE`，在程序顶部定义为`"HELLO SDL!"`，以及定义为白色的字体颜色。然后，我们将从我们的表面创建一个纹理，并释放我们刚刚分配的表面内存。在使用表面指针创建纹理后，您应该立即释放表面指针的内存，因为一旦您有了纹理，表面就不再需要了。

# 将纹理渲染到 HTML5 画布

从虚拟文件系统加载字体，然后将该字体渲染到纹理后，我们需要将该纹理复制到渲染器对象的位置。在完成这些操作后，我们需要将渲染器的内容呈现到 HTML5 画布元素。

以下是将纹理渲染到画布的源代码：

```cpp
SDL_QueryTexture( texture,
                    NULL, NULL,
                    &dest.w, &dest.h ); // query the width and height

dest.x -= dest.w / 2;
dest.y -= dest.h / 2;

SDL_RenderCopy( renderer, texture, NULL, &dest );
SDL_RenderPresent( renderer ); 
```

调用`SDL_QueryTexture`函数用于检索纹理的宽度和高度。我们需要使用这些值在目标矩形中，以便我们将纹理渲染到画布而不改变其尺寸。在那个调用之后，程序知道了纹理的宽度和高度，所以它可以使用这些值来修改目标矩形的*x*和*y*变量，以便它可以将我们的文本居中在画布上。因为`dest`（目标）矩形的*x*和*y*值指定了该矩形的左上角，我们需要减去矩形宽度的一半和矩形高度的一半，以确保它居中。然后`SDL_RenderCopy`函数将这个纹理渲染到我们的渲染缓冲区，`SDL_RenderPresent`将整个缓冲区移动到 HTML5 画布上。

到这一点，代码中剩下的就是`return`：

```cpp
return EXIT_SUCCESS;
```

以`EXIT_SUCCESS`的值返回告诉我们的 JavaScript 粘合代码，当运行这个模块时一切都进行得很好。

# 清理 SDL。

您可能会注意到这段代码中缺少的内容，这在 Windows 或 Linux 版本的 SDL 应用程序中会有，那就是在程序结束时进行一些 SDL 清理的代码。例如，如果我们在 Windows 中退出应用程序，而没有进行清理工作，我们将退出而不清除 SDL 分配的一些内存。如果这不是一个 WebAssembly 模块，以下行将包含在函数的末尾：

```cpp
SDL_Delay(5000);
SDL_DestroyWindow(window);
SDL_Quit();
```

因为我们还没有花时间制作游戏循环，我们希望通过调用`SDL_Delay(5000)`来延迟清理和退出程序五秒，`5000`是等待进行清理之前的毫秒数。我们要重申，因为我们正在编译为 WebAssembly，我们不希望清理我们的 SDL。这对不同的浏览器有不同的影响。

在 Firefox 中测试此代码时，使用延迟是不必要的，因为 Web 浏览器标签会在 WebAssembly 模块停止执行后保持打开。然而，Chrome 浏览器标签在 SDL 销毁`window`对象后会显示错误页面。

`SDL_DestroyWindow`函数会在 Windows 环境下销毁`window`对象。`SDL_Quit`函数终止 SDL 引擎，最后，`return EXIT_SUCCESS;`从`main`函数成功退出。

# 编译 hello_sdl.html

最后，我们将使用 Emscripten 的`emcc`编译器编译和测试我们的 WebAssembly 模块：

```cpp
emcc hello_sdl.c --emrun --preload-file font -s USE_SDL=2 -s USE_SDL_TTF=2 -o hello_sdl.html
```

重要的是要记住，您必须使用 Web 服务器或`emrun`来运行 WebAssembly 应用程序。如果您想使用`emrun`来运行 WebAssembly 应用程序，您必须使用`--emrun`标志进行编译。Web 浏览器需要 Web 服务器来流式传输 WebAssembly 模块。如果您尝试直接从硬盘驱动器在浏览器中打开使用 WebAssembly 的 HTML 页面，那么 WebAssembly 模块将无法加载。

在这次对`emcc`的调用中，我们使用了一些新的标志，并临时省略了`--shell-file new_shell.html`标志，该标志用于生成模板的定制版本。如果您想继续使用`emrun`来测试应用程序，您必须包括`--emrun`标志，以使用`emrun`命令运行。如果您使用 Node.js 等 Web 服务器来提供应用程序，则可以从现在开始省略`--emrun`标志。如果您喜欢使用`emrun`，请继续使用该标志进行编译。

我们已经添加了`--preload-file`字体标志，以便我们可以创建包含在`hello_sdl.data`文件中的虚拟文件系统。这个文件保存了我们的 TrueType 字体。应用程序使用了核心 SDL 库和额外的 SDL TrueType 字体模块，因此我们包含了以下标志`-s USE_SDL=2 -s USE_SDL_TTF=2`，以允许调用`SDL`和`SDL_ttf`。如果您的编译顺利进行，当您在浏览器中打开新的`hello_sdl.html`文件时，它将会是这个样子：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/261996ad-2fb3-49af-9505-dead70bfb861.png)

图 4.1：Hello SDL!应用程序截图

在下一节中，我们将学习如何使用 SDL 将精灵渲染到 HTML5 画布上。

# 将精灵渲染到画布上

现在我们已经学会了如何使用 SDL 和 Emscripten 将文本渲染到 HTML 画布元素，我们可以迈出下一步，学习如何渲染精灵。用于将精灵渲染到画布的代码与我们用于渲染 TrueType 字体的代码非常相似。我们仍然使用虚拟文件系统来生成包含我们使用的精灵的数据文件，但是我们需要一个新的 SDL 库来实现这一点。我们不再需要`SDL2_ttf`来加载 TrueType 字体并将其渲染到纹理。相反，我们需要`SDL2_image`。稍后我们将向您展示如何更改我们对`emcc`的调用以包含这个新库。

首先，让我们来看一下新版本的 SDL 代码，它将图像渲染到我们的 HTML 画布元素上，而不是我们在上一节中渲染的文本：

```cpp
#include <SDL2/SDL.h>
#include <SDL2/SDL_image.h>
#include <emscripten.h>
#include <stdio.h>
#define SPRITE_FILE "sprites/Franchise1.png"

int main() {
    SDL_Window *window;
    SDL_Renderer *renderer;
    SDL_Rect dest = {.x = 160, .y = 100, .w = 0, .h = 0 };
    SDL_Texture *texture;
    SDL_Init( SDL_INIT_VIDEO );
    SDL_CreateWindowAndRenderer( 320, 200, 0, &window, &renderer );
    SDL_SetRenderDrawColor( renderer, 0, 0, 0, 255 );
    SDL_RenderClear( renderer );
    SDL_Surface *temp_surface = IMG_Load( SPRITE_FILE );

    if( !temp_surface ) {
        printf("failed to load image: %s\n", IMG_GetError() );
        return 0;
    }

    texture = SDL_CreateTextureFromSurface( renderer, temp_surface );

    SDL_FreeSurface( temp_surface );

    SDL_QueryTexture( texture,
                        NULL, NULL,
                        &dest.w, &dest.h ); // query the width and 
                        height

    dest.x -= dest.w / 2;
    dest.y -= dest.h / 2;

    SDL_RenderCopy( renderer, texture, NULL, &dest );
    SDL_RenderPresent( renderer );

 SDL_Delay(5000);
 SDL_DestroyWindow(window);
 SDL_Quit();
    return 1;
}
```

这段代码类似于我们在上一节*HTML5 和 WebAssembly*中编写的代码，用于*HELLO SDL!*应用程序。我们使用的是`SDL2_image`模块，而不是`SDL2_ttf`模块。因此，我们需要包含`SDL2/SDL_image.h`头文件。我们还需要从`sprites`目录加载一个精灵文件，并将其添加到 WebAssembly 虚拟文件系统中：

```cpp
SDL_Surface *temp_surface = IMG_Load( SPRITE_FILE );

if( !temp_surface ) {
    printf("failed to load image: %s\n", IMG_GetError() );
    return 0;
}
```

在调用`IMG_Load`之后，我们添加了一个错误检查，以便在文件加载失败时让我们知道出了什么问题。除此之外，代码大部分都是相同的。如果成功，画布将显示我们的 16x16 像素的 Starship Franchise 图像：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/e3515281-4ae7-471c-ba8c-b98e64540058.png)

图 4.2：Franchise1.png

在下一节中，我们将学习如何使用 SDL 在画布上制作动画精灵。

# 动画精灵

在本节中，我们将学习如何在 SDL 应用程序中制作一个快速而简单的动画。这不是我们在最终游戏中做动画的方式，但它会让您了解我们如何通过在 SDL 内部交换纹理来随时间创建动画。我将呈现分解为两部分的代码来动画精灵。第一部分包括我们的预处理宏、全局变量和`show_animation`函数：

```cpp
#include <SDL2/SDL.h>
#include <SDL2/SDL_image.h>

#include <emscripten.h>
#include <stdio.h>

#define SPRITE_FILE "sprites/Franchise1.png"
#define EXP_FILE "sprites/FranchiseExplosion%d.png"
#define FRAME_COUNT 7

int current_frame = 0;
Uint32 last_time;
Uint32 current_time;
Uint32 ms_per_frame = 100; // animate at 10 fps

SDL_Window *window;
SDL_Renderer *renderer;
SDL_Rect dest = {.x = 160, .y = 100, .w = 0, .h = 0 };
SDL_Texture *sprite_texture;
SDL_Texture *temp_texture;
SDL_Texture* anim[FRAME_COUNT];

void show_animation() {
    current_time = SDL_GetTicks();
    int ms = current_time - last_time;

    if( ms < ms_per_frame) {
        return;
    }

    if( current_frame >= FRAME_COUNT ) {
        SDL_RenderClear( renderer );
        return;
    }

    last_time = current_time;
    SDL_RenderClear( renderer );

    temp_texture = anim[current_frame++];

    SDL_QueryTexture( temp_texture,
                        NULL, NULL,
                        &dest.w, &dest.h ); // query the width and       
                                               height

    dest.x = 160 - dest.w / 2;
    dest.y = 100 - dest.h / 2;

    SDL_RenderCopy( renderer, temp_texture, NULL, &dest );
    SDL_RenderPresent( renderer );
}

```

在定义了`show_animation`函数之后，我们需要定义模块的`main`函数：

```cpp
int main() {
    char explosion_file_string[40];
    SDL_Init( SDL_INIT_VIDEO );
    SDL_CreateWindowAndRenderer( 320, 200, 0, &window, &renderer );

    SDL_SetRenderDrawColor( renderer, 0, 0, 0, 255 );
    SDL_RenderClear( renderer );

    SDL_Surface *temp_surface = IMG_Load( SPRITE_FILE );

    if( !temp_surface ) {
        printf("failed to load image: %s\n", IMG_GetError() );
        return 0;
    }

    sprite_texture = SDL_CreateTextureFromSurface( renderer, 
    temp_surface );

    SDL_FreeSurface( temp_surface );

    for( int i = 1; i <= FRAME_COUNT; i++ ) {
        sprintf( explosion_file_string, EXP_FILE, i );
        SDL_Surface *temp_surface = IMG_Load( explosion_file_string );

        if( !temp_surface ) {
            printf("failed to load image: %s\n", IMG_GetError() );
            return 0;
        }

        temp_texture = SDL_CreateTextureFromSurface( renderer, 
        temp_surface );
        anim[i-1] = temp_texture;
        SDL_FreeSurface( temp_surface );
    }

    SDL_QueryTexture( sprite_texture,
                        NULL, NULL,
                        &dest.w, &dest.h ); // query the width and 
                                               height

    dest.x -= dest.w / 2;
    dest.y -= dest.h / 2;

    SDL_RenderCopy( renderer, sprite_texture, NULL, &dest );
    SDL_RenderPresent( renderer );

    last_time = SDL_GetTicks();
    emscripten_set_main_loop(show_animation, 0, 0);
    return 1;
}
```

这里有很多内容需要解释。有更高效的方法来做这个动画，但我们在这里所做的是基于我们已经完成的工作并进行扩展。在代码的早期版本中，我们将单个帧呈现到画布上，然后退出 WebAssembly 模块。如果您的目标是将静态内容呈现到画布并永远不更改它，那么这样做就足够了。但是，如果您正在编写游戏，则需要能够对精灵进行动画处理并在画布上移动它们。在这里，我们遇到了一个问题，如果我们将 C++代码编译为 WebAssembly 以外的任何目标，我们就不会遇到这个问题。游戏通常在循环中运行，并直接负责向屏幕渲染。WebAssembly 在 Web 浏览器的 JavaScript 引擎内运行。WebAssembly 模块本身无法更新我们的画布。Emscripten 使用 JavaScript 粘合代码间接从 SDL API 更新 HTML 画布。但是，如果 WebAssembly 在循环中运行，并使用该循环通过 SDL 来对我们的精灵进行动画处理，那么 WebAssembly 模块永远不会释放它所在的线程，并且 JavaScript 永远没有机会更新画布。因此，我们不能将游戏循环放在`main`函数中。相反，我们必须创建一个不同的函数，并使用 Emscripten 来设置 JavaScript 粘合代码，以便在每次浏览器渲染帧时调用该函数。我们将使用的函数如下：

```cpp
emscripten_set_main_loop(show_animation, 0, 0);
```

我们将传递给`emscripten_set_main_loop`的第一个参数是`show_animation`。这是我们在代码顶部附近定义的一个函数的名称。稍后我会谈论`show_animation`函数的具体内容。现在，知道这是每次浏览器在画布上渲染新帧时调用的函数就足够了。

`emscripten_set_main_loop`的第二个参数是**每秒帧数**（**FPS**）。如果要将游戏的 FPS 设置为固定速率，可以通过在此处将目标帧速率传递给函数来实现。如果传入`0`，这告诉`emscripten_set_main_loop`以尽可能高的帧速率运行。通常情况下，您希望游戏以尽可能高的帧速率运行，因此传入`0`通常是最好的做法。如果传入的值高于计算机能够渲染的速度，它将以其能够的速度渲染，因此此值仅对 FPS 设置了上限。

我们传递的第三个参数是`simulate_infinite_loop`。传入`0`等同于传递`false`值。如果此参数的值为`true`，它会强制模块在每帧通过`main`函数重新进入。我不确定这个用例是什么。我建议将其保持为`0`，并将游戏循环分离到另一个函数中，就像我们在这里做的那样。

在调用`emscripten_set_main_loop`之前，我们将设置一个 SDL 纹理表面指针的数组：

```cpp
for( int i = 1; i <= FRAME_COUNT; i++ ) {
 sprintf( explosion_file_string, EXP_FILE, i );
    SDL_Surface *temp_surface = IMG_Load( explosion_file_string );

    if( !temp_surface ) {
        printf("failed to load image: %s\n", IMG_GetError() );
        return 0;
    }

    temp_texture = SDL_CreateTextureFromSurface( renderer, temp_surface );
    anim[i-1] = temp_texture;
    SDL_FreeSurface( temp_surface );
}
```

这个循环将`FranchiseExplosion1.png`到`FranchiseExplosion7.png`加载到一个 SDL 纹理数组中，并将它们存储到一个名为`anim`的不同数组中。这是我们稍后将在`show_animation`函数中循环的数组。有更有效的方法可以使用精灵表，并通过修改目标矩形来实现这一点。我们将在后面的章节中讨论渲染动画精灵的这些技术。

在代码的顶部附近，我们定义了`show_animation`函数，每渲染一帧就调用一次：

```cpp
void show_animation() {
    current_time = SDL_GetTicks();
    int ms = current_time - last_time;

    if( ms < ms_per_frame) {
        return;
    }

    if( current_frame >= FRAME_COUNT ) {
        SDL_RenderClear( renderer );
        return;
    }

    last_time = current_time;
    SDL_RenderClear( renderer );

    temp_texture = anim[current_frame++];

    SDL_QueryTexture( temp_texture,
                        NULL, NULL,
                        &dest.w, &dest.h ); // query the width and 
                                               height

    dest.x = 160 - dest.w / 2;
    dest.y = 100 - dest.h / 2;

    SDL_RenderCopy( renderer, temp_texture, NULL, &dest );
    SDL_RenderPresent( renderer );
}
```

这个函数的设计是等待一定的毫秒数，然后更新我们正在渲染的纹理。我创建了一个七帧动画，让星际特许经营号在一个小像素化的爆炸中爆炸。在这个循环中我们需要短暂等待的原因是，我们的刷新率可能是 60+ FPS，如果我们每次调用`show_animation`时都渲染一个新的动画帧，整个动画将在大约 1/10 秒内运行完毕。经典的街机游戏经常以比游戏帧率慢得多的速度翻转它们的动画序列。许多经典的**任天堂娱乐系统**（**NES**）游戏使用两阶段动画，其中动画会在几百毫秒内交替精灵，尽管 NES 的帧率是 60 FPS。

这个函数的核心与我们之前创建的单纹理渲染类似。主要的区别是在改变动画帧之前我们等待固定的毫秒数，通过递增`current_frame`变量来遍历我们动画的所有七个阶段，这需要不到一秒的时间。

# 移动精灵

现在我们已经学会了如何以逐帧动画的方式为我们的精灵添加动画，我们将学习如何在画布上移动精灵。我希望保持我们的飞船动画，但我希望它不要在`爆炸`循环中运行。在我们的`sprites`文件夹中，我包含了一个简单的四阶段动画，可以使我们飞船的引擎闪烁。源代码非常长，所以我将分三部分介绍它：预处理和全局变量部分，`show_animation`函数和`main`函数。

这是我们的`cpp`文件开头定义的预处理指令和全局变量的代码：

```cpp
#include <SDL2/SDL.h>
#include <SDL2/SDL_image.h>

#include <emscripten.h>
#include <stdio.h>

#define SPRITE_FILE "sprites/Franchise1.png"
#define EXP_FILE "sprites/Franchise%d.png"

#define FRAME_COUNT 4

int current_frame = 0;
Uint32 last_time;
Uint32 current_time;
Uint32 ms_per_frame = 100; // animate at 10 fps

SDL_Window *window;

SDL_Renderer *renderer;
SDL_Rect dest = {.x = 160, .y = 100, .w = 0, .h = 0 };
SDL_Texture *sprite_texture;
SDL_Texture *temp_texture;
SDL_Texture* anim[FRAME_COUNT];
```

在预处理指令和全局变量之后，我们的`cpp`文件包含了一个定义游戏循环的`show_animation`函数。以下是我们`show_animation`函数的代码：

```cpp
void show_animation() {
    current_time = SDL_GetTicks();
    int ms = current_time - last_time;

    if( ms >= ms_per_frame) {
        ++current_frame;
        last_time = current_time;
    }

    if( current_frame >= FRAME_COUNT ) {
        current_frame = 0;
    }

    SDL_RenderClear( renderer );
    temp_texture = anim[current_frame];

    dest.y--;

    if( dest.y < -16 ) {
        dest.y = 200;
    }

    SDL_RenderCopy( renderer, temp_texture, NULL, &dest );
    SDL_RenderPresent( renderer );
}

```

我们的`cpp`文件的最后部分定义了`main`函数。这是我们的 WebAssembly 模块中的初始化代码：

```cpp
int main() {
    char explosion_file_string[40];
    SDL_Init( SDL_INIT_VIDEO );
    SDL_CreateWindowAndRenderer( 320, 200, 0, &window, &renderer );
    SDL_SetRenderDrawColor( renderer, 0, 0, 0, 255 );
    SDL_RenderClear( renderer );
    SDL_Surface *temp_surface = IMG_Load( SPRITE_FILE );

    if( !temp_surface ) {
        printf("failed to load image: %s\n", IMG_GetError() );
        return 0;
    }

    sprite_texture = SDL_CreateTextureFromSurface( renderer, 
    temp_surface );
    SDL_FreeSurface( temp_surface );

    for( int i = 1; i <= FRAME_COUNT; i++ ) {
        sprintf( explosion_file_string, EXP_FILE, i );
        SDL_Surface *temp_surface = IMG_Load( explosion_file_string );

        if( !temp_surface ) {
            printf("failed to load image: %s\n", IMG_GetError() );
            return 0;
        }

        temp_texture = SDL_CreateTextureFromSurface( renderer, 
        temp_surface );

        anim[i-1] = temp_texture;
        SDL_FreeSurface( temp_surface );
    }

    SDL_QueryTexture( sprite_texture,
                        NULL, NULL,
                        &dest.w, &dest.h ); // query the width and 
                                               height

    dest.x -= dest.w / 2;
    dest.y -= dest.h / 2;

    SDL_RenderCopy( renderer, sprite_texture, NULL, &dest );
    SDL_RenderPresent( renderer );

    last_time = SDL_GetTicks();
    emscripten_set_main_loop(show_animation, 0, 0);
    return 1;
}
```

这段代码类似于我们的`sprite_animation`代码。只有一些修改，大部分在`show_animation`函数中：

```cpp
void show_animation() {
    current_time = SDL_GetTicks();

    int ms = current_time - last_time;

    if( ms >= ms_per_frame) {
        ++current_frame;
        last_time = current_time;
    }

    if( current_frame >= FRAME_COUNT ) {
        current_frame = 0;
    }

    SDL_RenderClear( renderer );
    temp_texture = anim[current_frame];

    dest.y--;

    if( dest.y < -16 ) {
        dest.y = 200;
    }

    SDL_RenderCopy( renderer, temp_texture, NULL, &dest );
    SDL_RenderPresent( renderer );
}
```

当`ms`中的值超过`ms_per_frame`时，我们就会推进我们的帧，`ms`跟踪自上一帧更改以来的毫秒数，我们将`ms_per_frame`设置为`100`。因为飞船在移动，我们仍然需要在每一帧更新我们的画布以显示新的飞船位置。我们通过修改`dest.y`的值来实现这一点，这告诉 SDL 在 y 轴上渲染我们的飞船。我们每一帧都从`dest.y`变量中减去 1，以将飞船向上移动。我们还进行了一个检查，看看这个值是否变小到小于`-16`。因为精灵高度为 16 像素，当精灵完全移出屏幕顶部时，这种情况就会发生。如果是这种情况，我们需要通过将`y`值设置回`200`来将精灵移回游戏屏幕的底部。在实际游戏中，像这样直接将我们的移动与帧速率绑定在一起是一个坏主意，但是对于这个演示来说，这样做是可以的。

# 编译 sprite.html

现在我们可以使用`emcc`命令来编译我们的精灵 WebAssembly 应用程序。您需要从 GitHub 的`Chapter02`文件夹中获取`sprites`文件夹。在您下载了`sprites`文件夹并将其放在项目文件夹中之后，您可以使用以下命令编译应用程序：

```cpp
emcc sprite_move.c --preload-file sprites -s USE_SDL=2 -s USE_SDL_IMAGE=2 -s SDL2_IMAGE_FORMATS=["png"] -o sprite_move.html
```

重要的是要记住，应用程序必须从 Web 服务器上运行，或者使用`emrun`。如果您不从 Web 服务器上运行应用程序，或者使用`emrun`，当 JavaScript 粘合代码尝试下载 WASM 和数据文件时，您将收到各种错误。您还应该知道，为了设置`.wasm`和`.data`文件扩展名的正确 MIME 类型，IIS 需要额外的配置。

我们仍然使用`--preload-file`标志，但是这次我们传递的是`sprites`文件夹，而不是`fonts`文件夹。我们将继续使用`-s USE_SDL=2`标志，并将添加`-s USE_SDL_IMAGE=2`标志，这将允许我们在 SDL 中使用图像，这是`.bmp`文件格式的替代品。

为了告诉`SDL_IMAGE`要使用哪种文件格式，我们使用以下`-s SDL2_IMAGE_FORMATS=["png"]`标志传递`png`格式：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/3bd87aeb-0bf2-46f2-95ba-58180ce3f054.png)

图 4.3：sprite_move.html 的屏幕截图

# 总结

在本章中，我向您介绍了 SDL 及其可在 WebAssembly 中使用的模块库。我们了解了 WebAssembly 虚拟文件系统，以及 Emscripten 如何创建`.data`文件以便在 WebAssembly 虚拟文件系统中访问。我教会了您如何使用 SDL 将图像和字体渲染到 HTML 画布上。最后，我们学会了如何使用 SDL 在游戏中创建简单的动画。

在下一章中，我们将学习如何使用键盘输入来移动画布上的游戏对象。


# 第五章：键盘输入

现在我们有了精灵和动画，可以在画布上移动这些精灵，我们需要在游戏中添加一些交互。有几种方法可以获取游戏的键盘输入。一种方法是通过 JavaScript，根据输入调用 WebAssembly 模块中的不同函数。我们代码的第一部分将做到这一点。我们将在 WebAssembly 模块中添加一些函数，供我们在 JavaScript 包装器中使用。我们还将设置一些 JavaScript 键盘事件处理程序，这些处理程序将在触发键盘事件时调用我们的 WebAssembly 模块。

我们可以让 SDL 来为我们处理所有繁重的工作，从而将输入传递到我们的 WebAssembly 模块中。这涉及将 C 代码添加到我们的 WebAssembly 模块中，以捕获`SDL_KEYDOWN`和`SDL_KEYUP`事件。然后，模块将查看事件的键码，以确定触发事件的键。使用任一方法编写我们的代码都有成本和收益。一般来说，让 SDL 管理我们的键盘输入会使我们失去在 JavaScript 中编写键盘输入管理器的灵活性，同时，我们也会获得更加直接的代码的好处。

您需要在构建中包含几个图像，以使该项目正常工作。确保您从项目的 GitHub 中包含`/Chapter05/sprites/`文件夹。如果您还没有下载 GitHub 项目，可以在以下网址在线获取：[`github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly`](https://github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly)。

在本章中，我们将执行以下操作：

+   学习如何使用 JavaScript 键盘事件调用我们的 WebAssembly 模块

+   学习如何使用 SDL 事件来管理 WebAssembly 模块内的键盘输入

+   通过使用键盘输入来移动画布上的飞船精灵来演示我们所学到的内容

# JavaScript 键盘输入

我们将首先学习如何监听 JavaScript 键盘事件，并根据这些事件调用我们的 WebAssembly 模块。我们将重用我们为第二章编写的大部分代码，*HTML5 和 WebAssembly*，所以我们应该首先从`Chapter02`文件夹中获取该代码，并将其复制到我们的新`Chapter05`文件夹中。将`Chapter02`目录中的`new_shell.html`文件复制到`Chapter05`目录，然后将该文件重命名为`jskey_shell.html`。接下来，将`Chapter02`目录中的`shell.c`复制到`Chapter05`目录，并将该文件重命名为`jskey.c`。最后，将`Chapter02`目录中的`shell.css`文件复制到`Chapter05`目录，但不要重命名。这三个文件将为我们编写 JavaScript 键盘输入代码提供一个起点。

首先，让我们来看一下我们刚刚从`shell.c`创建的`jskey.c`文件。我们可以在文件的开头就把大部分代码删除掉。删除`main`函数结束后的所有代码。这意味着你将删除以下所有代码：

```cpp
void test() {
    printf("button test\n");
}

void int_test( int num ) {
    printf("int test=%d\n", num);
}

void float_test( float num ) {
    printf("float test=%f\n", num);
}

void string_test( char* str ) {
    printf("string test=%s\n", str);
}
```

接下来，我们将修改`main`函数。我们不再希望在`main`函数内部使用`EM_ASM`来调用我们的 JavaScript 包装器初始化函数，因此从`main`函数中删除以下两行代码：

```cpp
EM_ASM( InitWrappers() );
printf("Initialization Complete\n");
```

在我们的`main`函数中，唯一剩下的是一个`printf`语句。我们将更改该行以让我们知道`main`函数已运行。您可以更改此代码以说任何您喜欢的内容，或者完全删除`printf`语句。以下代码显示了我们`main`函数的内容：

```cpp
int main() {
    printf("main has run\n");
}
```

现在我们已经修改了`main`函数，并删除了我们不再需要的所有函数，让我们添加一些在触发 JavaScript`keyboard`事件时调用的函数。当用户在键盘上按下箭头键时，我们将添加一个`keypress`事件的函数。以下代码将被这些`keypress`事件调用：

```cpp
void press_up() {
    printf("PRESS UP\n");
}

void press_down() {
    printf("PRESS DOWN\n");
}

void press_left() {
    printf("PRESS LEFT\n");
}

void press_right() {
    printf("PRESS RIGHT\n");
}
```

我们还想知道用户何时释放按键。因此，我们将在 C 模块中添加四个`release`函数，如下所示：

```cpp
void release_up() {
    printf("RELEASE UP\n");
}

void release_down() {
    printf("RELEASE DOWN\n");
}

void release_left() {
    printf("RELEASE LEFT\n");
}

void release_right() {
    printf("RELEASE RIGHT\n");
}
```

现在我们有了新的 C 文件，我们可以改变我们的 shell 文件。打开`jskey_shell.html`。我们不需要改变`head`标签中的任何内容，但在`body`内部，我们将删除许多我们将不再使用的 HTML 元素。继续删除除`textarea`元素之外的所有元素。我们希望保留`textarea`元素，以便我们可以看到模块内的`printf`语句的输出。我们需要在`jskey_shell.html`中删除以下 HTML，然后再删除`textarea`元素之后的`div`及其内容：

```cpp
<div class="input_box">&nbsp;</div>
<div class="input_box">
    <button id="click_me" class="em_button">Click Me!</button>
</div>

<div class="input_box">
    <input type="number" id="int_num" max="9999" min="0" step="1" 
     value="1" class="em_input">
    <button id="int_button" class="em_button">Int Click!</button>
</div>

<div class="input_box">
    <input type="number" id="float_num" max="99" min="0" step="0.01" 
     value="0.0" class="em_input">
    <button id="float_button" class="em_button">Float Click!</button>
</div>

<div class="input_box">&nbsp;</div>
```

然后，在`textarea`元素之后，我们需要删除以下`div`及其内容：

```cpp
<div id="string_box">
    <button id="string_button" class="em_button">String Click!</button>
    <input id="string_input">
</div>
```

之后，我们有包含所有 JavaScript 代码的`script`标签。我们需要在该`script`标签中添加一些全局变量。首先，让我们添加一些布尔变量，告诉我们玩家是否按下了我们的任何箭头键。将所有这些值初始化为`false`，如下例所示：

```cpp
var left_key_press = false;
var right_key_press = false;
var up_key_press = false;
var down_key_press = false;
```

在我们的`key_press`标志之后，我们将有所有将用于保存调用我们 WebAssembly 模块内函数的`wrapper`函数的`wrapper`变量。我们将所有这些包装器初始化为`null`。稍后，我们只会在这些函数不为`null`时调用这些函数。以下代码显示了我们的包装器：

```cpp
var left_press_wrapper = null;
var left_release_wrapper = null;

var right_press_wrapper = null;
var right_release_wrapper = null;

var up_press_wrapper = null;
var up_release_wrapper = null;

var down_press_wrapper = null;
var down_release_wrapper = null;
```

现在我们已经定义了所有的全局变量，我们需要添加在`key_press`和`key_release`事件上触发的函数。其中之一是`keyPress`函数。我们为这个函数编写的代码如下：

```cpp
function keyPress() {
    event.preventDefault();
    if( event.repeat === true ) {
        return;
    }

    // PRESS UP ARROW
    if (event.keyCode === 38) {
        up_key_press = true;
        if( up_press_wrapper != null ) up_press_wrapper();
    }

    // PRESS LEFT ARROW
    if (event.keyCode === 37) {
        left_key_press = true;
        if( left_press_wrapper != null ) left_press_wrapper();
    }

    // PRESS RIGHT ARROW
    if (event.keyCode === 39) {
        right_key_press = true;
        if( right_press_wrapper != null ) right_press_wrapper();
    }

    // PRESS DOWN ARROW
    if (event.keyCode === 40) {
        down_key_press = true;
        if( down_press_wrapper != null ) down_press_wrapper();
    }
}
```

这个函数的第一行是`event.preventDefault();`。这一行阻止了网页浏览器在用户按下相应键时通常会做的事情。例如，如果你正在玩游戏，并按下下箭头键使你的飞船向下移动，你不希望网页也滚动向下。在`keyPress`函数的开头放置这个`preventDefault`调用将禁用所有按键的默认行为。在其他项目中，这可能不是你想要的。如果你只想在按下下箭头键时禁用默认行为，你会将该调用放在管理下箭头键按下的`if`块内。以下代码块检查事件是否为重复事件：

```cpp
if( event.repeat === true ) {
    return;
}
```

如果你按住其中一个键是正确的。例如，如果你按住上箭头键，你最初会得到一个上箭头键按下事件，但是，经过一段时间后，你会开始得到一个重复的上箭头键事件。你可能已经注意到，如果你曾经按住一个单一的键，比如*F*键，你会在你的文字处理器中看到一个 f，但是，一秒左右后你会开始看到 fffffffffffff，你会继续看到 f 重复进入你的文字处理器，只要你按住*F*键。一般来说，这种行为在使用文字处理器时可能是有帮助的，但在玩游戏时是有害的。前面的`if`块使我们在接收到重复按键事件时退出函数。

我们函数中的接下来的几个`if`块检查各种 JavaScript 键码，并根据这些键码调用我们的 WebAssembly 模块。让我们快速看一下当玩家按下上箭头键时会发生什么：

```cpp
// PRESS UP ARROW
if (event.keyCode === 38) {
    up_key_press = true;
    if( up_press_wrapper != null ) up_press_wrapper();
}
```

`if`语句正在检查事件的键码是否等于值`38`，这是上箭头的键码值。您可以在[`www.embed.com/typescript-games/html-keycodes.html`](https://www.embed.com/typescript-games/html-keycodes.html)找到 HTML5 键码的列表。如果触发事件是上箭头键按下，我们将`up_key_press`变量设置为`true`。如果我们的`up_press_wrapper`已初始化，我们将调用它，它将调用 WebAssembly 模块内的`press_up`函数。在检查上箭头键码的`if`块之后，我们将需要更多的`if`块来检查其他箭头键，如下例所示：

```cpp
    // PRESS LEFT ARROW
    if (event.keyCode === 37) {
        left_key_press = true;
        if( left_press_wrapper != null ) left_press_wrapper();
    }

    // PRESS RIGHT ARROW
    if (event.keyCode === 39) {
        right_key_press = true;
        if( right_press_wrapper != null ) right_press_wrapper();
    }

    // PRESS DOWN ARROW
    if (event.keyCode === 40) {
        down_key_press = true;
        if( down_press_wrapper != null ) down_press_wrapper();
    }
}
```

在`keyUp`函数之后，我们需要创建一个非常相似的函数：`keyRelease`。这个函数与`keyUp`几乎相同，只是它将调用 WebAssembly 模块中的按键释放函数。以下代码显示了`keyRelease()`函数的样子：

```cpp
function keyRelease() {
    event.preventDefault();

    // PRESS UP ARROW
    if (event.keyCode === 38) {
        up_key_press = false;
        if( up_release_wrapper != null ) up_release_wrapper();
    }

    // PRESS LEFT ARROW
    if (event.keyCode === 37) {
        left_key_press = false;
        if( left_release_wrapper != null ) left_release_wrapper();
    }

    // PRESS RIGHT ARROW
    if (event.keyCode === 39) {
        right_key_press = false;
        if( right_release_wrapper != null ) right_release_wrapper();
    }

    // PRESS DOWN ARROW
    if (event.keyCode === 40) {
        down_key_press = false;
        if( down_release_wrapper != null ) down_release_wrapper();
    }
}
```

在定义了这些函数之后，我们需要使用以下两行 JavaScript 代码将它们作为事件监听器：

```cpp
document.addEventListener('keydown', keyPress);
document.addEventListener('keyup', keyRelease);
```

接下来我们需要修改我们的`InitWrappers`函数来包装我们之前创建的函数。我们使用`Module.cwrap`函数来实现这一点。我们的`InitWrappers`函数的新版本如下：

```cpp
function InitWrappers() {
    left_press_wrapper = Module.cwrap('press_left', 'undefined');
    right_press_wrapper = Module.cwrap('press_right', 'undefined');
    up_press_wrapper = Module.cwrap('press_up', 'undefined');
    down_press_wrapper = Module.cwrap('press_down', 'undefined');

    left_release_wrapper = Module.cwrap('release_left', 'undefined');
    right_release_wrapper = Module.cwrap('release_right', 'undefined');
    up_release_wrapper = Module.cwrap('release_up', 'undefined');
    down_release_wrapper = Module.cwrap('release_down', 'undefined');
}
```

我们有两个不再需要的函数可以删除。这些是`runbefore`和`runafter`函数。这些函数在第二章的 shell 中使用，用来演示`preRun`和`postRun`模块功能。它们只是在控制台中记录一行，所以请从`jskey_shell.html`文件中删除以下代码：

```cpp
function runbefore() {
    console.log("before module load");
}

function runafter() {
    console.log("after module load");
}
```

现在我们已经删除了这些行，我们可以从模块的`preRun`和`postRun`数组中删除对这些函数的调用。因为我们之前已经从 WebAssembly 模块的`main`函数中删除了对`EM_ASM( InitWrappers() );`的调用，所以我们需要从模块的`postRun`数组中运行`InitWrappers`。以下代码显示了这些更改后`Module`对象定义的开头是什么样子的：

```cpp
preRun: [],
postRun: [InitWrappers],
```

现在我们应该构建和测试我们的新 JavaScript 键盘处理程序。运行以下`emcc`命令：

```cpp
emcc jskey.c -o jskey.html  -s NO_EXIT_RUNTIME=1 --shell-file jskey_shell.html -s EXPORTED_FUNCTIONS="['_main', '_press_up', '_press_down', '_press_left', '_press_right', '_release_up', '_release_down', '_release_left', '_release_right']" -s EXTRA_EXPORTED_RUNTIME_METHODS="['cwrap', 'ccall']"
```

您会注意到我们使用了`-s EXPORT_FUNCTIONS`标志来导出所有的按键按下和按键释放函数。因为我们没有使用默认的 shell，我们使用了`--shell-file jskey_shell.html`标志。`-s NO_EXIT_RUNTIME=1`标志防止浏览器在没有 emscripten 主循环时退出 WebAssembly 模块。我们还使用`-s EXTRA_EXPORTED_RUNTIME_METHODS="['cwrap', 'ccall']"`导出了`cwrap`和`ccall`。

以下是应用程序的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/e34de0b2-9525-4a1b-9cad-5e851c5e1368.png)

图 5.1：jskey.html 的屏幕截图

重要的是要记住，应用程序必须从 Web 服务器运行，或者使用`emrun`。如果您不从 Web 服务器运行应用程序，或者使用`emrun`，当 JavaScript 粘合代码尝试下载 WASM 和数据文件时，您将收到各种错误。您还应该知道，IIS 需要额外的配置才能为`.wasm`和`.data`文件扩展名设置正确的 MIME 类型。

在下一节中，我们将使用 SDL 事件处理程序和默认的 WebAssembly shell 来捕获和处理键盘事件。

# 向 WebAssembly 添加 SDL 键盘输入

SDL 允许我们轮询键盘输入。每当用户按下键时，调用`SDL_PollEvent( &event )`将返回一个`SDK_KEYDOWN SDL_Event`。当释放键时，它将返回一个`SDK_KEYUP`事件。在这种情况下，我们可以查看这些值，以确定哪个键被按下或释放。我们可以使用这些信息来设置游戏中的标志，以便在何时移动我们的飞船以及移动的方向。稍后，我们可以添加检测空格键按下的代码，以发射飞船的武器。

现在，我们将回到使用默认的 Emscripten shell。在本节的其余部分，我们将能够在 WebAssembly C 代码中完成所有操作。我将带你创建一个新的`keyboard.c`文件，从头开始处理键盘事件并在默认 shell 中打印到`textarea`。

首先创建一个新的`keyboard.c`文件，并在文件顶部添加以下`#include`指令：

```cpp
#include <SDL2/SDL.h>
#include <emscripten.h>
#include <stdio.h>
#include <stdbool.h>
```

之后，我们需要添加我们的全局`SDL`对象。前两个，`SDL_Window`和`SDL_Renderer`，现在应该看起来很熟悉。第三个，`SDL_Event`，是新的。我们将使用`SDL_PollEvent`在代码后期填充这个事件对象：

```cpp
SDL_Window *window;
SDL_Renderer *renderer;
SDL_Event event;
```

和这段代码的 JavaScript 版本一样，我们将使用全局变量来跟踪我们当前按下的箭头键。这些都将是布尔变量，如下面的代码所示：

```cpp
bool left_key_press = false;
bool right_key_press = false;
bool up_key_press = false;
bool down_key_press = false;
```

我们要定义的第一个函数是`input_loop`，但在我们定义该函数之前，我们需要声明`input_loop`将调用的两个函数，如下所示：

```cpp
void key_press();
void key_release();
```

这将允许我们在实际定义`input_loop`调用这些函数之前定义`input_loop`函数。`input_loop`函数将调用`SDL_PollEvent`来获取一个事件对象。然后我们可以查看事件的类型，如果是`SDL_KEYDOWN`或`SDL_KEYUP`事件，我们可以调用适当的函数来处理这些事件，如下所示：

```cpp
void input_loop() {
    if( SDL_PollEvent( &event ) ){
        if( event.type == SDL_KEYDOWN ){
            key_press();
        }
        else if( event.type == SDL_KEYUP ) {
            key_release();
        }
    }
}
```

我们将定义的第一个函数是`key_press()`函数。在这个函数内部，我们将在 switch 中查看键盘事件，并将值与不同的箭头键 SDLK 事件进行比较。如果键之前是弹起状态，它会打印出一个消息，让我们知道用户按下了哪个键。然后我们应该将`keypress`标志设置为`true`。下面的示例展示了`key_press()`函数的全部内容：

```cpp
void key_press() {
    switch( event.key.keysym.sym ){
        case SDLK_LEFT:
            if( !left_key_press ) {
                printf("left arrow key press\n");
            }
            left_key_press = true;
            break;

        case SDLK_RIGHT:
            if( !right_key_press ) {
                printf("right arrow key press\n");
            }
            right_key_press = true;
            break;

        case SDLK_UP:
            if( !up_key_press ) {
                printf("up arrow key press\n");
            }
            up_key_press = true;
            break;

        case SDLK_DOWN:
            if( !down_key_press ) {
                printf("down arrow key press\n");
            }
            down_key_press = true;
            break;

        default:
            printf("unknown key press\n");
            break;
    }
}
```

`key_press`函数内的第一行是一个 switch 语句，`switch(event.key.keysym.sym)`。这些都是结构中的结构。在`input_loop`函数内，我们调用了`SDL_PollEvent`，传递了一个`SDL_Event`结构的引用。这个结构包含了可能返回给我们的任何事件的事件数据，以及一个告诉我们这是什么类型事件的类型。如果类型是`SDL_KEYDOWN`或`SDL_KEYUP`，那意味着内部的`key`结构，它是一个`SDL_KeyboardEvent`类型的结构，被填充了。如果你想看`SDL_Event`结构的完整定义，你可以在 SDL 网站上找到它：[`wiki.libsdl.org/SDL_Event`](https://wiki.libsdl.org/SDL_Event)。在`SDL_Event`内部的 key 变量，你会注意到它是一个`SDL_KeyboardEvent`类型的结构。这个结构里有很多我们暂时不会用到的数据。它包括时间戳、这个键是否是重复按下的，或者这个键是被按下还是被释放；但是我们在 switch 语句中关注的是`keysym`变量，它是一个`SDL_Keysym`类型的结构。关于`SDL_KeyboardEvent`的更多信息，你可以在 SDL 网站上找到它的定义：[`wiki.libsdl.org/SDL_KeyboardEvent`](https://wiki.libsdl.org/SDL_KeyboardEvent)。`SDL_KeyboardEvent`结构中的`keysym`变量是你会在`sym`变量中找到`SDL_Keycode`的地方。这个键码是我们必须查看的，以确定玩家按下了哪个键。这就是为什么我们在`switch( event.key.keysym.sym )`周围构建了 switch 语句。SDL 键码的所有可能值的链接可以在这里找到：[`wiki.libsdl.org/SDL_Keycode`](https://wiki.libsdl.org/SDL_Keycode)。

我们在 switch 语句中的所有 case 语句看起来非常相似：如果按下给定的 SDLK 键码，我们会检查上一个周期是否按下了该键，并且仅在其未按下时打印出该值。然后我们将`keypress`标志设置为`true`。以下示例显示了我们检测左箭头键按下的代码：

```cpp
case SDLK_LEFT:
    if( !left_key_press ) {
        printf("left arrow key press\n");
    }
    left_key_press = true;
    break;
```

当事件类型为`SDL_KEYUP`时，我们的应用程序调用`key_release`函数。这与`key_down`函数非常相似。主要区别在于它是在查看用户是否按下按键，并且仅在状态变为未按下时打印消息。以下示例展示了该函数的全部内容：

```cpp
void key_release() {
    switch( event.key.keysym.sym ){

        case SDLK_LEFT:
            if( left_key_press ) {
                printf("left arrow key release\n");
            }
            left_key_press = false;
            break;

        case SDLK_RIGHT:
            if( right_key_press ) {
                printf("right arrow key release\n");
            }
            right_key_press = false;
            break;

        case SDLK_UP:
            if( up_key_press ) {
                printf("up arrow key release\n");
            }
            up_key_press = false;
            break;

        case SDLK_DOWN:
            if( down_key_press ) {
                printf("down arrow key release\n");
            }
            down_key_press = false;
            break;

        default:
            printf("unknown key release\n");
            break;
    }
}
```

我们的最后一个函数是`main`函数的新版本，在加载我们的`Module`时调用。我们仍然需要使用`emscripten_set_main_loop`来防止我们的代码占用 JavaScript 引擎。我们创建了一个我们之前定义的`input_loop`。它使用 SDL 来轮询键盘事件。但是，在此之前，我们仍然需要进行 SDL 初始化。我们使用 Emscripten 默认 shell，因此调用`SDL_CreateWindowAndRenderer`将设置我们的`canvas`元素的宽度和高度。我们不会在`input_loop`中渲染`canvas`元素，但是我们仍希望在此处进行初始化，因为在下一节中，我们将调整此代码以将太空船图像渲染到画布上，并使用按键移动它。以下代码显示了我们的`main`函数的新版本将是什么样子：

```cpp
int main() {
    SDL_Init( SDL_INIT_VIDEO );

    SDL_CreateWindowAndRenderer( 320, 200, 0, &window, &renderer );
    SDL_SetRenderDrawColor( renderer, 0, 0, 0, 255 );

    SDL_RenderClear( renderer );
    SDL_RenderPresent( renderer );

    emscripten_set_main_loop(input_loop, 0, 0);
    return 1;
}
```

现在我们已经将所有代码放入了`keyboard.c`文件中，我们可以使用以下`emcc`命令编译我们的`keyboard.c`文件：

```cpp
emcc keyboard.c -o keyboard.html -s USE_SDL=2
```

当您在浏览器中运行`keyboard.html`时，您会注意到按下箭头键会导致消息打印到 Emscripten 默认 shell 的文本区域。

考虑以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/41a1b5c7-89b9-4b88-ae20-16283cad1c8e.png)

图 5.2：keyboard.html 的屏幕截图

在接下来的部分，我们将学习如何使用键盘输入来移动精灵在画布上移动。

# 使用键盘输入移动精灵

现在我们知道如何获取键盘输入并在我们的 WebAssembly 模块中使用它，让我们想想如何将键盘输入用于在 HTML 画布上移动我们的太空船精灵。让我们从`Chapter04`目录中复制`sprite_move.c`到`Chapter05`目录中。这将给我们一个很好的起点。现在我们可以开始修改代码。我们需要在我们的`.c`文件开头添加一个`#include`。因为我们需要布尔变量，所以我们必须添加`#include <stdbool.h>`。现在我们的`.c`文件的新开头将如下所示：

```cpp
#include <SDL2/SDL.h>
#include <SDL2/SDL_image.h>
#include <emscripten.h>
#include <stdio.h>
#include <stdbool.h>
```

之后，所有的`#define`指令将保持与`sprite_move.c`文件中的内容相同，如下面的代码所示：

```cpp
#define SPRITE_FILE "sprites/Franchise1.png"
#define ANIM_FILE "sprites/Franchise%d.png"
#define FRAME_COUNT 4
```

`sprite_move.c`文件中有几个全局变量，我们将继续在`keyboard_move.c`中使用。不要删除这些变量中的任何一个；我们只会添加到它们中：

```cpp
int current_frame = 0;

Uint32 last_time;
Uint32 current_time;
Uint32 ms_per_frame = 100; // animate at 10 fps

SDL_Window *window;
SDL_Renderer *renderer;
SDL_Rect dest = {.x = 160, .y = 100, .w = 0, .h = 0 };

SDL_Texture *sprite_texture;
SDL_Texture *temp_texture;
SDL_Texture* anim[FRAME_COUNT];
```

现在我们需要从`keyboard.c`文件中引入一些变量，这些变量在上一节中使用过。我们需要`SDL_Event`全局变量，以便我们有东西传递给我们对`SDL_PollEvent`的调用，并且我们需要我们的布尔键按下标志，如下所示：

```cpp
SDL_Event event;

bool left_key_press = false;
bool right_key_press = false;
bool up_key_press = false;
bool down_key_press = false;
```

然后是函数声明，允许我们在定义`input_loop`函数之后定义`key_press`和`key_release`函数，如下例所示：

```cpp
void key_press();
void key_release();
```

接下来，我们将从我们的`keyboard.c`文件中引入`input_loop`函数。这是我们用来调用`SDL_PollEvent`的函数，并根据返回的事件类型调用`key_press`或`key_release`。这个函数与我们在`keyboard.c`中的版本保持不变，如下例所示：

```cpp
void input_loop() {
    if( SDL_PollEvent( &event ) ){
        if( event.type == SDL_KEYDOWN ){
            key_press();
        }
        else if( event.type == SDL_KEYUP ) {
            key_release();
        }
    }
}
```

`key_press`和`key_release`函数跟随`input_loop`函数，并且与`keyboard.c`版本保持不变。这些函数的主要目的是设置按键标志。`printf`语句现在是不必要的，但我们将它们留在那里。这对性能来说并不是一件好事，因为继续在我们的`textarea`中添加每次按键按下和释放的行最终会减慢我们的游戏速度，但是，此时，我觉得最好还是为了演示目的将这些语句留在那里：

```cpp
void key_press() {
    switch( event.key.keysym.sym ){

        case SDLK_LEFT:
            if( !left_key_press ) {
                printf("left arrow key press\n");
            }
            left_key_press = true;
            break;

        case SDLK_RIGHT:
            if( !right_key_press ) {
                printf("right arrow key press\n");
            }
            right_key_press = true;
            break;

        case SDLK_UP:
            if( !up_key_press ) {
                printf("up arrow key press\n");
            }
            up_key_press = true;
            break;

        case SDLK_DOWN:
            if( !down_key_press ) {
                printf("down arrow key press\n");
            }
            down_key_press = true;
            break;

        default:
            printf("unknown key press\n");
            break;
    }
}

void key_release() {
    switch( event.key.keysym.sym ){

        case SDLK_LEFT:
            if( left_key_press ) {
                printf("left arrow key release\n");
            }
            left_key_press = false;
            break;

        case SDLK_RIGHT:
            if( right_key_press ) {
                printf("right arrow key release\n");
            }
            right_key_press = false;
            break;

        case SDLK_UP:
            if( up_key_press ) {
                printf("up arrow key release\n");
            }
            up_key_press = false;
            break;

        case SDLK_DOWN:
            if( down_key_press ) {
                printf("down arrow key release\n");
            }
            down_key_press = false;
            break;

        default:
            printf("unknown key release\n");
            break;
    }
}
```

`keyboard_move.c`文件中的下一个函数将是`show_animation`。这个函数需要与`sprite_move.c`中的版本有显著的改变，以便玩家可以控制飞船并在画布上移动它。在我们逐步讲解之前，以下示例展示了新函数的全部内容：

```cpp
void show_animation() {
    input_loop();

    current_time = SDL_GetTicks();
    int ms = current_time - last_time;

    if( ms >= ms_per_frame) {
        ++current_frame;
        last_time = current_time;
    }

    if( current_frame >= FRAME_COUNT ) {
        current_frame = 0;
    }

    SDL_RenderClear( renderer );
    temp_texture = anim[current_frame];

    if( up_key_press ) {
        dest.y--;

        if( dest.y < -16 ) {
            dest.y = 200;
        }
    }

    if( down_key_press ) {
        dest.y++;

        if( dest.y > 200 ) {
            dest.y = -16;
        }
    }

    if( left_key_press ) {
        dest.x--;

        if( dest.x < -16 ) {
            dest.x = 320;
        }
    }

    if( right_key_press ) {
        dest.x++;

        if( dest.x > 320 ) {
            dest.x = -16;
        }
    }

    SDL_RenderCopy( renderer, temp_texture, NULL, &dest );
    SDL_RenderPresent( renderer );
}
```

我们将`show_animation`中的第一行添加到这个函数的新版本中。调用`input_loop`用于在每帧设置按键按下标志。在调用`input_loop`之后，有一大块代码，我们没有从`sprite_move.c`文件中更改，如下例所示：

```cpp
current_time = SDL_GetTicks();
int ms = current_time - last_time;

if( ms >= ms_per_frame) {
    ++current_frame;
    last_time = current_time;
}

if( current_frame >= FRAME_COUNT ) {
    current_frame = 0;
}

SDL_RenderClear( renderer );
temp_texture = anim[current_frame];
```

这段代码调用`SDL_GetTicks()`来获取当前时间，然后从上一次当前帧更改的时间中减去当前时间，以获取自上次帧更改以来的毫秒数。如果自上次帧更改以来的毫秒数大于我们希望停留在任何给定帧上的毫秒数，我们需要推进当前帧。一旦我们弄清楚了是否推进了当前帧，我们需要确保当前帧不超过我们的帧数。如果超过了，我们需要将其重置为`0`。之后，我们需要清除我们的渲染器，并将我们使用的纹理设置为与当前帧对应的动画数组中的纹理。

在`sprite_move.c`中，我们使用以下几行代码将飞船的`y`坐标每帧向上移动一个像素：

```cpp
dest.y--;

if( dest.y < -16 ) {
    dest.y = 200;
}
```

在新的键盘应用程序中，我们只希望在玩家按下上箭头键时改变我们的`y`坐标。为此，我们必须将改变`y`坐标的代码放在一个检查`up_key_press`标志的`if`块中。以下是该代码的新版本：

```cpp
if( up_key_press ) {
    dest.y--;

    if( dest.y < -16 ) {
        dest.y = 200;
    }
}
```

我们还需要添加代码，当玩家按下其他箭头键时移动飞船。根据玩家当前按下的键，以下代码将使飞船向下、向左或向右移动：

```cpp
if( down_key_press ) {
    dest.y++;

    if( dest.y > 200 ) {
        dest.y = -16;
    }
}

if( left_key_press ) {
    dest.x--;

    if( dest.x < -16 ) {
        dest.x = 320;
    }
}

if( right_key_press ) {
    dest.x++;

    if( dest.x > 320 ) {
        dest.x = -16;
    }
}
```

最后，我们必须渲染纹理并呈现它，如下所示：

```cpp
SDL_RenderCopy( renderer, temp_texture, NULL, &dest );
SDL_RenderPresent( renderer );
```

`main`函数不会从`sprite_move.c`中的版本改变，因为初始化没有改变。以下代码显示了`keyboard_move.c`中的`main`函数：

```cpp
int main() {
    char explosion_file_string[40];

    SDL_Init( SDL_INIT_VIDEO );
    SDL_CreateWindowAndRenderer( 320, 200, 0, &window, &renderer );
    SDL_SetRenderDrawColor( renderer, 0, 0, 0, 255 );
    SDL_RenderClear( renderer );

    SDL_Surface *temp_surface = IMG_Load( SPRITE_FILE );

    if( !temp_surface ) {
        printf("failed to load image: %s\n", IMG_GetError() );
        return 0;
    }

    sprite_texture = SDL_CreateTextureFromSurface( renderer, temp_surface );

    SDL_FreeSurface( temp_surface );

    for( int i = 1; i <= FRAME_COUNT; i++ ) {
        sprintf( explosion_file_string, ANIM_FILE, i );
        SDL_Surface *temp_surface = IMG_Load( explosion_file_string );

        if( !temp_surface ) {
            printf("failed to load image: %s\n", IMG_GetError() );
            return 0;
        }

        temp_texture = SDL_CreateTextureFromSurface( renderer, temp_surface );
        anim[i-1] = temp_texture;
        SDL_FreeSurface( temp_surface );
    }

    SDL_QueryTexture( sprite_texture,
                        NULL, NULL,
                        &dest.w, &dest.h ); // query the width and height

    dest.x -= dest.w / 2;
    dest.y -= dest.h / 2;

    SDL_RenderCopy( renderer, sprite_texture, NULL, &dest );
    SDL_RenderPresent( renderer );

    last_time = SDL_GetTicks();
    emscripten_set_main_loop(show_animation, 0, 0);
    return 1;
}
```

正如我之前所说，这段代码是我们在第四章中编写的最后一个应用程序的结合，*使用 SDL 在 WebAssembly 中进行精灵动画*，以及我们在*将 SDL 键盘输入添加到 WebAssembly*部分编写的代码，我们在那里从键盘接收输入并使用`printf`语句记录我们的按键。我们保留了`input_loop`函数，并在`show_animation`函数的开头添加了对它的调用。在`show_animation`内部，我们不再在每一帧移动飞船一像素，而是只有在按下上箭头键时才移动飞船。同样，当用户按下左箭头键时，我们向左移动飞船，当按下右箭头键时，我们向右移动飞船，当用户按下下箭头键时，我们向下移动飞船。

现在我们有了新的`keyboard_move.c`文件，让我们编译它并尝试一下我们的新移动飞船。运行以下`emcc`命令来编译代码：

```cpp
emcc keyboard_move.c -o keyboard_move.html --preload-file sprites -s USE_SDL=2 -s USE_SDL_IMAGE=2 -s SDL2_IMAGE_FORMATS=["png"]
```

我们需要添加`--preload-file sprites`标志，以指示我们希望在虚拟文件系统中包含 sprites 文件夹。我们还需要添加`-s USE_SDL=2`和`-s USE_SDL_IMAGE=2 -s SDL2_IMAGE_FORMATS=["png"]`标志，以允许我们从虚拟文件系统加载`.png`文件。一旦你编译了`keyboard_move.html`，将其加载到浏览器中，并使用箭头键在画布上移动飞船。请参阅以下截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/cb33d02f-3e01-4378-a984-a4a408df6e4b.png)

图 5.3：keyboard_move.html 的键盘移动截图

# 摘要

在本章中，我们学习了如何获取用于 WebAssembly 的键盘输入。有两种主要方法。我们可以在 JavaScript 端接收键盘输入，并通过使用`Module.cwrap`制作的包装器与 WebAssembly 进行通信，或者直接通过`Module.ccall`调用 WebAssembly 函数。在 WebAssembly 中接受键盘输入的另一种方法是使用 SDL 键盘输入事件。当我们使用这种方法时，我们可以使用默认的 Emscripten shell。使用 SDL 事件的这种第二种方法将是本书其余部分中我们首选的方法。

在下一章中，我们将更多地了解游戏循环以及我们将如何在我们的游戏中使用它，以及一般的游戏。


# 第六章：游戏对象和游戏循环

在本章中，我们将开始构建游戏的框架。所有游戏都有**游戏对象**和**游戏循环**。游戏循环存在于每个游戏中。一些工具，比如 Unity，尽最大努力抽象出游戏循环，以便开发人员不一定需要知道它的存在，但即使在这些情况下，它仍然存在。所有游戏都必须对操作系统或硬件的渲染能力进行一定的控制，并在游戏运行时向屏幕绘制图像。游戏的所有工作都在一个**大循环**中完成。游戏对象可以是**面向对象编程**（**OOP**）语言（如 C++）中的类的实例，也可以是过程式语言（如 C）中的松散变量或结构的集合。在本章中，我们将学习如何设计游戏循环，并从 C++编译成**WebAssembly**中学习我们游戏对象的早期版本。

您需要在构建中包含几个图像才能使此项目工作。确保您包含了项目的 GitHub 存储库中的`/Chapter06-game-object/sprites/`文件夹。如果您还没有下载 GitHub 项目，可以在这里在线获取：[`github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly`](https://github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly)。

在本章中，我们将涵盖以下主题：

+   游戏循环

+   对象池

+   玩家游戏对象

+   敌人游戏对象

+   抛射物

# 理解游戏循环

游戏设计中的一个关键概念是游戏循环。在任何游戏中，代码必须一遍又一遍地运行，执行一系列任务，如输入、人工智能、物理和渲染。游戏循环可能看起来像这样：

```cpp
while(loop_forever) {
    get_user_input();
    move_game_objects();
    collision_detection();
    render_game_objects();
    play_audio();
}
```

一个针对几乎任何平台的 SDL/C++游戏会有一个`while`循环，可能位于 C++代码的`main`函数中，只有当玩家退出游戏时才会退出。WebAssembly 与您的 Web 浏览器内部的 JavaScript 引擎共享运行时。JavaScript 引擎在单个线程上运行，Emscripten 使用 JavaScript 的**glue code**将您在 WebAssembly 中的 SDL 内部所做的工作渲染到 HTML 画布元素上。因此，我们需要使用一个特定于 Emscripten 的代码片段来实现我们的游戏循环：

```cpp
emscripten_set_main_loop(game_loop, 0, 0);
```

在接下来的几章中，我们将向我们的游戏中添加一些这些函数：

+   游戏对象管理

+   游戏对象之间的碰撞检测

+   粒子系统

+   使用**有限状态机**（**FSM**）的敌人飞船 AI

+   用于跟踪玩家的游戏摄像机

+   播放音频和音效

+   游戏物理

+   用户界面

这些将是从游戏循环中调用的函数。

# 编写基本游戏循环

在某种程度上，我们已经有了一个简单的游戏循环，尽管我们没有显式地创建一个名为`game_loop`的函数。我们将修改我们的代码，以便有一个更明确的游戏循环，将分离`input`、`move`和`render`函数。此时，我们的`main`函数变成了一个初始化函数，最后使用 Emscripten 来设置游戏循环。这个新应用的代码比之前的应用要大。让我们首先以高层次的方式浏览代码，介绍每个部分。然后我们将详细介绍代码的每个部分。

我们从`#include`和`#define`预处理宏开始编写代码：

```cpp
#include <SDL2/SDL.h>
#include <SDL2/SDL_image.h>
#include <emscripten.h>
#include <stdio.h>
#include <stdbool.h>
#include <math.h>

#define SPRITE_FILE "sprites/Franchise.png"
#define PI 3.14159
#define TWO_PI 6.28318
#define MAX_VELOCITY 2.0
```

在预处理宏之后，我们有一些全局时间变量：

```cpp
Uint32 last_time;
Uint32 last_frame_time;
Uint32 current_time;
```

然后我们将定义几个与 SDL 相关的全局变量：

```cpp
SDL_Window *window;
SDL_Renderer *renderer;
SDL_Rect dest = {.x = 160, .y = 100, .w = 16, .h = 16 };
SDL_Texture *sprite_texture;
SDL_Event event;
```

在我们的 SDL 全局变量之后，我们有一个键盘标志块：

```cpp
bool left_key_down = false;
bool right_key_down = false;
bool up_key_down = false;
bool down_key_down = false;
```

最后的全局变量跟踪玩家数据：

```cpp
float player_x = 160.0;
float player_y = 100.0;
float player_rotation = PI;
float player_dx = 0.0;
float player_dy = 1.0;
float player_vx = 0.0;
float player_vy = 0.0;
float delta_time = 0.0;
```

现在我们已经定义了所有的全局变量，我们需要两个函数来使玩家的飞船向左和向右旋转：

```cpp

void rotate_left() {
    player_rotation -= delta_time;
    if( player_rotation < 0.0 ) {
        player_rotation += TWO_PI;
    }
    player_dx = sin(player_rotation);
    player_dy = -cos(player_rotation);
}

void rotate_right() {
    player_rotation += delta_time;
    if( player_rotation >= TWO_PI ) {
        player_rotation -= TWO_PI;
    }
    player_dx = sin(player_rotation);
    player_dy = -cos(player_rotation);
}
```

然后我们有三个与玩家飞船相关的移动函数。我们使用它们来加速和减速我们的飞船，并限制我们飞船的速度：

```cpp

void accelerate() {
    player_vx += player_dx * delta_time;
    player_vy += player_dy * delta_time;
}

void decelerate() {
    player_vx -= (player_dx * delta_time) / 2.0;
    player_vy -= (player_dy * delta_time) / 2.0;
}

void cap_velocity() {
    float vel = sqrt( player_vx * player_vx + player_vy * player_vy );
    if( vel > MAX_VELOCITY ) {
        player_vx /= vel;
        player_vy /= vel;
        player_vx *= MAX_VELOCITY;
        player_vy *= MAX_VELOCITY;
    }
}
```

`move`函数执行游戏对象的高级移动：

```cpp

void move() {
    current_time = SDL_GetTicks();
    delta_time = (float)(current_time - last_time) / 1000.0;
    last_time = current_time;

    if( left_key_down ) {
        rotate_left();
    }
    if( right_key_down ) {
        rotate_right();
    }
    if( up_key_down ) {
        accelerate();
    }
    if( down_key_down ) {
        decelerate();
    }
    cap_velocity();

    player_x += player_vx;

    if( player_x > 320 ) {
        player_x = -16;
    }
    else if( player_x < -16 ) {
        player_x = 320;
    }

    player_y += player_vy;

    if( player_y > 200 ) {
        player_y = -16;
    }
    else if( player_y < -16 ) {
        player_y = 200;
    }
} 
```

`input`函数确定键盘输入状态并设置我们的全局键盘标志：

```cpp

void input() {
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
                    default:
                        break;
                }
                break;
            case SDL_KEYUP:
                switch( event.key.keysym.sym ){
                    case SDLK_LEFT:
                        left_key_down = false;
                        break;
                    case SDLK_RIGHT:
                        right_key_down = false;
                        break;
                    case SDLK_UP:
                        up_key_down = false;
                        break;
                    case SDLK_DOWN:
                        down_key_down = false;
                        break;
                    default:
                        break;
                }
                break;

            default:
                break;
        }
    }
}
```

`render`函数将玩家的精灵绘制到画布上：

```cpp
void render() {
    SDL_RenderClear( renderer );

    dest.x = player_x;
    dest.y = player_y;

    float degrees = (player_rotation / PI) * 180.0;
    SDL_RenderCopyEx( renderer, sprite_texture,
                        NULL, &dest,
    degrees, NULL, SDL_FLIP_NONE );

    SDL_RenderPresent( renderer );
 }
```

`game_loop`函数在每一帧中运行我们所有的高级游戏对象：

```cpp
void game_loop() {
    input();
    move();
    render();
}
```

与往常一样，`main`函数执行所有初始化：

```cpp
int main() {
    char explosion_file_string[40];
    SDL_Init( SDL_INIT_VIDEO );
    SDL_CreateWindowAndRenderer( 320, 200, 0, &window, &renderer );
    SDL_SetRenderDrawColor( renderer, 0, 0, 0, 255 );
    SDL_RenderClear( renderer );
    SDL_Surface *temp_surface = IMG_Load( SPRITE_FILE );

    if( !temp_surface ) {
        printf("failed to load image: %s\n", IMG_GetError() );
        return 0;
    }

    sprite_texture = SDL_CreateTextureFromSurface( renderer, 
                                                  temp_surface );
    SDL_FreeSurface( temp_surface );
    last_frame_time = last_time = SDL_GetTicks();

    emscripten_set_main_loop(game_loop, 0, 0);
    return 1;
}
```

在前面的代码中，您可能已经注意到我们添加了大量全局变量来定义特定于玩家的值：

```cpp
float player_x = 160.0;
float player_y = 100.0;
float player_rotation = PI;
float player_dx = 0.0;
float player_dy = 1.0;
float player_vx = 0.0;
float player_vy = 0.0;
```

在“游戏对象”部分，我们将开始创建游戏对象并将这些值从全局定义移动到对象中，但是目前，将它们作为全局变量将起作用。我们正在添加移动玩家飞船的能力，这与经典街机游戏“Asteroids”类似。在我们游戏的最终版本中，我们将有两艘太空飞船进行决斗。为此，我们需要跟踪飞船的“x”和“y”坐标以及飞船的旋转；`player_dx`和`player_dy`组成了我们太空飞船的归一化方向向量。

`player_vx`和`player_vy`变量分别是玩家当前的`x`和`y`速度。

我们不再让左右键在按住时移动飞船向左或向右，而是让这些键将飞船向左或向右转动。为此，我们的输入函数将调用`rotate_left`和`rotate_right`函数：

```cpp
void rotate_left() {
    player_rotation -= delta_time;
    if( player_rotation < 0.0 ) {
        player_rotation += TWO_PI;
    }
    player_dx = sin(player_rotation);
    player_dy = -cos(player_rotation);
}

void rotate_right() {
    player_rotation += delta_time;
    if( player_rotation >= TWO_PI ) {
         player_rotation -= TWO_PI;
    }
    player_dx = sin(player_rotation);
    player_dy = -cos(player_rotation);
}
```

如果玩家正在向左转，我们会从玩家旋转中减去`delta_time`变量，这是自上一帧渲染以来的秒数。 `player_rotation`变量是玩家的弧度旋转，其中 180 度=π（3.14159…）。这意味着玩家可以通过按住左或右箭头约三秒钟来旋转 180 度。如果玩家的旋转低于 0 或玩家的旋转超过 2π（360 度），我们还必须纠正我们的旋转。如果您不熟悉弧度，它是一种替代的角度测量系统，其中一个圆中有 360 度。使用弧度，您可以考虑您需要绕单位圆的周长走多远才能到达该角度。半径为 1 的圆称为**单位圆**。

单位圆在左侧：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/8a524c84-989f-42ee-a3bb-07d3d95fa6ef.png)

单位圆和半径为 2 的圆

圆的直径公式是 2πr（在我们的代码中是`2 * PI * radius`）。因此，弧度中的 2π等同于 360 度。大多数游戏引擎和数学库在旋转精灵时使用弧度而不是度，但由于某种原因 SDL 在旋转精灵时使用度，因此我们需要在渲染游戏对象时将我们的弧度旋转回度（呸！）。

只是为了确保每个人都在跟着我，我们的代码中，`PI`宏保存了一个近似值，即定义为圆的直径与其周长的比值的π。 π的典型近似值为 3.14，尽管在我们的代码中，我们将π近似为 3.14159。

如果玩家按下键盘上的上下键，我们还需要加速或减速飞船。为此，我们将创建`accelerate`和`decelerate`函数，当玩家按住上下键时调用这些函数：

```cpp
void accelerate() {
    player_vx += player_dx * delta_time;
    player_vy += player_dy * delta_time;
}

void decelerate() {
    player_vx -= (player_dx * delta_time) / 2.0;
    player_vy -= (player_dy * delta_time) / 2.0;
}
```

这两个函数都使用了使用我们的旋转函数中的`sin`和`-cos`计算出的`player_dx`和`player_dy`变量，并使用这些值来添加到存储在`player_vx`和`player_vy`变量中的玩家的*x*和*y*速度。我们将该值乘以`delta_time`，这将使我们的加速度设置为每秒 1 像素。我们的减速函数将该值除以 2，这将使我们的减速率设置为每秒 0.5 像素。

在定义了“加速”和“减速”函数之后，我们需要创建一个函数，将我们的飞船的`x`和`y`速度限制为每秒 2.0 像素：

```cpp
void cap_velocity() {
    float vel = sqrt( player_vx * player_vx + player_vy * player_vy );

    if( vel > MAX_VELOCITY ) {
        player_vx /= vel;
        player_vy /= vel;
        player_vx *= MAX_VELOCITY;
        player_vy *= MAX_VELOCITY;
     }
}
```

这不是定义这个函数的最有效方式，但这是最容易理解的方式。第一行确定了我们速度向量的大小。如果你不知道这意味着什么，让我更好地解释一下。我们有一个沿着*x*轴的速度。我们也有一个沿着*y*轴的速度。我们想要限制总速度。如果我们分别限制`x`和`y`的速度，我们将能够通过对角线行进更快。为了计算我们的总速度，我们需要使用毕达哥拉斯定理（你还记得高中的三角学吗？）。如果你不记得了，当你有一个直角三角形时，要计算它的斜边，你需要取另外两条边的平方和的平方根（记得`A² + B² = C²`吗？）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/58d0adaf-31a8-45fa-85aa-2ef16b155019.png)[使用毕达哥拉斯定理来确定使用 x 和 y 速度的速度大小]

因此，为了计算我们的总速度，我们需要对`x`速度进行平方，对`y`速度进行平方，然后将它们加在一起，然后取平方根。在这一点上，我们将我们的速度与`MAX_VELOCITY`值进行比较，我们已经将其定义为`2.0`。如果当前速度大于这个最大速度，我们需要调整我们的`x`和`y`速度，使其达到`2`的值。我们通过将`x`和`y`速度都除以总速度，然后乘以`MAX_VELOCITY`来实现这一点。

最终我们需要编写一个`move`函数，它将移动所有游戏对象，但目前我们只会移动玩家的太空飞船：

```cpp
void move() {
    current_time = SDL_GetTicks();
    delta_time = (float)(current_time - last_time) / 1000.0;
    last_time = current_time;

    if( left_key_down ) {
        rotate_left();
    }

    if( right_key_down ) {
        rotate_right();
    }

    if( up_key_down ) {
        accelerate();
    }

    if( down_key_down ) {
        decelerate();
    }

    cap_velocity();
    player_x += player_vx;

    if( player_x > 320 ) {
         player_x = -16;
     }
    else if( player_x < -16 ) {
        player_x = 320;
    }
    player_y += player_vy;

    if( player_y > 200 ) {
        player_y = -16;
    }
    else if( player_y < -16 ) {
        player_y = 200;
    }
}
```

我们需要做的第一件事是获取这一帧的当前时间，然后将其与我们之前的帧时间结合起来计算`delta_time`。`delta_time`变量是自上一帧时间以来的时间量（以秒为单位）。我们需要将许多移动和动画与这个值联系起来，以获得一个与任何给定计算机的帧速率无关的一致的游戏速度。之后，我们需要根据我们在`input`函数中设置的标志来旋转、加速或减速我们的太空飞船。然后我们限制我们的速度，并使用`x`和`y`值来修改玩家太空飞船的*x*和*y*坐标。

在`move`函数中，我们使用了一系列标志，告诉我们当前是否按住了键盘上的特定键。为了设置这些标志，我们需要一个`input`函数，它使用`SDL_PollEvent`来查找键盘事件，并相应地设置标志：

```cpp

void input() {
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
                    default:
                        break;
                }
                break;
            case SDL_KEYUP:
                switch( event.key.keysym.sym ){
                    case SDLK_LEFT:
                        left_key_down = false;
                        break;
                    case SDLK_RIGHT:
                        right_key_down = false;
                        break;
                    case SDLK_UP:
                        up_key_down = false;
                        break;
                    case SDLK_DOWN:
                        down_key_down = false;
                        break;
                    default:
                        break;
                }
                break;
            default:
                break;
        }
    }
}
```

这个函数包括一些`switch`语句，用于查找箭头键的按下和释放。如果按下箭头键之一，我们将相应的标志设置为`true`；如果释放了一个键，我们将该标志设置为`false`。

接下来，我们定义`render`函数。这个函数目前渲染了我们的太空飞船精灵，并最终会渲染所有精灵到 HTML 画布上：

```cpp
void render() {
    SDL_RenderClear( renderer );
    dest.x = player_x;
    dest.y = player_y;
    float degrees = (player_rotation / PI) * 180.0;
    SDL_RenderCopyEx( renderer, sprite_texture,
                        NULL, &dest,
                        degrees, NULL, SDL_FLIP_NONE );
    SDL_RenderPresent( renderer );
}
```

这个函数清除 HTML 画布，将目的地`x`和`y`值设置为`player_x`和`player_y`，计算玩家的旋转角度，然后将该精灵渲染到画布上。我们用一个调用`SDL_RenderCopyEx`替换了之前的`SDL_RenderCopy`调用。这个新函数允许我们传入一个值，旋转我们的太空飞船的精灵。

在我们定义了`render`函数之后，我们有了新的`game_loop`函数：

```cpp
void game_loop() {
    input();
    move();
    render();
}
```

这个函数将被`emscripten_set_main_loop`从我们的`main`函数中调用。这个函数在渲染的每一帧都会运行，并负责管理游戏中发生的所有活动。它目前调用我们在游戏代码中之前定义的`input`、`move`和`render`函数，将来还会调用我们的 AI 代码、音效、物理代码等。

# 编译 gameloop.html

现在我们已经编写了我们的代码，可以继续编译我们的游戏循环应用程序。在运行此命令之前，我想重申，您需要从 GitHub（[`github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly`](https://github.com/PacktPublishing/Hands-On-Game-Development-with-WebAssembly)）下载项目，因为您需要在`/Chapter06-game-loop/sprites`文件夹中找到 PNG 文件才能构建此项目。

一旦您正确设置了文件夹，使用以下命令编译应用程序：

```cpp
emcc game_loop.c -o gameloop.html  --preload-file sprites -s NO_EXIT_RUNTIME=1 -s USE_SDL_IMAGE=2 -s SDL2_IMAGE_FORMATS=["png"] -s EXTRA_EXPORTED_RUNTIME_METHODS="['cwrap', 'ccall']" -s USE_SDL=2
```

使用 Web 服务器提供您编译的目录，或者使用 emrun 构建和运行它，加载到 Web 浏览器中时应该是这样的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/13918915-c0b6-448b-b3be-996e683d26a9.png)

游戏循环的屏幕截图

重要的是要记住，必须使用 WebAssembly 应用程序使用 Web 服务器或`emrun`运行。如果您想使用`emrun`运行 WebAssembly 应用程序，必须使用`--emrun`标志进行编译。Web 浏览器需要一个 Web 服务器来流式传输 WebAssembly 模块。如果您尝试直接从硬盘驱动器在浏览器中打开使用 WebAssembly 的 HTML 页面，那么 WebAssembly 模块将无法加载。

应用程序编译完成后，您应该能够使用箭头键在画布上移动太空飞船。现在我们有了一个基本的游戏循环，在下一节中，我们将向我们的应用程序添加一些游戏对象，使其更像一个游戏。

# 游戏对象

到目前为止，我们的方法完全是过程化的，并且编码方式可以用 C 而不是 C++编写。开发人员长期以来一直在用 C 甚至汇编语言编写游戏，因此从代码管理的角度来看，面向对象的游戏设计并不是绝对必要的，但是从代码管理的角度来看，面向对象编程是设计和编写游戏的一种很好的方式。游戏对象可以帮助我们通过对象池管理我们分配的内存。此时，开始将程序分解成多个文件也是有意义的。我的方法是有一个单独的`.hpp`文件来定义所有的游戏对象，以及一个`.cpp`文件来定义每个对象。

# 玩家的太空飞船游戏对象

到目前为止，我们一直在全局变量中保存跟踪玩家飞船的所有值。从组织的角度来看，这并不理想。我们将创建的第一个游戏对象将是玩家的飞船对象。我们将从一个基本类开始，稍后再向我们的代码中添加更多面向对象的特性。

这是我们新的头文件`game.hpp`的代码：

```cpp
#ifndef __GAME_H__
#define __GAME_H__#include <SDL2/SDL.h>
#include <SDL2/SDL_image.h>
#include <emscripten.h>
#include <stdio.h>
#include <stdbool.h>
#include <math.h>
#include <string>
#include <vector>

#define SPRITE_FILE "sprites/Franchise.png"
#define MAX_VELOCITY 2.0
#define PI 3.14159
#define TWO_PI 6.28318

extern Uint32 last_time;
extern Uint32 last_frame_time;
extern Uint32 current_time;
extern SDL_Window *window;
extern SDL_Renderer *renderer;
extern SDL_Rect dest;
extern SDL_Texture *sprite_texture;
extern SDL_Event event;
extern bool left_key_down;
extern bool right_key_down;
extern bool up_key_down;
extern bool down_key_down;
extern bool space_key_down;
extern float delta_time;
extern int diff_time;

class PlayerShip {
    public:
        float m_X;
        float m_Y;
        float m_Rotation;
        float m_DX;
        float m_DY;
        float m_VX;
        float m_VY;

        PlayerShip();
        void RotateLeft();
        void RotateRight();
        void Accelerate();
        void Decelerate();
        void CapVelocity();
        void Move();
        void Render();
};

extern PlayerShip player;
#endif
```

我们所有的 CPP 文件都将包括这个`game.hpp`头文件。这个文件的前几行是为了确保我们不会多次包含这个文件。然后我们定义了我们在旧的 C 文件中定义的所有全局变量：

```cpp
extern Uint32 last_time;
extern Uint32 last_frame_time;
extern Uint32 current_time;
extern SDL_Window *window;
extern SDL_Renderer *renderer;
extern SDL_Rect dest;
extern SDL_Texture *sprite_texture;
extern SDL_Event event;
extern bool left_key_down;
extern bool right_key_down;
extern bool up_key_down;
extern bool down_key_down;
extern float delta_time;
```

在头文件中，我们不会在堆上分配空间。在全局变量定义之前使用`extern`关键字告诉编译器我们在一个`.cpp`文件中声明了全局变量。现在，我们仍然有很多全局变量。随着我们在本章对代码进行修改，我们将减少这些全局变量的数量。

如果这是生产代码，将所有这些值移到类中是有意义的，但是，目前，我们只创建了一个`PlayerShip`对象。我们还为`PlayerShip`定义了我们的类定义。开发人员通常在头文件中创建类定义。

在定义了所有全局变量之后，我们将需要我们的类定义。

这是我们的`PlayerShip`类的定义：

```cpp
class PlayerShip {
    public:
        float m_X;
        float m_Y;
        float m_Rotation;
        float m_DX;
        float m_DY;
        float m_VX;
        float m_VY;

        PlayerShip();
        void RotateLeft();
        void RotateRight();
        void Accelerate();
        void Decelerate();
        void CapVelocity();
        void Move();
        void Render();
 };

extern PlayerShip player;
```

在本书中，我们将声明所有的属性为`public`。这意味着我们的代码可以从任何地方访问它们，而不仅仅是从这个函数内部。如果你正在与多个开发人员一起开发项目，这通常不被认为是一个好的做法。如果你不希望另一个开发人员直接修改一些只有类中的函数才能修改的特定属性，比如`m_DX`和`m_DY`，那么阻止其他类能够直接修改一些属性是一个好主意。然而，出于演示目的，将我们类中的所有内容定义为`public`将简化我们的设计。

在定义了我们的属性之后，我们有一系列函数，一旦定义，就会与这个类相关联。第一个函数`PlayerShip()`与我们的类同名，这使它成为构造函数，也就是说，当我们的应用程序创建`PlayerShip`类型的对象时，默认情况下会调用该函数。如果我们希望，我们可以定义一个析构函数，当对象被销毁时运行，通过将其命名为`~PlayerShip()`。我们目前不需要该对象的析构函数，因此我们不会在这里定义它，这意味着我们将依赖 C++为这个类创建一个*默认析构函数*。

我们在这个类中定义的所有其他函数对应于我们在游戏的先前 C 版本中创建的函数。将所有这些函数移动到一个类中可以更好地组织我们的代码。请注意，在我们的类定义之后，我们创建了另一个全局变量，一个名为`player`的`PlayerShip`。编译器在包含我们的`game.hpp`文件的所有`.cpp`文件中共享这个玩家对象。

# 对象池

我们已经定义了我们的第一个游戏对象，代表了我们玩家的太空飞船，但我们所能做的就是在游戏屏幕上飞行。我们需要允许玩家发射抛射物。如果每次玩家发射抛射物时都创建一个新的抛射物对象，我们很快就会填满 WASM 模块的内存。我们需要做的是创建所谓的**对象池**。对象池用于创建具有固定寿命的对象。我们的抛射物只需要存活足够长的时间，要么击中目标，要么在消失之前行进一定距离。如果我们创建一定数量的抛射物，略多于我们一次在屏幕上需要的数量，我们可以将这些对象保留在池中，处于活动或非活动状态。当我们需要发射新的抛射物时，我们扫描我们的对象池，找到一个非活动的对象，然后激活它并将其放置在发射点。这样，我们就不会不断地分配和释放内存来创建我们的抛射物。

让我们回到我们的`game.hpp`文件，在`#endif`宏之前添加一些类定义。

```cpp
class Projectile {
    public:
        const char* c_SpriteFile = "sprites/Projectile.png";
        const int c_Width = 8;
        const int c_Height = 8;
        SDL_Texture *m_SpriteTexture;
        bool m_Active;
        const float c_Velocity = 6.0;
        const float c_AliveTime = 2000;
        float m_TTL;
        float m_X;
        float m_Y;
        float m_VX;
        float m_VY;

        Projectile();
        void Move();
        void Render();
        void Launch(float x, float y, float dx, float dy);
};

class ProjectilePool {
    public:
        std::vector<Projectile*> m_ProjectileList;
        ProjectilePool();
        ~ProjectilePool();
        void MoveProjectiles();
        void RenderProjectiles();
        Projectile* GetFreeProjectile();
};

extern ProjectilePool* projectile_pool; 
```

因此，我们已经在`game.hpp`文件中定义了所有的类。现在，我们有三个类：`PlayerShip`，`Projectile`和`ProjectilePool`。

`PlayerShip`类之前就存在，但我们正在为该类添加一些额外的功能，以允许我们发射抛射物。为了允许这种新功能，我们正在向我们的类定义中添加一些新的公共属性：

```cpp
public:
    const char* c_SpriteFile = "sprites/Franchise.png";
    const Uint32 c_MinLaunchTime = 300;
    const int c_Width = 16;
    const int c_Height = 16;
    Uint32 m_LastLaunchTime;
    SDL_Texture *m_SpriteTexture;
```

我们将一些在`#define`宏中的值直接移到了类中。`c_SpriteFile`常量是我们将加载以渲染玩家太空飞船精灵的 PNG 文件的名称。`c_MinLaunchTime`常量是两次发射抛射物之间的最小时间间隔（以毫秒为单位）。我们还用`c_Width`和`c_Height`常量定义了精灵的宽度和高度。这样，我们可以为不同的对象类型设置不同的值。`m_LastLaunchTime`属性跟踪了最近的抛射物发射时间（以毫秒为单位）。精灵纹理，之前是一个全局变量，将移动到玩家飞船类的属性中。

在对`PlayerShip`类定义进行修改后，我们必须为两个新类添加类定义。这两个类中的第一个是`Projectile`类：

```cpp
class Projectile {
    public:
        const char* c_SpriteFile = "sprites/Projectile.png";
        const int c_Width = 8;
        const int c_Height = 8;
        const float c_Velocity = 6.0;
        const float c_AliveTime = 2000;

        SDL_Texture *m_SpriteTexture;
        bool m_Active;
        float m_TTL;
        float m_X;
        float m_Y;
        float m_VX;
        float m_VY;

        Projectile();
        void Move();
        void Render();
        void Launch(float x, float y, float dx, float dy);
};
```

这个类代表了玩家将射出的 projectile 游戏对象，以及后来的敌人飞船。我们从几个常量开始，这些常量定义了我们在虚拟文件系统中放置精灵的位置，以及宽度和高度：

```cpp
class Projectile {
    public:
        const char* c_SpriteFile = "sprites/Projectile.png";
        const int c_Width = 8;
        const int c_Height = 8;
```

接下来的属性是`m_SpriteTexture`，它是一个指向用于渲染我们的 projectiles 的 SDL 纹理的指针。我们需要一个变量来告诉我们的对象池这个游戏对象是活动的。我们称这个属性为`m_Active`。接下来，我们有一个常量，它定义了我们的 projectile 每秒移动的像素数，称为`c_Velocity`，以及一个常量，表示 projectile 在自毁之前会在毫秒内保持活动的时间，称为`c_AliveTime`。

`m_TTL`变量是一个**生存时间**变量，跟踪着直到这个 projectile 将其`m_Active`变量更改为`false`并将自己回收到**projectile 池**中还有多少毫秒。`m_X`，`m_Y`，`m_VX`和`m_VY`变量用于跟踪我们的 projectile 的`x`和`y`位置以及`x`和`y`速度。

然后我们为我们的 projectile 类声明了四个函数：

```cpp
Projectile();
void Move();
void Render();
void Launch(float x, float y, float dx, float dy);
```

`Projectile`函数是我们的类构造函数。如果我们的 projectile 当前处于活动状态，`Move`和`Render`将在每帧调用一次。`Move`函数将管理活动 projectile 的移动，`Render`将管理将 projectile 精灵绘制到我们的 HTML 画布元素上。`Launch`函数将从我们的`PlayerShip`类中调用，使我们的飞船朝着飞船的方向发射 projectile。

我们必须添加到我们的`game.hpp`文件中的最终类定义是`ProjectilePool`类：

```cpp
class ProjectilePool {
    public:
        std::vector<Projectile*> m_ProjectileList;
        ProjectilePool();
        ~ProjectilePool();
        void MoveProjectiles();
        void RenderProjectiles();
        Projectile* GetFreeProjectile();
};
```

这个类管理一个包含在向量属性`m_ProjectileList`中的 10 个 projectiles 的**池**。这个类的函数包括构造函数和析构函数，`MoveProjectiles`，`RenderProjectils`和`GetFreeProjectile`。

`MoveProjectiles()`函数循环遍历我们的 projectile 列表，调用任何活动 projectile 上的`move`函数。`RenderProjectiles()`函数循环遍历我们的 projectile 列表，并在画布上渲染任何活动的 projectile，`GetFreeProjectile`返回我们的池中第一个非活动的 projectile。

# 池化玩家的 projectiles

现在我们已经查看了`Projectile`和`ProjectilePool`类的类定义，我们需要创建一个`projectile.cpp`文件和一个`projectile_pool.cpp`文件来存储这些类的函数代码。因为这是在第六章，*游戏对象和游戏循环*，我建议创建一个名为`Chapter06`的新文件夹来保存这些文件。这段代码将完成我们的 projectiles 的池化工作，在我们需要时请求一个非活动的 projectile，并移动和渲染我们的活动 projectiles。首先，让我们看看我们在`projectile.cpp`中的代码：

```cpp
#include "game.hpp"

Projectile::Projectile() {
    m_Active = false;
    m_X = 0.0;
    m_Y = 0.0;
    m_VX = 0.0;
    m_VY = 0.0;

    SDL_Surface *temp_surface = IMG_Load( c_SpriteFile );

    if( !temp_surface ) {
        printf("failed to load image: %s\n", IMG_GetError() );
        return;
    }

    m_SpriteTexture = SDL_CreateTextureFromSurface( renderer, 
    temp_surface );

    if( !m_SpriteTexture ) {
        printf("failed to create texture: %s\n", IMG_GetError() );
        return;
    }

    SDL_FreeSurface( temp_surface );
}

void Projectile::Move() {
    m_X += m_VX;
    m_Y += m_VY;
    m_TTL -= diff_time;

    if( m_TTL <= 0 ) {
        m_Active = false;
        m_TTL = 0;
    }
}

void Projectile::Render() {
    dest.x = m_X;
    dest.y = m_Y;
    dest.w = c_Width;
    dest.h = c_Height;

    int return_val = SDL_RenderCopy( renderer, m_SpriteTexture,
                                     NULL, &dest );
    if( return_val != 0 ) {
        printf("SDL_Init failed: %s\n", SDL_GetError());
    }
}

void Projectile::Launch(float x, float y, float dx, float dy) {
    m_X = x;
    m_Y = y;
    m_VX = c_Velocity * dx;
    m_VY = c_Velocity * dy;
    m_TTL = c_AliveTime;
    m_Active = true;
}
```

这是处理移动、渲染和发射单个 projectile 的代码。这里声明的第一个函数是构造函数：

```cpp
Projectile::Projectile() {
    m_Active = false;
    m_X = 0.0;
    m_Y = 0.0;
    m_VX = 0.0;
    m_VY = 0.0;

    SDL_Surface *temp_surface = IMG_Load( c_SpriteFile );

    if( !temp_surface ) {
        printf("failed to load image: %s\n", IMG_GetError() );
        return;
    }

    m_SpriteTexture = SDL_CreateTextureFromSurface( renderer, 
    temp_surface );

    if( !m_SpriteTexture ) {
        printf("failed to create texture: %s\n", IMG_GetError() );
        return;
    }
    SDL_FreeSurface( temp_surface );
}
```

这个构造函数的主要任务是将 projectile 设置为非活动状态，并创建一个 SDL 纹理，我们稍后将用它来渲染我们的精灵到画布元素上。在定义了构造函数之后，我们定义了我们的`Move`函数：

```cpp
void Projectile::Move() {
    m_X += m_VX;
    m_Y += m_VY;
    m_TTL -= diff_time;
    if( m_TTL <= 0 ) {
        m_Active = false;
        m_TTL = 0;
    }
}
```

这个函数根据速度改变我们的 projectile 的*x*和*y*位置，并减少我们的 projectile 的生存时间，如果它的生存时间小于或等于零，就将其设置为非活动状态并回收到 projectile 池中。我们定义的下一个函数是我们的`Render`函数：

```cpp
void Projectile::Render() {
    dest.x = m_X;
    dest.y = m_Y;
    dest.w = c_Width;
    dest.h = c_Height;

    int return_val = SDL_RenderCopy( renderer, m_SpriteTexture,
                                    NULL, &dest );

    if( return_val != 0 ) {
        printf("SDL_Init failed: %s\n", SDL_GetError());
    }
}
```

这段代码与我们用来渲染飞船的代码类似，所以它应该对你来说看起来很熟悉。我们最后的 projectile 函数是`Launch`函数：

```cpp
void Projectile::Launch(float x, float y, float dx, float dy) {
    m_X = x;
    m_Y = y;
    m_VX = c_Velocity * dx;
    m_VY = c_Velocity * dy;
    m_TTL = c_AliveTime;
    m_Active = true;
}
```

这个函数是在玩家在键盘上按下空格键时从`PlayerShip`类中调用的。`PlayerShip`对象将在`dx`和`dy`参数中传入玩家飞船的*x*和*y*坐标，以及飞船面对的方向。这些参数用于设置抛射物的*x*和*y*坐标以及抛射物的*x*和*y*速度。游戏将生存时间设置为默认的存活时间，然后将对象设置为活动状态。

现在我们已经完全定义了我们的`Projectile`类，让我们设置一个管理这些抛射物的`ProjectilePool`类。以下代码将在我们的`projectile_pool.cpp`文件中：

```cpp
#include "game.hpp"

ProjectilePool::ProjectilePool() {
    for( int i = 0; i < 10; i++ ) {
        m_ProjectileList.push_back( new Projectile() );
    }
}

ProjectilePool::~ProjectilePool() {
    m_ProjectileList.clear();
}

void ProjectilePool::MoveProjectiles() {
    Projectile* projectile;
    std::vector<Projectile*>::iterator it;

    for( it = m_ProjectileList.begin(); it != m_ProjectileList.end(); it++ ) {
        projectile = *it;
        if( projectile->m_Active ) {
            projectile->Move();
        }
    }
}

void ProjectilePool::RenderProjectiles() {
    Projectile* projectile;
    std::vector<Projectile*>::iterator it;

    for( it = m_ProjectileList.begin(); it != m_ProjectileList.end(); it++ ) {
        projectile = *it;
        if( projectile->m_Active ) {
            projectile->Render();
         }
    }
}

Projectile* ProjectilePool::GetFreeProjectile() {
    Projectile* projectile;
    std::vector<Projectile*>::iterator it;

    for( it = m_ProjectileList.begin(); it != m_ProjectileList.end(); it++ ) {
        projectile = *it;
        if( projectile->m_Active == false ) {
            return projectile;
        }
    }
    return NULL;
}
```

前两个函数是构造函数和析构函数。这些函数在我们的列表内创建和销毁抛射物。接下来的函数是`MoveProjectiles`函数，它循环遍历我们的`m_ProjectileList`寻找活动的抛射物并移动它们。之后，我们有一个`RenderProjectiles`函数，它与我们的`MoveProjectiles`函数非常相似。这个函数循环遍历我们的列表，调用所有活动抛射物的`Render`函数。最后一个函数是`GetFreeProjectile`函数，它通过`m_ProjectileList`寻找第一个不活动的抛射物以返回它。每当我们想要发射一个抛射物时，我们需要调用这个函数来找到一个不活动的抛射物。

# 创建一个敌人

所以，现在我们有了一个射击的玩家飞船，我们可以开始添加一个敌人飞船。它将类似于`PlayerShip`类。稍后，我们将进入类继承，这样我们就不会得到一个复制并粘贴的相同代码版本，但现在我们将在我们的`game.hpp`文件中添加一个几乎与我们的`PlayerShip`类相同的新类定义：

```cpp
enum FSM_STUB {
    SHOOT = 0,
    TURN_LEFT = 1,
    TURN_RIGHT = 2,
    ACCELERATE = 3,
    DECELERATE = 4
};

class EnemyShip {
    public:
        const char* c_SpriteFile = "sprites/BirdOfAnger.png";
        const Uint32 c_MinLaunchTime = 300;
        const int c_Width = 16;
        const int c_Height = 16;
        const int c_AIStateTime = 2000;

        Uint32 m_LastLaunchTime;
        SDL_Texture *m_SpriteTexture;

        FSM_STUB m_AIState;
        int m_AIStateTTL;

        float m_X;
        float m_Y;
        float m_Rotation;
        float m_DX;
        float m_DY;
        float m_VX;
        float m_VY;

        EnemyShip();
        void RotateLeft();
        void RotateRight();
        void Accelerate();
        void Decelerate();
        void CapVelocity();
        void Move();
        void Render();
        void AIStub();
};
```

您会注意到在`EnemyShip`类之前，我们定义了一个`FSM_STUB`枚举。枚举就像是您可以在 C 或 C++代码中定义的新数据类型。我们将在另一章中讨论**人工智能**和**有限状态机**，但现在我们仍然希望我们的敌人飞船做一些事情，即使那些事情并不是很聪明。我们创建了一个`FSM_STUB`枚举来定义我们的敌人飞船目前可以做的事情。我们还在我们的`EnemyShip`类中创建了一个`AIStub`，它将作为未来 AI 逻辑的替身。整数属性`m_AIStateTTL`是一个倒计时计时器，用于 AI 状态的变化。还有一个名为`c_AIStateTime`的新常量，它的值为`2000`。这是我们的 AI 状态在随机更改之前将持续的毫秒数。

我们将创建一个`enemy_ship.cpp`文件，并向其中添加九个函数。第一个函数是我们的构造函数，在它之前是我们的`game.hpp`文件的`#include`：

```cpp
#include "game.hpp"
EnemyShip::EnemyShip() {
 m_X = 60.0;
    m_Y = 50.0;
    m_Rotation = PI;
    m_DX = 0.0;
    m_DY = 1.0;
    m_VX = 0.0;
    m_VY = 0.0;
    m_LastLaunchTime = current_time;

    SDL_Surface *temp_surface = IMG_Load( c_SpriteFile );

    if( !temp_surface ) {
        printf("failed to load image: %s\n", IMG_GetError() );
        return;
    }
    else {
        printf("success creating enemy ship surface\n");
    }
    m_SpriteTexture = SDL_CreateTextureFromSurface( renderer, 
    temp_surface );

    if( !m_SpriteTexture ) {
        printf("failed to create texture: %s\n", IMG_GetError() );
        return;
    }
    else {
        printf("success creating enemy ship texture\n");
    }
    SDL_FreeSurface( temp_surface );
}
```

之后，我们有`RotateLeft`和`RotateRight`函数，用于转动太空飞船：

```cpp
void EnemyShip::RotateLeft() {
    m_Rotation -= delta_time;

    if( m_Rotation < 0.0 ) {
        m_Rotation += TWO_PI;
    }
    m_DX = sin(m_Rotation);
    m_DY = -cos(m_Rotation);
}
void EnemyShip::RotateRight() {
    m_Rotation += delta_time;

    if( m_Rotation >= TWO_PI ) {
        m_Rotation -= TWO_PI;
    }
    m_DX = sin(m_Rotation);
    m_DY = -cos(m_Rotation);
}
```

函数`Accelerate`、`Decelerate`和`CapVelocity`都用于修改敌舰的速度。

```cpp
void EnemyShip::Accelerate() {
    m_VX += m_DX * delta_time;
    m_VY += m_DY * delta_time;
}

void EnemyShip::Decelerate() {
    m_VX -= (m_DX * delta_time) / 2.0;
    m_VY -= (m_DY * delta_time) / 2.0;
}

void EnemyShip::CapVelocity() {
    float vel = sqrt( m_VX * m_VX + m_VY * m_VY );

    if( vel > MAX_VELOCITY ) {
        m_VX /= vel;
        m_VY /= vel;

        m_VX *= MAX_VELOCITY;
        m_VY *= MAX_VELOCITY;
    }
}
```

接下来我们添加到文件中的是`Render`函数：

```cpp
void EnemyShip::Render() {
    dest.x = (int)m_X;
    dest.y = (int)m_Y;
    dest.w = c_Width;
    dest.h = c_Height;

    float degrees = (m_Rotation / PI) * 180.0;

    int return_code = SDL_RenderCopyEx( renderer, m_SpriteTexture,
                                        NULL, &dest,
                                        degrees, NULL, SDL_FLIP_NONE );

 if( return_code != 0 ) {
 printf("failed to render image: %s\n", IMG_GetError() );
 }
}

```

最后，我们添加了`Move`和`AIStub`函数：

```cpp
void EnemyShip::Move() {
     AIStub();

 if( m_AIState == TURN_LEFT ) {
     RotateLeft();
 }

 if( m_AIState == TURN_RIGHT ) {
     RotateRight();
 }

 if( m_AIState == ACCELERATE ) {
     Accelerate();
 }

 if( m_AIState == DECELERATE ) {
     Decelerate();
 }

 CapVelocity();
 m_X += m_VX;

 if( m_X > 320 ) {
     m_X = -16;
 }
 else if( m_X < -16 ) {
     m_X = 320;
 }

 m_Y += m_VY;

 if( m_Y > 200 ) {
     m_Y = -16;
 }
 else if( m_Y < -16 ) {
     m_Y = 200;
 }

 if( m_AIState == SHOOT ) {
     Projectile* projectile;
     if( current_time - m_LastLaunchTime >= c_MinLaunchTime ) {
         m_LastLaunchTime = current_time;
         projectile = projectile_pool->GetFreeProjectile();

         if( projectile != NULL ) {
             projectile->Launch( m_X, m_Y, m_DX, m_DY );
             }
         }
     }
}

void EnemyShip::AIStub() {
     m_AIStateTTL -= diff_time;
     if( m_AIStateTTL <= 0 ) {
         // for now get a random AI state.
         m_AIState = (FSM_STUB)(rand() % 5);
         m_AIStateTTL = c_AIStateTime;
     }
}
```

这些函数都与我们的`player_ship.cpp`文件中定义的函数相同，除了`Move`函数。我们添加了一个新函数，`AIStub`。以下是`AIStub`函数中的代码：

```cpp
void EnemyShip::AIStub() {
    m_AIStateTTL -= diff_time;

    if( m_AIStateTTL <= 0 ) {
        // for now get a random AI state.
        m_AIState = (FSM_STUB)(rand() % 5);
        m_AIStateTTL = c_AIStateTime;
    }
}
```

这个函数是暂时的。我们最终将为我们的敌人飞船定义一个真正的 AI。现在，这个函数使用`m_AIStateTTL`来倒计时固定数量的毫秒，直到达到或低于`0`。在这一点上，它会基于我们之前定义的枚举`FSM_STUB`中的一个值随机设置一个新的 AI 状态。我们还对我们为玩家飞船创建的`Move()`函数进行了一些修改：

```cpp
void EnemyShip::Move() {
    AIStub();

    if( m_AIState == TURN_LEFT ) {
        RotateLeft();
    }
    if( m_AIState == TURN_RIGHT ) {
        RotateRight();
    }
    if( m_AIState == ACCELERATE ) {
        Accelerate();
    }
    if( m_AIState == DECELERATE ) {
        Decelerate();
    }
    CapVelocity();
     m_X += m_VX;

    if( m_X > 320 ) {
        m_X = -16;
    }
    else if( m_X < -16 ) {
        m_X = 320;
    }
    m_Y += m_VY;

    if( m_Y > 200 ) {
        m_Y = -16;
    }
    else if( m_Y < -16 ) {
        m_Y = 200;
    }

    if( m_AIState == SHOOT ) {
        Projectile* projectile;
        if( current_time - m_LastLaunchTime >= c_MinLaunchTime ) {
            m_LastLaunchTime = current_time;
            projectile = projectile_pool->GetFreeProjectile();

            if( projectile != NULL ) {
                projectile->Launch( m_X, m_Y, m_DX, m_DY );
            }
        }
    }
}
```

我已经从我们的`PlayerShip::Move`函数中取出了代码并对其进行了一些修改。在这个新函数的开头，我们添加了对`AIStub`函数的调用。这个函数是我们未来 AI 的替身。与我们为玩家飞船所做的一样，敌人飞船不会查看我们的键盘输入，而是会查看 AI 状态并选择左转、右转、加速、减速或射击。这不是真正的 AI，只是飞船做一些随机的事情，但它让我们能够想象一下当飞船具有真正的 AI 时它会是什么样子，并且它将允许我们稍后添加更多功能，比如碰撞检测。

# 编译 game_objects.html

现在我们已经构建了所有这些游戏对象，我们不再将所有内容放在一个文件中。我们需要包含几个 CPP 文件，并将它们全部编译成一个名为`game_objects.html`的输出文件。因为我们已经从 C 世界转移到了 C++世界，所以我们将使用 em++来指示我们正在编译的文件是 C++文件而不是 C 文件。这并不是严格必要的，因为当 Emscripten 接收到扩展名为`.cpp`的文件作为输入时，它会自动判断我们正在使用 C++进行编译。当我们传入`-std=c++17`标志时，我们还明确告诉编译器我们正在使用的 C++版本。请使用以下 em++命令编译`game_objects.html`文件：

```cpp
em++ main.cpp enemy_ship.cpp player_ship.cpp projectile.cpp projectile_pool.cpp -std=c++17 --preload-file sprites -s USE_WEBGL2=1 -s USE_SDL=2 -s USE_SDL_IMAGE=2 -s SDL2_IMAGE_FORMATS=["png"] -o game_objects.html
```

现在我们已经编译了`game_objects.html`文件，请使用 Web 服务器来提供文件并在浏览器中打开它，它应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-gm-dev-wasm/img/23123d7f-c321-4339-b623-e4be90bc4388.png)

game_objects.html 的屏幕截图

不要忘记，您必须使用 Web 服务器或`emrun`来运行 WebAssembly 应用程序。如果您想使用`emrun`运行 WebAssembly 应用程序，您必须使用`--emrun`标志进行编译。Web 浏览器需要 Web 服务器来流式传输 WebAssembly 模块。如果您尝试直接从硬盘驱动器在浏览器中打开使用 WebAssembly 的 HTML 页面，那么 WebAssembly 模块将无法加载。

您可以使用箭头键在画布上移动您的飞船，并使用空格键发射抛射物。敌船将在画布上随机移动并射击。

如果您在构建此应用程序或本书中的任何其他应用程序时遇到问题，请记住您可以在 Twitter 上联系我，[`twitter.com/battagline/`](https://twitter.com/battagline/)，使用 Twitter 账号`@battagline`提问。我很乐意帮助。

# 摘要

在本章中，我们学习了如何创建一个基本的游戏框架。我们了解了游戏循环是什么，以及如何使用 Emscripten 为 WebAssembly 创建游戏循环。我们学习了游戏对象，并创建了用于定义玩家飞船、敌人飞船和抛射物的类。我们学习了对象池，以及如何使用对象池来回收内存中的对象，这样我们就不需要不断地在内存中创建和销毁新对象。我们利用这些知识为我们的抛射物创建了一个对象池。我们还为我们的敌人飞船创建了一个 AI 存根，使该对象具有随机行为，并创建了让我们的玩家和敌人相互射击的函数，同时我们的抛射物会无害地穿过飞船。

在下一章结束时，我们将添加碰撞检测；这将允许我们的抛射物摧毁它们击中的飞船，并添加一个动画序列，当飞船被抛射物击中时将显示飞船被摧毁的情景。
