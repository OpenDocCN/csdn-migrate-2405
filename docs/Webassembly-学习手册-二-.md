# Webassembly 学习手册（二）

> 原文：[`annas-archive.org/md5/d5832e9a9d99a1607969f42f55873dd5`](https://annas-archive.org/md5/d5832e9a9d99a1607969f42f55873dd5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：创建和加载 WebAssembly 模块

我们在第四章 *安装所需的依赖项*中向`emcc`命令传递的标志产生了一个单一的`.wasm`文件，可以使用本机的`WebAssembly`对象在浏览器中加载和实例化。C 代码是一个非常简单的示例，旨在测试编译器，而无需考虑包含的库或 WebAssembly 的限制。通过利用 Emscripten 的一些功能，我们可以克服 C/C++代码的一些 WebAssembly 的限制，而只有最小的性能损失。

在本章中，我们将涵盖与 Emscripten 的粘合代码使用对应的编译和加载步骤。我们还将描述使用浏览器的`WebAssembly`对象编译/输出严格的`.wasm`文件并加载它们的过程。

本章的目标是理解以下内容：

+   利用 Emscripten 的 JavaScript“glue”代码编译 C 代码的过程

+   如何在浏览器中加载 Emscripten 模块

+   只输出`.wasm`文件的 C 代码编译过程（没有“glue”代码）

+   如何在 VS Code 中配置构建任务

+   如何使用全局的`WebAssembly`对象在浏览器中编译和加载 Wasm 模块

# 使用 Emscripten 粘合代码编译 C

在第四章 *安装所需的依赖项*中，您编写并编译了一个简单的三行程序，以确保您的 Emscripten 安装有效。我们向`emcc`命令传递了几个标志，这些标志要求只输出一个`.wasm`文件。通过向`emcc`命令传递其他标志，我们可以在`.wasm`文件旁边输出 JavaScript 粘合代码以及一个处理加载过程的 HTML 文件。在本节中，我们将编写一个更复杂的 C 程序，并使用 Emscripten 提供的输出选项进行编译。

# 编写示例 C 代码

我们在第四章中涵盖的示例中没有包含任何头文件或传递任何函数，*安装所需的依赖项*。由于代码的目的仅是测试编译器安装是否有效，因此并不需要太多。Emscripten 提供了许多额外的功能，使我们能够与 JavaScript 以及反之互动我们的 C 和 C++代码。其中一些功能是 Emscripten 特有的，不对应*核心规范*或其 API。在我们的第一个示例中，我们将利用 Emscripten 的一个移植库和 Emscripten 的 API 提供的一个函数。

以下程序使用**Simple DirectMedia Layer**（**SDL2**）在画布上对角移动一个矩形的无限循环。它取自[`github.com/timhutton/sdl-canvas-wasm`](https://github.com/timhutton/sdl-canvas-wasm)，但我将其从 C++转换为 C 并稍微修改了代码。本节的代码位于`learn-webassembly`存储库的`/chapter-05-create-load-module`文件夹中。按照以下说明使用 Emscripten 编译 C。

在您的`/book-examples`文件夹中创建一个名为`/chapter-05-create-load-module`的文件夹。在此文件夹中创建一个名为`with-glue.c`的新文件，并填充以下内容：

```cpp
/*
 * Converted to C code taken from:
 * https://github.com/timhutton/sdl-canvas-wasm
 * Some of the variable names and comments were also
 * slightly updated.
 */
#include <SDL2/SDL.h>
#include <emscripten.h>
#include <stdlib.h>

// This enables us to have a single point of reference
// for the current iteration and renderer, rather than
// have to refer to them separately.
typedef struct Context {
  SDL_Renderer *renderer;
  int iteration;
} Context;

/*
 * Looping function that draws a blue square on a red
 * background and moves it across the <canvas>.
 */
void mainloop(void *arg) {
    Context *ctx = (Context *)arg;
    SDL_Renderer *renderer = ctx->renderer;
    int iteration = ctx->iteration;

    // This sets the background color to red:
    SDL_SetRenderDrawColor(renderer, 255, 0, 0, 255);
    SDL_RenderClear(renderer);

    // This creates the moving blue square, the rect.x
    // and rect.y values update with each iteration to move
    // 1px at a time, so the square will move down and
    // to the right infinitely:
    SDL_Rect rect;
    rect.x = iteration;
    rect.y = iteration;
    rect.w = 50;
    rect.h = 50;
    SDL_SetRenderDrawColor(renderer, 0, 0, 255, 255);
    SDL_RenderFillRect(renderer, &rect);

    SDL_RenderPresent(renderer);

    // This resets the counter to 0 as soon as the iteration
    // hits the maximum canvas dimension (otherwise you'd
    // never see the blue square after it travelled across
    // the canvas once).
    if (iteration == 255) {
        ctx->iteration = 0;
    } else {
        ctx->iteration++;
    }
}

int main() {
    SDL_Init(SDL_INIT_VIDEO);
    SDL_Window *window;
    SDL_Renderer *renderer;

    // The first two 255 values represent the size of the <canvas>
    // element in pixels.
    SDL_CreateWindowAndRenderer(255, 255, 0, &window, &renderer);

    Context ctx;
    ctx.renderer = renderer;
    ctx.iteration = 0;

    // Call the function repeatedly:
    int infinite_loop = 1;

    // Call the function as fast as the browser wants to render
    // (typically 60fps):
    int fps = -1;

    // This is a function from emscripten.h, it sets a C function
    // as the main event loop for the calling thread:
    emscripten_set_main_loop_arg(mainloop, &ctx, fps, infinite_loop);

    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);
    SDL_Quit();

    return EXIT_SUCCESS;
}
```

`main()`函数末尾的`emscripten_set_main_loop_arg()`是可用的，因为我们在文件顶部包含了`emscripten.h`。以`SDL_`为前缀的变量和函数是可用的，因为在文件顶部包含了`#include <SDL2/SDL.h>`。如果您在`<SDL2/SDL.h>`语句下看到了红色的波浪线错误，您可以忽略它。这是因为 SDL 的`include`路径不在您的`c_cpp_properties.json`文件中。

# 编译示例 C 代码

现在我们已经编写了我们的 C 代码，我们需要编译它。您必须传递给`emcc`命令的一个必需标志是`-o <target>`，其中`<target>`是所需输出文件的路径。该文件的扩展名不仅仅是输出该文件；它会影响编译器做出的一些决定。下表摘自 Emscripten 的`emcc`文档[`kripken.github.io/emscripten-site/docs/tools_reference/emcc.html#emcc-o-target`](http://kripken.github.io/emscripten-site/docs/tools_reference/emcc.html#emcc-o-target)，定义了根据指定的文件扩展名生成的输出类型：

| **扩展名** | **输出** |
| --- | --- |
| `<name>.js` | JavaScript 胶水代码（如果指定了`s WASM=1`标志，则还有`.wasm`）。 |
| `<name>.html` | HTML 和单独的 JavaScript 文件（`<name>.js`）。有单独的 JavaScript 文件可以提高页面加载时间。 |
| `<name>.bc` | LLVM 位码（默认）。 |
| `<name>.o` | LLVM 位码（与`.bc`相同）。 |
| `<name>.wasm` | 仅 Wasm 文件（使用第四章中指定的标志）。 |

您可以忽略`.bc`和`.o`文件扩展名，我们不需要输出 LLVM 位码。`.wasm`扩展名不在`emcc` *工具参考*页面上，但如果您传递正确的编译器标志，它是一个有效的选项。这些输出选项影响我们编写的 C/C++代码。

# 输出带有胶水代码的 HTML

如果您为输出文件指定 HTML 文件扩展名（例如，`-o with-glue.html`），您将得到一个`with-glue.html`、`with-glue.js`和`with-glue.wasm`文件（假设您还指定了`-s WASM=1`）。如果您在源 C/C++文件中有一个`main()`函数，它将在 HTML 加载后立即执行该函数。让我们编译我们的示例 C 代码，看看它是如何运行的。要使用 HTML 文件和 JavaScript 胶水代码进行编译，`cd`到`/chapter-05-create-load-module`文件夹，并运行以下命令：

```cpp
emcc with-glue.c -O3 -s WASM=1 -s USE_SDL=2 -o with-glue.html
```

第一次运行此命令时，Emscripten 将下载并构建`SDL2`库。这可能需要几分钟才能完成，但您只需要等待一次。Emscripten 会缓存该库，因此后续构建速度会快得多。构建完成后，您将在文件夹中看到三个新文件：HTML、JavaScript 和 Wasm 文件。运行以下命令在本地`serve`文件：

```cpp
serve -l 8080
```

如果您在浏览器中打开`http://127.0.0.1:8080/with-glue.html`，您应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/bb584a1f-c5eb-415f-b86a-5904f11404a5.png)

在浏览器中运行 Emscripten 加载代码

蓝色矩形应该从红色矩形的左上角对角线移动到右下角。由于您在 C 文件中指定了`main()`函数，Emscripten 知道应该立即执行它。如果您在 VS code 中打开`with-glue.html`文件并滚动到文件底部，您将看到加载代码。您不会看到任何对`WebAssembly`对象的引用；这在 JavaScript 胶水代码文件中处理。

# 输出没有 HTML 的胶水代码

Emscripten 在 HTML 文件中生成的加载代码包含错误处理和其他有用的功能，以确保模块在执行`main()`函数之前加载。如果您为输出文件的扩展名指定`.js`，则必须自己创建 HTML 文件并编写加载代码。在下一节中，我们将更详细地讨论加载代码。

# 加载 Emscripten 模块

加载和与使用 Emscripten 的胶水代码的模块进行交互与 WebAssembly 的 JavaScript API 有很大不同。这是因为 Emscripten 为与 JavaScript 代码交互提供了额外的功能。在本节中，我们将讨论 Emscripten 在输出 HTML 文件时提供的加载代码，并审查在浏览器中加载 Emscripten 模块的过程。

# 预生成的加载代码

如果在运行`emcc`命令时指定了`-o <target>.html`，Emscripten 会生成一个 HTML 文件，并自动添加代码来加载模块到文件的末尾。以下是 HTML 文件中加载代码的样子，其中排除了每个`Module`函数的内容：

```cpp
var statusElement = document.getElementById('status');
var progressElement = document.getElementById('progress');
var spinnerElement = document.getElementById('spinner');

var Module = {
  preRun: [],
  postRun: [],
  print: (function() {...})(),
  printErr: function(text) {...},
  canvas: (function() {...})(),
  setStatus: function(text) {...},
  totalDependencies: 0,
  monitorRunDependencies: function(left) {...}
};

Module.setStatus('Downloading...');

window.onerror = function(event) {
  Module.setStatus('Exception thrown, see JavaScript console');
  spinnerElement.style.display = 'none';
  Module.setStatus = function(text) {
    if (text) Module.printErr('[post-exception status] ' + text);
  };
};
```

`Module`对象内的函数用于检测和解决错误，监视`Module`的加载状态，并在对应的粘合代码文件执行`run()`方法之前或之后可选择执行一些函数。下面的代码片段中显示的`canvas`函数返回了在加载代码之前在 HTML 文件中指定的 DOM 中的`<canvas>`元素：

```cpp
canvas: (function() {
  var canvas = document.getElementById('canvas');
  canvas.addEventListener(
    'webglcontextlost',
    function(e) {
      alert('WebGL context lost. You will need to reload the page.');
      e.preventDefault();
    },
    false
  );

  return canvas;
})(),
```

这段代码方便检测错误并确保`Module`已加载，但对于我们的目的，我们不需要那么冗长。

# 编写自定义加载代码

Emscripten 生成的加载代码提供了有用的错误处理。如果你在生产中使用 Emscripten 的输出，我建议你包含它以确保你正确处理错误。然而，我们实际上不需要所有的代码来使用我们的`Module`。让我们编写一些更简单的代码并测试一下。首先，让我们将我们的 C 文件编译成没有 HTML 输出的粘合代码。为此，运行以下命令：

```cpp
emcc with-glue.c -O3 -s WASM=1 -s USE_SDL=2 -s MODULARIZE=1 -o custom-loading.js
```

`-s MODULARIZE=1`编译器标志允许我们使用类似 Promise 的 API 来加载我们的`Module`。编译完成后，在`/chapter-05-create-load-module`文件夹中创建一个名为`custom-loading.html`的文件，并填充以下内容：

```cpp
<!doctype html>
<html lang="en-us">
<head>
  <title>Custom Loading Code</title>
</head>
<body>
  <h1>Using Custom Loading Code</h1>
  <canvas id="canvas"></canvas>
  <script type="application/javascript" src="img/custom-loading.js"></script>
  <script type="application/javascript">
    Module({
      canvas: (() => document.getElementById('canvas'))(),
    })
      .then(() => {
        console.log('Loaded!');
      });
  </script>
</body>
</html>
```

现在加载代码使用了 ES6 的箭头函数语法来加载画布函数，这减少了所需的代码行数。通过在`/chapter-05-create-load-module`文件夹中运行`serve`命令来启动本地服务器：

```cpp
serve -l 8080
```

当你在浏览器中导航到`http://127.0.0.1:8080/custom-loading.html`时，你应该看到这个：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/5089d0d0-ffc7-4874-8cdf-9e307b5c3a1a.png)

在浏览器中运行自定义加载代码

当然，我们运行的函数并不是非常复杂，但它演示了加载 Emscripten 的`Module`所需的基本要求。我们将在第六章中更详细地研究`Module`对象，*与 JavaScript 交互和调试*，但现在只需知道加载过程与 WebAssembly 不同，我们将在下一节中介绍。

# 编译不带粘合代码的 C 代码

如果我们想要按照官方规范使用 WebAssembly，而不使用 Emscripten 提供的额外功能，我们需要向`emcc`命令传递一些标志，并确保编写的代码可以相对轻松地被 WebAssembly 使用。在*编写示例 C 代码*部分，我们编写了一个程序，它在红色画布上对角移动的蓝色矩形。它利用了 Emscripten 的一个移植库 SDL2。在本节中，我们将编写和编译一些不依赖于 Emscripten 辅助方法和移植库的 C 代码。

# 用于 WebAssembly 的 C 代码

在我们开始编写用于 WebAssembly 模块的 C 代码之前，让我们进行一个实验。在`/chapter-05-create-load-module`文件夹中打开 CLI，并尝试运行以下命令：

```cpp
emcc with-glue.c -Os -s WASM=1 -s USE_SDL=2 -s SIDE_MODULE=1 -s BINARYEN_ASYNC_COMPILATION=0 -o try-with-glue.wasm
```

在编译完成后，你应该在 VS Code 的文件资源管理器面板中看到一个`try-with-glue.wasm`文件。右键单击该文件，选择显示 WebAssembly。相应的 Wat 表示的开头应该类似于以下代码：

```cpp
(module
  (type $t0 (func (param i32)))
  (type $t1 (func (param i32 i32 i32 i32 i32) (result i32)))
  (type $t2 (func (param i32) (result i32)))
  (type $t3 (func))
  (type $t4 (func (param i32 i32) (result i32)))
  (type $t5 (func (param i32 i32 i32 i32)))
  (type $t6 (func (result i32)))
  (type $t7 (func (result f64)))
  (import "env" "memory" (memory $env.memory 256))
  (import "env" "table" (table $env.table 4 anyfunc))
  (import "env" "memoryBase" (global $env.memoryBase i32))
  (import "env" "tableBase" (global $env.tableBase i32))
  (import "env" "abort" (func $env.abort (type $t0)))
  (import "env" "_SDL_CreateWindowAndRenderer" (func $env._SDL_CreateWindowAndRenderer (type $t1)))
  (import "env" "_SDL_DestroyRenderer" (func $env._SDL_DestroyRenderer (type $t0)))
  (import "env" "_SDL_DestroyWindow" (func $env._SDL_DestroyWindow (type $t0)))
  (import "env" "_SDL_Init" (func $env._SDL_Init (type $t2)))
  (import "env" "_SDL_Quit" (func $env._SDL_Quit (type $t3)))
  (import "env" "_SDL_RenderClear" (func $env._SDL_RenderClear (type $t2)))
  (import "env" "_SDL_RenderFillRect" (func $env._SDL_RenderFillRect (type $t4)))
  (import "env" "_SDL_RenderPresent" (func $env._SDL_RenderPresent (type $t0)))
  (import "env" "_SDL_SetRenderDrawColor" (func $env._SDL_SetRenderDrawColor (type $t1)))
  (import "env" "_emscripten_set_main_loop_arg" (func $env._emscripten_set_main_loop_arg (type $t5)))
  ...
```

如果你想在浏览器中加载并执行它，你需要向 WebAssembly 的`instantiate()`或`compile()`函数传递一个`importObj`对象，其中包含每个`import "env"`函数的`env`对象。Emscripten 在幕后处理所有这些工作，使用粘合代码使其成为一个非常有价值的工具。然而，我们可以通过使用 DOM 替换 SDL2 功能，同时仍然在 C 中跟踪矩形的位置。

我们将以不同的方式编写 C 代码，以确保我们只需要将一些函数传递到`importObj.env`对象中来执行代码。在`/chapter-05-create-load-module`文件夹中创建一个名为`without-glue.c`的文件，并填充以下内容：

```cpp
/*
 * This file interacts with the canvas through imported functions.
 * It moves a blue rectangle diagonally across the canvas
 * (mimics the SDL example).
 */
#include <stdbool.h>

#define BOUNDS 255
#define RECT_SIDE 50
#define BOUNCE_POINT (BOUNDS - RECT_SIDE)

// These functions are passed in through the importObj.env object
// and update the rectangle on the <canvas>:
extern int jsClearRect();
extern int jsFillRect(int x, int y, int width, int height);

bool isRunning = true;

typedef struct Rect {
  int x;
  int y;
  char direction;
} Rect;

struct Rect rect;

/*
 * Updates the rectangle location by 1px in the x and y in a
 * direction based on its current position.
 */
void updateRectLocation() {
    // Since we want the rectangle to "bump" into the edge of the
    // canvas, we need to determine when the right edge of the
    // rectangle encounters the bounds of the canvas, which is why
    // we're using the canvas width - rectangle width:
    if (rect.x == BOUNCE_POINT) rect.direction = 'L';

    // As soon as the rectangle "bumps" into the left side of the
    // canvas, it should change direction again.
    if (rect.x == 0) rect.direction = 'R';

    // If the direction has changed based on the x and y
    // coordinates, ensure the x and y points update
    // accordingly:
    int incrementer = 1;
    if (rect.direction == 'L') incrementer = -1;
    rect.x = rect.x + incrementer;
    rect.y = rect.y + incrementer;
}

/*
 * Clear the existing rectangle element from the canvas and draw a
 * new one in the updated location.
 */
void moveRect() {
    jsClearRect();
    updateRectLocation();
    jsFillRect(rect.x, rect.y, RECT_SIDE, RECT_SIDE);
}

bool getIsRunning() {
    return isRunning;
}

void setIsRunning(bool newIsRunning) {
    isRunning = newIsRunning;
}

void init() {
    rect.x = 0;
    rect.y = 0;
    rect.direction = 'R';
    setIsRunning(true);
}
```

我们将从 C 代码中调用这些函数来确定*x*和*y*坐标。`setIsRunning()`函数可用于暂停矩形的移动。现在我们的 C 代码已经准备好了，让我们来编译它。在 VS Code 终端中，`cd`进入`/chapter-05-create-load-module`文件夹，并运行以下命令：

```cpp
emcc without-glue.c -Os -s WASM=1 -s SIDE_MODULE=1 -s BINARYEN_ASYNC_COMPILATION=0 -o without-glue.wasm
```

编译完成后，你可以右键单击生成的`without-glue.wasm`文件，选择 Show WebAssembly 来查看 Wat 表示。你应该在文件顶部看到`import "env"`项的以下内容：

```cpp
(module
  (type $t0 (func (param i32)))
  (type $t1 (func (result i32)))
  (type $t2 (func (param i32 i32 i32 i32) (result i32)))
  (type $t3 (func))
  (type $t4 (func (result f64)))
  (import "env" "memory" (memory $env.memory 256))
  (import "env" "table" (table $env.table 8 anyfunc))
  (import "env" "memoryBase" (global $env.memoryBase i32))
  (import "env" "tableBase" (global $env.tableBase i32))
  (import "env" "abort" (func $env.abort (type $t0)))
  (import "env" "_jsClearRect" (func $env._jsClearRect (type $t1)))
  (import "env" "_jsFillRect" (func $env._jsFillRect (type $t2)))
  ...
```

我们需要在`importObj`对象中传入`_jsClearRect`和`_jsFillRect`函数。我们将在 HTML 文件与 JavaScript 交互代码的部分介绍如何做到这一点。

# 在 VS Code 中使用构建任务进行编译

`emcc`命令有点冗长，手动为不同文件在命令行上运行这个命令可能会变得麻烦。为了加快编译过程，我们可以使用 VS Code 的 Tasks 功能为我们将要使用的文件创建一个构建任务。要创建一个构建任务，选择 Tasks | Configure Default Build Task…，选择 Create tasks.json from template 选项，并选择 Others 来在`.vscode`文件夹中生成一个简单的`tasks.json`文件。更新文件的内容以包含以下内容：

```cpp
{
  // See https://go.microsoft.com/fwlink/?LinkId=733558
  // for the documentation about the tasks.json format
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Build",
      "type": "shell",
      "command": "emcc",
      "args": [
        "${file}",
        "-Os",
        "-s", "WASM=1",
        "-s", "SIDE_MODULE=1",
        "-s", "BINARYEN_ASYNC_COMPILATION=0",
        "-o", "${fileDirname}/${fileBasenameNoExtension}.wasm"
       ],
      "group": {
        "kind": "build",
        "isDefault": true
       },
       "presentation": {
         "panel": "new"
       }
     }
  ]
}
```

`label`值只是一个运行任务时的名称。`type`和`command`值表示它应该在 shell（终端）中运行`emcc`命令。`args`值是要传递给`emcc`命令的参数数组（基于空格分隔）。`"${file}"`参数告诉 VS Code 编译当前打开的文件。`"${fileDirname}/${fileBasenameNoExtension}.wasm"`参数表示`.wasm`输出将与当前打开的文件具有相同的名称（带有`.wasm`扩展名），并且应放在当前打开文件的活动文件夹中。如果不指定`${fileDirname}`，输出文件将放在根文件夹中（而不是在本例中的`/chapter-05-create-load-module`中）。

`group`对象表示这个任务是默认的构建步骤，所以如果你使用键盘快捷键*Cmd*/*Ctrl* + *Shift* + *B*，这就是将要运行的任务。`presentation.panel`值为`"new"`告诉 VS Code 在运行构建步骤时打开一个新的 CLI 实例。这是个人偏好，可以省略。

一旦`tasks.json`文件完全填充，你可以保存并关闭它。要测试它，首先删除在上一节中使用`emcc`命令生成的`without-glue.wasm`文件。接下来，确保你打开了`without-glue.c`文件，并且光标在文件中，然后通过选择**Tasks** | Run Build Task…或使用键盘快捷键*Cmd*/*Ctrl* + *Shift* + *B*来运行构建任务。集成终端中的一个新面板将执行编译，一两秒后会出现一个`without-glue.wasm`文件。

# 获取和实例化 Wasm 文件

现在我们有了一个 Wasm 文件，我们需要一些 JavaScript 代码来编译和执行它。有一些步骤我们需要遵循，以确保代码可以成功地在浏览器中使用。在本节中，我们将编写一些常见的 JavaScript 加载代码，以便在其他示例中重用，创建一个演示 Wasm 模块使用的 HTML 文件，并在浏览器中测试结果。

# 常见的 JavaScript 加载代码

我们将在几个示例中获取和实例化一个`.wasm`文件，因此将 JavaScript 加载代码移到一个公共文件是有意义的。实际的获取和实例化代码只有几行，但是反复重新定义 Emscripten 期望的`importObj`对象是一种浪费时间。我们将使这段代码在一个通常可访问的文件中，以加快编写代码的过程。在`/book-examples`文件夹中创建一个名为`/common`的新文件夹，并添加一个名为`load-wasm.js`的文件，其中包含以下内容：

```cpp
/**
 * Returns a valid importObj.env object with default values to pass
 * into the WebAssembly.Instance constructor for Emscripten's
 * Wasm module.
 */
const getDefaultEnv = () => ({
  memoryBase: 0,
  tableBase: 0,
  memory: new WebAssembly.Memory({ initial: 256 }),
  table: new WebAssembly.Table({ initial: 2, element: 'anyfunc' }),
  abort: console.log
});

/**
 * Returns a WebAssembly.Instance instance compiled from the specified
 * .wasm file.
 */
function loadWasm(fileName, importObj = { env: {} }) {
  // Override any default env values with the passed in importObj.env
  // values:
  const allEnv = Object.assign({}, getDefaultEnv(), importObj.env);

  // Ensure the importObj object includes the valid env value:
  const allImports = Object.assign({}, importObj, { env: allEnv });

  // Return the result of instantiating the module (instance and module):
  return fetch(fileName)
    .then(response => {
      if (response.ok) return response.arrayBuffer();
      throw new Error(`Unable to fetch WebAssembly file ${fileName}`);
    })
    .then(bytes => WebAssembly.instantiate(bytes, allImports));
}
```

`getDefaultEnv()`函数为 Emscripten 的 Wasm 模块提供所需的`importObj.env`内容。我们希望能够传入任何其他的导入，这就是为什么使用`Object.assign()`语句的原因。除了 Wasm 模块期望的任何其他导入之外，Emscripten 的 Wasm 输出将始终需要这五个`"env"`对象的导入语句：

```cpp
(import "env" "memory" (memory $env.memory 256))
(import "env" "table" (table $env.table 8 anyfunc))
(import "env" "memoryBase" (global $env.memoryBase i32))
(import "env" "tableBase" (global $env.tableBase i32))
(import "env" "abort" (func $env.abort (type $t0)))
```

我们需要将这些传递给`instantiate()`函数，以确保 Wasm 模块成功加载，否则浏览器将抛出错误。现在我们的加载代码准备好了，让我们继续进行 HTML 和矩形渲染代码。

# HTML 页面

我们需要一个包含`<canvas>`元素和与 Wasm 模块交互的 JavaScript 代码的 HTML 页面。在`/chapter-05-create-load-module`文件夹中创建一个名为`without-glue.html`的文件，并填充以下内容：

```cpp
<!doctype html>
<html lang="en-us">
<head>
  <title>No Glue Code</title>
  <script type="application/javascript" src="img/load-wasm.js"></script>
</head>
<body>
  <h1>No Glue Code</h1>
  <canvas id="myCanvas" width="255" height="255"></canvas>
  <div style="margin-top: 16px;">
    <button id="actionButton" style="width: 100px; height: 24px;">
      Pause
    </button>
  </div>
  <script type="application/javascript">
    const canvas = document.querySelector('#myCanvas');
    const ctx = canvas.getContext('2d');

    const env = {
      table: new WebAssembly.Table({ initial: 8, element: 'anyfunc' }),
      _jsFillRect: function (x, y, w, h) {
        ctx.fillStyle = '#0000ff';
        ctx.fillRect(x, y, w, h);
      },
      _jsClearRect: function() {
        ctx.fillStyle = '#ff0000';
        ctx.fillRect(0, 0, 255, 255);
      },
    };

    loadWasm('without-glue.wasm', { env }).then(({ instance }) => {
      const m = instance.exports;
      m._init();

      // Move the rectangle by 1px in the x and y every 20 milliseconds:
      const loopRectMotion = () => {
        setTimeout(() => {
          m._moveRect();
          if (m._getIsRunning()) loopRectMotion();
        }, 20)
      };

      // Enable you to pause and resume the rectangle movement:
      document.querySelector('#actionButton')
        .addEventListener('click', event => {
          const newIsRunning = !m._getIsRunning();
          m._setIsRunning(newIsRunning);
          event.target.innerHTML = newIsRunning ? 'Pause' : 'Start';
          if (newIsRunning) loopRectMotion();
        });

      loopRectMotion();
    });
  </script>
</body>
</html>
```

这段代码将复制我们在前几节中创建的 SDL 示例，并添加一些功能。当矩形撞到右下角时，它会改变方向。您还可以使用`<canvas>`元素下的按钮暂停和恢复矩形的移动。您可以看到我们如何将`_jsFillRect`和`_jsClearRect`函数传递给`importObj.env`对象，以便 Wasm 模块可以引用它们。

# 提供所有服务

让我们在浏览器中测试我们的代码。从 VS Code 终端，确保您在`/book-examples`文件夹中，并运行命令启动本地服务器：

```cpp
serve -l 8080
```

重要的是您要在`/book-examples`文件夹中。如果您只尝试在`/chapter-05-create-load-module`文件夹中提供代码，您将无法使用`loadWasm()`函数。如果您在浏览器中打开`http://127.0.0.1:8080/chapter-05-create-load-module/without-glue.html`，您应该会看到这个：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/76e4c6ba-e85a-448f-8418-7e71adddb265.png)

在浏览器中运行的无粘合代码示例

尝试按下暂停按钮；标题应该更改为开始，矩形应该停止移动。再次点击它应该导致矩形重新开始移动。

# 总结

在本章中，我们介绍了使用 Emscripten 粘合代码和 Wasm 模块的编译和加载过程。通过利用 Emscripten 的一些内置功能，如移植库和辅助方法，我们能够展示 Emscripten 提供的优势。我们讨论了一些可以传递给`emcc`命令的编译器标志，以及这将如何影响您的输出。通过利用 VS Code 的任务功能，我们能够设置一个构建命令，以加快未来的构建过程。我们还回顾了在没有粘合代码的情况下编译和加载 Wasm 模块的过程。我们编写了一些可重用的 JavaScript 代码来加载模块，以及与我们编译的 Wasm 模块交互的代码。

在第六章，*与 JavaScript 交互和调试*中，我们将介绍在浏览器中与 JavaScript 交互和调试技术。

# 问题

1.  SDL 代表什么？

1.  除了 JavaScript、HTML 和 Wasm，您还可以使用`emcc`命令的`-o`标志生成什么其他输出类型？

1.  使用 Emscripten 的预生成加载代码有哪些优势？

1.  在 C/C++文件中，您必须如何命名您的函数，以确保它会自动在浏览器中执行编译后的输出？

1.  为什么在使用移植库时不能只使用 Wasm 文件输出而不使用“粘合”代码？

1.  在 VS Code 中运行默认构建任务的键盘快捷键是什么？

1.  在 Wasm 加载代码中，为什么我们需要`getDefaultEnv()`方法？

1.  对于使用 Emscripten 创建的 Wasm 模块，传递给 Wasm 实例化代码的`importObj.env`对象需要哪五个项目？

# 进一步阅读

+   关于 SDL：[`www.libsdl.org/index.php`](https://www.libsdl.org/index.php)

+   **Emscripten 编译器前端**（**emcc**）：[`kripken.github.io/emscripten-site/docs/tools_reference/emcc.html`](http://kripken.github.io/emscripten-site/docs/tools_reference/emcc.html)

+   通过任务与外部工具集成：[`code.visualstudio.com/docs/editor/tasks`](https://code.visualstudio.com/docs/editor/tasks)

+   加载和运行 WebAssembly 代码：[`developer.mozilla.org/en-US/docs/WebAssembly/Loading_and_running`](https://developer.mozilla.org/en-US/docs/WebAssembly/Loading_and_running)


# 第六章：与 JavaScript 交互和调试

WebAssembly 中有许多令人兴奋的功能和提案。然而，在撰写本书时，功能集相当有限。就目前而言，您可以从 Emscripten 提供的一些功能中获益良多。从 JavaScript 与 C/C++交互（反之亦然）的过程将取决于您是否决定使用 Emscripten。

在本章中，我们将介绍如何使用 JavaScript 函数与 C/C++代码以及如何与 JavaScript 中编译输出的 C/C++代码进行交互。我们还将描述 Emscripten 的*glue*代码如何影响 Wasm 实例的使用方式以及如何在浏览器中调试编译代码。

本章的目标是理解以下内容：

+   Emscripten 的`Module`与浏览器的`WebAssembly`对象之间的差异

+   如何从您的 JavaScript 代码中调用编译后的 C/C++函数

+   如何从您的 C/C++代码中调用 JavaScript 函数

+   在使用 C++时需要注意的特殊考虑事项

+   在浏览器中调试编译输出的技术

# Emscripten 模块与 WebAssembly 对象

在上一章中，我们简要介绍了 Emscripten 的`Module`对象以及如何在浏览器中加载它。`Module`对象提供了几种方便的方法，并且与浏览器的`WebAssembly`对象有很大的不同。在本节中，我们将更详细地回顾 Emscripten 的`Module`对象。我们还将讨论 Emscripten 的`Module`与 WebAssembly 的*JavaScript API*中描述的对象之间的差异。

# 什么是 Emscripten 模块？

Emscripten 的官方网站为`Module`对象提供了以下定义：

“Module 是一个全局 JavaScript 对象，Emscripten 生成的代码在其执行的各个点上调用它的属性。”

`Module`不仅在加载过程上与 WebAssembly 的`compile`和`instantiate`函数不同，而且`Module`在全局范围内提供了一些有用的功能，否则在 WebAssembly 中需要自定义实现。在获取和加载 Emscripten 的 JavaScript *glue*代码后，`Module`在全局范围内(`window.Module`)可用。

# 胶水代码中的默认方法

Emscripten 的`Module`对象提供了一些默认方法和属性，以帮助调试和确保编译代码的成功执行。您可以利用`preRun`和`postRun`属性在`run()`函数调用之前或之后执行 JavaScript 代码，或将`print()`和`printErr()`函数的输出导入页面上的 HTML 元素。我们将在本书的后面使用其中一些方法。您可以在[`kripken.github.io/emscripten-site/docs/api_reference/module.html`](https://kripken.github.io/emscripten-site/docs/api_reference/module.html)了解更多信息。

# WebAssembly 对象的差异

我们在第五章中介绍了浏览器的 WebAssembly 对象和相应的加载过程，*创建和加载 WebAssembly 模块*。WebAssembly 的 JavaScript 和 Web API 定义了浏览器的`window.WebAssembly`对象中可用的对象和方法。Emscripten 的`Module`可以看作是 WebAssembly 的`Module`和`Instance`对象的组合，这些对象存在于 WebAssembly 的实例化函数返回的`result`对象中。通过将`-s MODULARIZE=1`标志传递给`emcc`命令，我们能够复制 WebAssembly 的实例化方法（在一定程度上）。随着我们评估在即将到来的章节中集成 JavaScript 和 C/C++的方法，我们将更详细地检查 Emscripten 的`Module`与浏览器的`WebAssembly`对象之间的差异。

# 从 JavaScript 调用编译后的 C/C++函数

从 Wasm 实例调用函数是一个相对简单的过程，无论是否使用 Emscripten 的粘合代码。利用 Emscripten 的 API 可以提供更广泛的功能和集成，但需要将粘合代码与`.wasm`文件一起包含。在本节中，我们将回顾通过 JavaScript 与编译后的 Wasm 实例进行交互的方法以及 Emscripten 提供的附加工具。

# 从 Module 调用函数

Emscripten 提供了两个函数来从 JavaScript 调用编译后的 C/C++函数：`ccall()`和`cwrap()`。这两个函数都存在于`Module`对象中。决定使用哪一个取决于函数是否会被多次调用。以下内容摘自 Emscripten 的 API 参考文档`preamble.js`，可以在[`kripken.github.io/emscripten-site/docs/api_reference/preamble.js.html`](http://kripken.github.io/emscripten-site/docs/api_reference/preamble.js.html)上查看。

在使用`ccall()`或`cwrap()`时，不需要在函数调用前加上`_`前缀，只需使用 C/C++文件中指定的名称。

# Module.ccall()

`Module.ccall()`从 JavaScript 调用编译后的 C 函数，并返回该函数的结果。`Module.ccall()`的函数签名如下：

```cpp
ccall(ident, returnType, argTypes, args, opts)
```

在`returnType`和`argTypes`参数中必须指定类型名称。可能的类型有`"number"`、`"string"`、`"array"`和`"boolean"`，分别对应适当的 JavaScript 类型。不能在`returnType`参数中指定`"array"`，因为无法知道数组的长度。如果函数不返回任何内容，可以为`returnType`指定`null`（注意没有引号）。

`opts`参数是一个可选的选项对象，可以包含一个名为`async`的布尔属性。为此属性指定值`true`意味着调用将执行异步操作。我们不会在任何示例中使用此参数，但如果您想了解更多信息，可以在文档[`kripken.github.io/emscripten-site/docs/api_reference/preamble.js.html#calling-compiled-c-functions-from-javascript`](http://kripken.github.io/emscripten-site/docs/api_reference/preamble.js.html#calling-compiled-c-functions-from-javascript)中找到。

让我们看一个`ccall()`的例子。以下代码取自 Emscripten 网站，演示了如何从 C 文件的编译输出中调用名为`c_add()`的函数：

```cpp
// Call C from JavaScript
var result = Module.ccall(
  'c_add', // name of C function
  'number', // return type
  ['number', 'number'], // argument types
  [10, 20] // arguments
);

// result is 30
```

# Module.cwrap()

`Module.cwrap()`类似于`ccall()`，它调用一个编译后的 C 函数。然而，它不是返回一个值，而是返回一个 JavaScript 函数，可以根据需要重复使用。`Module.cwrap()`的函数签名如下：

```cpp
cwrap(ident, returnType, argTypes)
```

与`ccall()`一样，您可以指定代表`returnType`和`argTypes`参数的字符串值。在调用函数时，不能在`argTypes`中使用`"array"`类型，因为无法知道数组的长度。对于不返回值的函数，可以在`returnType`参数中使用`null`（不带引号）。

以下代码取自 Emscripten 网站，演示了如何使用`cwrap()`创建可重用的函数：

```cpp
// Call C from JavaScript
var c_javascript_add = Module.cwrap(
  'c_add', // name of C function
  'number', // return type
  ['number', 'number'] // argument types
);

// Call c_javascript_add normally
console.log(c_javascript_add(10, 20)); // 30
console.log(c_javascript_add(20, 30)); // 50
```

# C++和名称修饰

您可能已经注意到，`ccall()`和`cwrap()`的描述指出两者都用于调用编译后的 C 函数。故意省略了 C++，因为需要额外的步骤才能从 C++文件中调用函数。C++支持函数重载，这意味着可以多次使用相同的函数名称，但对每个函数传递不同的参数以获得不同的结果。以下是使用函数重载的一些代码示例：

```cpp
int addNumbers(int num1, int num2) {
    return num1 + num2;
}

int addNumbers(int num1, int num2, int num3) {
    return num1 + num2 + num3;
}

int addNumbers(int num1, int num2, int num3, int num4) {
    return num1 + num2 + num3 + num4;
}

// The function will return a value based on how many
// arguments you pass it:
int getSumOfTwoNumbers = addNumbers(1, 2);
// returns 3

int getSumOfThreeNumbers = addNumbers(1, 2, 3);
// returns 6

int getSumOfFourNumbers = addNumbers(1, 2, 3, 4);
// returns 10
```

编译器需要区分这些函数。如果它使用了名称`addNumbers`，并且您尝试在一个地方用两个参数调用该函数，在另一个地方用三个参数调用该函数，那么它将失败。要在编译后的 Wasm 中按名称调用函数，您需要将函数包装在`extern`块中。包装函数的一个影响是您必须明确为每个条件定义函数。以下代码片段演示了如何实现之前的函数而不进行名称混淆：

```cpp
extern "C" {
int addTwoNumbers(int num1, int num2) {
    return num1 + num2;
}

int addThreeNumbers(int num1, int num2, int num3) {
    return num1 + num2 + num3;
}

int addFourNumbers(int num1, int num2, int num3, int num4) {
    return num1 + num2 + num3 + num4;
}
}
```

# 从 WebAssembly 实例调用函数

我们在上一章中演示了如何从 JavaScript 中调用 Wasm 实例中的函数，但那是假设您在浏览器中实例化了一个模块而没有粘合代码。Emscripten 还提供了从 Wasm 实例调用函数的能力。在模块实例化后，您可以通过从已解析的`Promise`的结果中访问的`instance.exports`对象来调用函数。MDN 的文档为`WebAssembly.instantiateStreaming`提供了以下函数签名：

```cpp
Promise<ResultObject> WebAssembly.instantiateStreaming(source, importObject);
```

根据您的浏览器，您可能需要使用`WebAssembly.instantiate()`方法。Chrome 目前支持`WebAssembly.instantiateStreaming()`，但如果在尝试加载模块时遇到错误，请改用`WebAssembly.instantiate()`方法。

`ResultObject`包含我们需要引用的`instance`对象，以便从模块中调用导出的函数。以下是调用编译后的 Wasm 实例中名为`_addTwoNumbers`的函数的一些代码：

```cpp
// Assume the importObj is already defined.
WebAssembly.instantiateStreaming(
  fetch('simple.wasm'),
  importObj
)
  .then(result => {
    const addedNumbers = result.instance.exports._addTwoNumbers(1, 2);
    // result is 3
  });
```

Emscripten 提供了一种以类似的方式执行函数调用的方法，尽管实现略有不同。如果使用类似 Promise 的 API，您可以从`Module()`解析出的`asm`对象中访问函数。以下示例演示了如何利用这个功能：

```cpp
// Using Emscripten's Module
Module()
  .then(result => {
    // "asm" is essentially "instance"
    const exports = result.asm;
    const addedNumbers = exports._addTwoNumbers(1, 2);
    // result is 3
  });
```

使用 Emscripten 复制 WebAssembly 的 Web API 语法可以简化任何未来的重构。如果决定使用 WebAssembly 的 Web API，您可以轻松地将`Module()`替换为 WebAssembly 的`instantiateStreaming()`方法，并将`result.asm`替换为`result.instance`。

# 从 C/C++调用 JavaScript 函数

从 C/C++代码访问 JavaScript 的功能可以在使用 WebAssembly 时增加灵活性。在 Emscripten 的粘合代码和仅使用 Wasm 的实现之间，利用 JavaScript 的方法和手段有很大的不同。在本节中，我们将介绍您可以在 C/C++代码中集成 JavaScript 的各种方式，无论是否使用 Emscripten。

# 使用粘合代码与 JavaScript 交互

Emscripten 提供了几种将 JavaScript 与 C/C++代码集成的技术。可用的技术在实现和复杂性上有所不同，有些只适用于特定的执行环境（例如浏览器）。决定使用哪种技术取决于您的具体用例。我们将重点介绍`emscripten_run_script()`函数和使用`EM_*`包装器内联 JavaScript 的内容。以下部分的内容取自 Emscripten 网站的*与代码交互*部分，网址为[`kripken.github.io/emscripten-site/docs/porting/connecting_cpp_and_javascript/Interacting-with-code.html#interacting-with-code`](https://kripken.github.io/emscripten-site/docs/porting/connecting_cpp_and_javascript/Interacting-with-code.html#interacting-with-code)。

# 使用`emscripten_run_script()`执行字符串。

Emscripten 网站将`emscripten_run_script()`函数描述为调用 JavaScript 进行 C/C++的最直接但略慢的方法。这是一种非常适合单行 JavaScript 代码的技术，并且对于调试非常有用。文档说明它有效地使用`eval()`运行代码，`eval()`是一个执行字符串作为代码的 JavaScript 函数。以下代码取自 Emscripten 网站，演示了使用`emscripten_run_script()`调用浏览器的`alert()`函数并显示文本`'hi'`的方法：

```cpp
emscripten_run_script("alert('hi')");
```

对于性能是一个因素的更复杂的用例，使用*内联 JavaScript*提供了更好的解决方案。

# 使用 EM_ASM()执行内联 JavaScript()

您可以在 C/C++文件中使用`EM_ASM()`包装 JavaScript 代码，并在浏览器中运行编译后的代码时执行它。以下代码演示了基本用法：

```cpp
#include <emscripten.h>

int main() {
    EM_ASM(
        console.log('This is some JS code.');
    );
    return 0;
}
```

JavaScript 代码会立即执行，并且无法在包含它的 C/C++文件中重复使用。参数可以传递到 JavaScript 代码块中，其中它们作为变量`$0`，`$1`等到达。这些参数可以是`int32_t`或`double`类型。以下代码片段取自 Emscripten 网站，演示了如何在`EM_ASM()`块中使用参数：

```cpp
EM_ASM({
    console.log('I received: ' + [ $0, $1 ]);
}, 100, 35.5);
```

# 重用内联 JavaScript 与 EM_JS()

如果您需要在 C/C++文件中使用可重用的函数，可以将 JavaScript 代码包装在`EM_JS()`块中，并像普通的 C/C++函数一样执行它。`EM_JS()`的定义如下代码片段所示：

```cpp
EM_JS(return_type, function_name, arguments, code)
```

`return_type`参数表示与 JavaScript 代码输出对应的 C 类型（例如`int`或`float`）。如果从 JavaScript 代码中没有返回任何内容，请为`return_type`指定`void`。下一个参数`function_name`表示在从 C/C++文件的其他位置调用 JavaScript 代码时要使用的名称。`arguments`参数用于定义可以从 C 调用函数传递到 JavaScript 代码中的参数。`code`参数是用大括号括起来的 JavaScript 代码。以下代码片段取自 Emscripten 网站，演示了在 C 文件中使用`EM_JS()`的方法：

```cpp
#include <emscripten.h>

EM_JS(void, take_args, (int x, float y), {
    console.log(`I received ${x} and ${y}`);
});

int main() {
    take_args(100, 35.5);
    return 0;
}
```

# 使用粘合代码的示例

让我们编写一些代码来利用所有这些功能。在本节中，我们将修改我们在第五章中使用的代码，即*编译 C 而不使用粘合代码*和*获取和实例化 Wasm 文件*部分，*创建和加载 WebAssembly 模块*。这是显示在红色画布上移动的蓝色矩形的代码，并且可以通过单击按钮暂停和重新启动。本节的代码位于`learn-webassembly`存储库中的`/chapter-06-interact-with-js`文件夹中。让我们首先更新 C 代码。

# C 代码

在您的`/book-examples`文件夹中创建一个名为`/chapter-06-interact-with-js`的新文件夹。在`/chapter-06-interact-with-js`文件夹中创建一个名为`js-with-glue.c`的新文件，并填充以下内容：

```cpp
/*
 * This file interacts with the canvas through imported functions.
 * It moves a blue rectangle diagonally across the canvas
 * (mimics the SDL example).
 */
#include <emscripten.h>
#include <stdbool.h>

#define BOUNDS 255
#define RECT_SIDE 50
#define BOUNCE_POINT (BOUNDS - RECT_SIDE)

bool isRunning = true;

typedef struct Rect {
  int x;
  int y;
  char direction;
} Rect;

struct Rect rect;

/*
 * Updates the rectangle location by 1px in the x and y in a
 * direction based on its current position.
 */
void updateRectLocation() {
    // Since we want the rectangle to "bump" into the edge of the
    // canvas, we need to determine when the right edge of the
    // rectangle encounters the bounds of the canvas, which is why
    // we're using the canvas width - rectangle width:
    if (rect.x == BOUNCE_POINT) rect.direction = 'L';

    // As soon as the rectangle "bumps" into the left side of the
    // canvas, it should change direction again.
    if (rect.x == 0) rect.direction = 'R';

    // If the direction has changed based on the x and y
    // coordinates, ensure the x and y points update
    // accordingly:
    int incrementer = 1;
    if (rect.direction == 'L') incrementer = -1;
    rect.x = rect.x + incrementer;
    rect.y = rect.y + incrementer;
}

EM_JS(void, js_clear_rect, (), {
    // Clear the rectangle to ensure there's no color where it
    // was before:
    var canvas = document.querySelector('#myCanvas');
    var ctx = canvas.getContext('2d');
    ctx.fillStyle = '#ff0000';
    ctx.fillRect(0, 0, 255, 255);
});

EM_JS(void, js_fill_rect, (int x, int y, int width, int height), {
    // Fill the rectangle with blue in the specified coordinates:
    var canvas = document.querySelector('#myCanvas');
    var ctx = canvas.getContext('2d');
    ctx.fillStyle = '#0000ff';
    ctx.fillRect(x, y, width, height);
});

/*
 * Clear the existing rectangle element from the canvas and draw a
 * new one in the updated location.
 */
EMSCRIPTEN_KEEPALIVE
void moveRect() {
    // Event though the js_clear_rect doesn't have any
    // parameters, we pass 0 in to prevent a compiler warning:
    js_clear_rect(0);
    updateRectLocation();
    js_fill_rect(rect.x, rect.y, RECT_SIDE, RECT_SIDE);
}

EMSCRIPTEN_KEEPALIVE
bool getIsRunning() {
    return isRunning;
}

EMSCRIPTEN_KEEPALIVE
void setIsRunning(bool newIsRunning) {
    isRunning = newIsRunning;
    EM_ASM({
        // isRunning is either 0 or 1, but in JavaScript, 0
        // is "falsy", so we can set the status text based
        // without explicitly checking if the value is 0 or 1:
        var newStatus = $0 ? 'Running' : 'Paused';
        document.querySelector('#runStatus').innerHTML = newStatus;
    }, isRunning);
}

EMSCRIPTEN_KEEPALIVE
void init() {
    emscripten_run_script("console.log('Initializing rectangle...')");
    rect.x = 0;
    rect.y = 0;
    rect.direction = 'R';
    setIsRunning(true);
    emscripten_run_script("console.log('Rectangle should be moving!')");
}
```

您可以看到我们使用了 Emscripten 提供的所有三种 JavaScript 集成。有两个函数`js_clear_rect()`和`js_fill_rect()`，它们在`EM_JS()`块中定义，代替了原始示例中导入的函数。`setIsRunning()`函数中的`EM_ASM()`块更新了我们将添加到 HTML 代码中的新状态元素的文本。`emscripten_run_script()`函数只是简单地记录一些状态消息。我们需要在我们计划在模块外部使用的函数上方指定`EMSCRIPTEN_KEEPALIVE`。如果不指定这一点，编译器将把这些函数视为死代码并将其删除。

# HTML 代码

让我们在`/chapter-06-interact-with-js`文件夹中创建一个名为`js-with-glue.html`的文件，并填充以下内容：

```cpp
<!doctype html>
<html lang="en-us">
<head>
  <title>Interact with JS using Glue Code</title>
</head>
<body>
  <h1>Interact with JS using Glue Code</h1>
  <canvas id="myCanvas" width="255" height="255"></canvas>
  <div style="margin-top: 16px;">
    <button id="actionButton" style="width: 100px; height: 24px;">Pause</button>
    <span style="width: 100px; margin-left: 8px;">Status:</span>
    <span id="runStatus" style="width: 100px;"></span>
  </div>
  <script type="application/javascript" src="img/js-with-glue.js"></script>
  <script type="application/javascript">
    Module()
      .then(result => {
        const m = result.asm;
        m._init();

        // Move the rectangle by 1px in the x and y every 20 milliseconds:
        const loopRectMotion = () => {
          setTimeout(() => {
            m._moveRect();
            if (m._getIsRunning()) loopRectMotion();
          }, 20)
        };

        // Enable you to pause and resume the rectangle movement:
        document.querySelector('#actionButton')
          .addEventListener('click', event => {
            const newIsRunning = !m._getIsRunning();
            m._setIsRunning(newIsRunning);
            event.target.innerHTML = newIsRunning ? 'Pause' : 'Start';
            if (newIsRunning) loopRectMotion();
          });

        loopRectMotion();
      });
  </script>
</body>
</html>
```

我们添加了两个`<span>`元素来显示矩形移动的状态，以及相应的标签。我们使用 Emscripten 的类似 Promise 的 API 来加载模块并引用编译代码中的函数。我们不再将`_jsFillRect`和`_jsClearRect`函数传递给模块，因为我们在`js-with-glue.c`文件中处理了这个问题。

# 编译和提供结果

要编译代码，请确保你在`/chapter-06-interact-with-js`文件夹中，并运行以下命令：

```cpp
emcc js-with-glue.c -O3 -s WASM=1 -s MODULARIZE=1 -o js-with-glue.js
```

完成后，运行以下命令启动本地服务器：

```cpp
serve -l 8080
```

打开浏览器，转到`http://127.0.0.1:8080/js-with-glue.html`。你应该会看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/72e12623-7f8d-4d6a-8661-1f13822c1ef5.png)

在浏览器中运行胶水代码

如果你按下暂停按钮，按钮上的标题应该会变成开始，状态旁边的文本应该会变成暂停，矩形应该会停止移动。

# 无需胶水代码与 JavaScript 交互

在 C/C++文件中利用 JavaScript 代码遵循与 Emscripten 使用的技术不同的范例。你不是在 C/C++文件中编写 JavaScript，而是将函数传递到你的 WebAssembly 实例化代码中。在本节中，我们将更详细地描述这个过程。

# 使用导入对象将 JavaScript 传递给 C/C++

为了在你的 C/C++代码中利用 JavaScript 的功能，你需要向传递到 WebAssembly 实例化函数的`importObj.env`参数中添加一个函数定义。你可以在`importObj.env`之外或内联定义函数。以下代码片段演示了每个选项：

```cpp
// You can define the function inside of the env object:
const env = {
  // Make sure you prefix the function name with "_"!
  _logValueToConsole: value => {
    console.log(`'The value is ${value}'`);
  }
};

// Or define it outside of env and reference it within env:
const logValueToConsole = value => {
  console.log(`'The value is ${value}'`);
};

const env = {
  _logValueToConsole: logValueToConsole
};
```

考虑到 C、C++和 Rust 的手动内存管理和严格类型要求，你在 Wasm 模块中可以传递和利用的内容是有限的。JavaScript 允许你在代码执行过程中轻松地添加、删除和更改对象的属性值。你甚至可以通过向内置语言特性的`prototype`添加函数来扩展语言。C、C++和 Rust 更加严格，如果你不熟悉这些语言，要充分利用 WebAssembly 可能会很困难。

# 在 C/C++中调用导入的函数

你需要在使用`importObj.env`的 C/C++代码中定义你传递的 JavaScript 函数。函数签名必须与你传递的相匹配。以下示例更详细地演示了这一点。以下是与编译的 C 文件(`index.html`)交互的 JavaScript 代码：

```cpp
// index.html <script> contents
const env = {
  _logAndMultiplyTwoNums: (num1, num2) => {
    const result = num1 * num2;
    console.log(result);
    return result;
  },
};

loadWasm('main.wasm', { env })
  .then(({ instance }) => {
    const result = instance.exports._callMultiply(5.5, 10);
    console.log(result);
    // 55 is logged to the console twice
  });
```

这是`main.c`的内容，它被编译为`main.wasm`并在`index.html`中使用：

```cpp
// main.c (compiled to main.wasm)
extern float logAndMultiplyTwoNums(float num1, float num2);

float callMultiply(float num1, float num2) {
    return logAndMultiplyTwoNums(num1, num2);
}
```

你调用 C/C++中的 JavaScript 函数的方式与调用普通的 C/C++函数相同。虽然当你将它传递到`importObj.env`时，你需要在你的函数前加上`_`，但在 C/C++文件中定义时，你不需要包括前缀。

# 一个没有胶水代码的例子

来自第五章的*编译不使用胶水代码的 C*和*获取和实例化 Wasm 文件*部分的示例代码演示了如何在我们的 C 文件中集成 JavaScript 而不使用 Emscripten 的胶水代码。在本节中，我们将稍微修改示例代码，并将文件类型更改为 C++。

# C++代码

在你的`/chapter-06-interact-with-js`文件夹中创建一个名为`js-without-glue.cpp`的文件，并填充以下内容：

```cpp
/*
 * This file interacts with the canvas through imported functions.
 * It moves a circle diagonally across the canvas.
 */
#define BOUNDS 255
#define CIRCLE_RADIUS 50
#define BOUNCE_POINT (BOUNDS - CIRCLE_RADIUS)

bool isRunning = true;

typedef struct Circle {
  int x;
  int y;
  char direction;
} Circle;

struct Circle circle;

/*
 * Updates the circle location by 1px in the x and y in a
 * direction based on its current position.
 */
void updateCircleLocation() {
    // Since we want the circle to "bump" into the edge of the canvas,
    // we need to determine when the right edge of the circle
    // encounters the bounds of the canvas, which is why we're using
    // the canvas width - circle width:
    if (circle.x == BOUNCE_POINT) circle.direction = 'L';

    // As soon as the circle "bumps" into the left side of the
    // canvas, it should change direction again.
    if (circle.x == CIRCLE_RADIUS) circle.direction = 'R';

    // If the direction has changed based on the x and y
    // coordinates, ensure the x and y points update accordingly:
    int incrementer = 1;
    if (circle.direction == 'L') incrementer = -1;
    circle.x = circle.x + incrementer;
    circle.y = circle.y - incrementer;
}

// We need to wrap any imported or exported functions in an
// extern block, otherwise the function names will be mangled.
extern "C" {
// These functions are passed in through the importObj.env object
// and update the circle on the <canvas>:
extern int jsClearCircle();
extern int jsFillCircle(int x, int y, int radius);

/*
 * Clear the existing circle element from the canvas and draw a
 * new one in the updated location.
 */
void moveCircle() {
    jsClearCircle();
    updateCircleLocation();
    jsFillCircle(circle.x, circle.y, CIRCLE_RADIUS);
}

bool getIsRunning() {
    return isRunning;
}

void setIsRunning(bool newIsRunning) {
    isRunning = newIsRunning;
}

void init() {
    circle.x = 0;
    circle.y = 255;
    circle.direction = 'R';
    setIsRunning(true);
}
}
```

这段代码与之前的例子类似，但画布上元素的形状和方向已经改变。现在，元素是一个圆，从画布的左下角开始，沿对角线向右上移动。

# HTML 代码

接下来，在你的`/chapter-06-interact-with-js`文件夹中创建一个名为`js-without-glue.html`的文件，并填充以下内容：

```cpp
<!doctype html>
<html lang="en-us">
<head>
  <title>Interact with JS without Glue Code</title>
  <script
    type="application/javascript"
    src="img/load-wasm.js">
  </script>
  <style>
    #myCanvas {
      border: 2px solid black;
    }
    #actionButtonWrapper {
      margin-top: 16px;
    }
    #actionButton {
      width: 100px;
      height: 24px;
    }
  </style>
</head>
<body>
  <h1>Interact with JS without Glue Code</h1>
  <canvas id="myCanvas" width="255" height="255"></canvas>
  <div id="actionButtonWrapper">
    <button id="actionButton">Pause</button>
  </div>
  <script type="application/javascript">
    const canvas = document.querySelector('#myCanvas');
    const ctx = canvas.getContext('2d');

    const fillCircle = (x, y, radius) => {
      ctx.fillStyle = '#fed530';
      // Face outline:
      ctx.beginPath();
      ctx.arc(x, y, radius, 0, 2 * Math.PI);
      ctx.fill();
      ctx.stroke();
      ctx.closePath();

      // Eyes:
      ctx.fillStyle = '#000000';
      ctx.beginPath();
      ctx.arc(x - 15, y - 15, 6, 0, 2 * Math.PI);
      ctx.arc(x + 15, y - 15, 6, 0, 2 * Math.PI);
      ctx.fill();
      ctx.closePath();

      // Mouth:
      ctx.beginPath();
      ctx.moveTo(x - 20, y + 10);
      ctx.quadraticCurveTo(x, y + 30, x + 20, y + 10);
      ctx.lineWidth = 4;
      ctx.stroke();
      ctx.closePath();
    };

    const env = {
      table: new WebAssembly.Table({ initial: 8, element: 'anyfunc' }),
      _jsFillCircle: fillCircle,
      _jsClearCircle: function() {
        ctx.fillStyle = '#fff';
        ctx.fillRect(0, 0, 255, 255);
      },
    };

    loadWasm('js-without-glue.wasm', { env }).then(({ instance }) => {
      const m = instance.exports;
      m._init();

      // Move the circle by 1px in the x and y every 20 milliseconds:
      const loopCircleMotion = () => {
        setTimeout(() => {
          m._moveCircle();
          if (m._getIsRunning()) loopCircleMotion();
        }, 20)
      };

      // Enable you to pause and resume the circle movement:
      document.querySelector('#actionButton')
        .addEventListener('click', event => {
          const newIsRunning = !m._getIsRunning();
          m._setIsRunning(newIsRunning);
          event.target.innerHTML = newIsRunning ? 'Pause' : 'Start';
          if (newIsRunning) loopCircleMotion();
        });

      loopCircleMotion();
    });
  </script>
</body>
</html>
```

我们可以使用 canvas 元素的 2D 上下文上可用的函数手动绘制路径，而不是使用`rect()`元素。

# 编译和提供结果

我们只生成了一个 Wasm 模块，因此可以使用我们在上一章中设置的构建任务来编译我们的代码。选择任务 | 运行构建任务...或使用键盘快捷键*Ctrl*/*Cmd* + *Shift* + *B*来编译代码。如果您不使用 VS Code，请在`/chapter-06-interact-with-js`文件夹中打开 CLI 实例并运行以下命令：

```cpp
emcc js-without-glue.cpp -Os -s WASM=1 -s SIDE_MODULE=1 -s BINARYEN_ASYNC_COMPILATION=0 -o js-without-glue.wasm
```

完成后，在`/book-examples`文件夹中打开终端，并运行以下命令启动本地服务器：

```cpp
serve -l 8080
```

打开浏览器并导航到`http://127.0.0.1:8080/chapter-06-interact-with-js/js-without-glue.html`。您应该会看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/c981ffdb-10a6-4d61-b87c-fdfa19ce9d83.png)

在浏览器中运行的 Wasm 模块，无需粘合代码

与之前的示例一样，如果按下暂停按钮，则按钮上的标题应更改为开始，并且圆圈应停止移动。

# 高级 Emscripten 功能

我们在前面的部分中介绍了我们将在 JavaScript 和 C/C++之间频繁使用的 Emscripten 功能，但这并不是 Emscripten 提供的唯一功能。还有一些高级功能和额外的 API，您需要了解，特别是如果您计划向应用程序添加更复杂的功能。在本节中，我们将简要介绍一些这些高级功能，并提供有关您可以了解更多信息的详细信息。

# Embind

Embind 是 Emscripten 提供的用于连接 JavaScript 和 C++的附加功能。Emscripten 的网站提供了以下描述：

"Embind 用于将 C++函数和类绑定到 JavaScript，以便编译后的代码可以被'普通'JavaScript 以自然的方式使用。Embind 还支持从 C++调用 JavaScript 类。"

Embind 是一个强大的功能，允许 JavaScript 和 C++之间进行紧密集成。您可以将一些 C++代码包装在`EMSCRIPTEN_BINDINGS()`块中，并通过浏览器中的`Module`对象引用它。让我们看一个来自 Emscripten 网站的例子。以下文件`example.cpp`使用`emcc`的`--bind`标志编译：

```cpp
// example.cpp
#include <emscripten/bind.h>

using namespace emscripten;

float lerp(float a, float b, float t) {
    return (1 - t) * a + t * b;
}

EMSCRIPTEN_BINDINGS(my_module) {
    function("lerp", &lerp);
}
```

生成的模块在`example.html`中加载，并调用`lerp()`函数：

```cpp
<!-- example.html -->
<!doctype html>
<html>
<script src="img/example.js"></script>
<script>
  // example.js was generated by running this command:
  // emcc --bind -o example.js example.cpp
  console.log('lerp result: ' + Module.lerp(1, 2, 0.5));
</script>
</html>
```

上述示例仅代表 Embind 功能的一小部分。您可以在[`kripken.github.io/emscripten-site/docs/porting/connecting_cpp_and_javascript/embind.html`](https://kripken.github.io/emscripten-site/docs/porting/connecting_cpp_and_javascript/embind.html)了解更多关于 Embind 的信息。

# 文件系统 API

Emscripten 通过使用 FS 库提供对文件操作的支持，并公开了一个用于处理文件系统的 API。但是，默认情况下在编译项目时不会包含它，因为它可能会显著增加文件的大小。如果您的 C/C++代码使用文件，该库将自动添加。文件系统类型根据执行环境而异。例如，如果在 worker 内运行代码，则可以使用`WORKERFS`文件系统。默认情况下使用`MEMFS`，它将数据存储在内存中，当页面重新加载时，内存中的任何数据都将丢失。您可以在[`kripken.github.io/emscripten-site/docs/api_reference/Filesystem-API.html#filesystem-api`](https://kripken.github.io/emscripten-site/docs/api_reference/Filesystem-API.html#filesystem-api)阅读有关文件系统 API 的更多信息。

# Fetch API

Emscripten 还提供了 Fetch API。以下内容摘自文档：

"Emscripten Fetch API 允许本机代码通过 XHR（HTTP GET、PUT、POST）从远程服务器传输文件，并将下载的文件持久存储在浏览器的 IndexedDB 存储中，以便可以在随后的页面访问中本地重新访问。Fetch API 可以从多个线程调用，并且可以根据需要同步或异步运行网络请求。"

Fetch API 可用于与 Emscripten 的其他功能集成。如果您需要获取 Emscripten 未使用的数据，应使用浏览器的 Fetch API ([`developer.mozilla.org/en-US/docs/Web/API/Fetch_API`](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API))。您可以在[`kripken.github.io/emscripten-site/docs/api_reference/fetch.html`](https://kripken.github.io/emscripten-site/docs/api_reference/fetch.html)上了解有关 Fetch API 的更多信息。

# 在浏览器中调试

在浏览器中有效地调试 JavaScript 代码并不总是容易的。然而，浏览器和具有内置调试功能的编辑器/IDE 的开发工具已经显著改进。不幸的是，将 WebAssembly 添加到 Web 应用程序会给调试过程增加额外的复杂性。在本节中，我们将回顾一些调试 JavaScript 并利用 Wasm 的技术，以及 Emscripten 提供的一些额外功能。

# 高级概述

调试 Emscripten 的`Module`相对比较简单。Emscripten 的错误消息形式良好且描述清晰，因此通常您会立即发现问题的原因。您可以在浏览器的开发工具控制台中查看这些消息。

如果在运行`emcc`命令时指定了`.html`输出，一些调试代码将已经内置（`Module.print`和`Module.printErr`）。在 HTML 文件中，加载代码设置了`window.onerror`事件来调用`Module.printErr`事件，因此您可以查看加载时发生的错误的详细信息。

您可能会遇到的一个常见错误是调用错误的函数名称。如果您正在使用 Emscripten 的类似 Promise 的 API，可以通过在浏览器控制台中运行以下代码来打印出可用的函数：

```cpp
console.log(Module().asm);
```

以下屏幕截图显示了我们在本章的*从 C/C++调用 JavaScript 函数*部分中使用的`js-with-glue.js`示例的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/7a85c9a2-9f60-48eb-b1d1-196d77f5e9f8.png)

在浏览器控制台中记录`Module().asm`的内容

您的函数以及 Emscripten 生成的一些函数将以`_`为前缀。编写可编译的代码的优势在于编译器将在前期捕获大多数错误。鉴于 C 和 C++等语言可用的广泛工具，您应该能够快速理解和解决这些错误。

如果您没有使用任何粘合代码，并且使用 WebAssembly 的 JavaScript 和 Web API 实例化 Wasm 文件，则调试可能会变得更加复杂。正如之前所述，您有优势可以在 C 或 C++代码的编译时捕获大多数错误。与 Emscripten 一样，浏览器开发工具控制台中打印出的错误消息提供了堆栈跟踪和相对清晰的问题描述。然而，如果您正在解决一个特别棘手的错误，记录到控制台可能会变得繁琐和难以管理。幸运的是，您可以使用源映射来提高调试能力。

# 使用源映射

Emscripten 有能力通过向编译器传递一些额外的标志来生成源映射。源映射允许浏览器将文件的源映射到应用程序中使用的文件。例如，您可以使用 JavaScript 构建工具（如 Webpack）在构建过程中对代码进行缩小。但是，如果您试图查找错误，导航和调试缩小的代码将变得非常困难。通过生成源映射，您可以在浏览器的开发工具中查看原始形式的代码，并设置断点进行调试。让我们为我们的`/chapter-06-interact-with-js/js-without-glue.cpp`文件生成一个源映射。在`/book-examples`文件夹中，在终端中运行以下命令：

```cpp
emcc chapter-06-interact-with-js/js-without-glue.cpp -O1 -g4 -s WASM=1 -s SIDE_MODULE=1 -s BINARYEN_ASYNC_COMPILATION=0 -o chapter-06-interact-with-js/js-without-glue.wasm --source-map-base http://localhost:8080/chapter-06-interact-with-js/
```

`-g4`参数启用源映射，而`--source-map-base`参数告诉浏览器在哪里找到源映射文件。编译后，通过运行以下命令从`/book-examples`文件夹启动本地服务器：

```cpp
serve -l 8080
```

转到`http://127.0.0.1:8080/chapter-06-interact-with-js/js-without-glue.html`，打开开发者工具，并选择源标签（在 Chrome 中）或调试器标签（在 Firefox 中）。如果您使用 Chrome，您应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/ccc8b38d-f748-40fb-8d25-667dc176c0ff.png)

Chrome 开发者工具中的 Wasm 源映射

正如您所看到的，文件名并不是很有帮助。每个文件应该在顶部包含函数名称，尽管其中一些名称可能已经被搅乱。如果遇到错误，您可以设置断点，Chrome 的调试功能允许您导航调用堆栈。Firefox 以不同的方式处理它们的源映射。以下截图显示了 Firefox 的开发者工具中的调试器视图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/d40de2b0-f550-4e74-bbac-4249f1693ec4.png)

Firefox 开发者工具中的 Wasm 源映射

源映射是一个包含 Wasm 文件的 Wat 表示的单个文件。您也可以在这里设置断点和调试代码。随着 WebAssembly 的发展，将会有更多（和更好）的工具可用。与此同时，记录到控制台和利用源映射是您可以使用的当前调试方法。

# 总结

在本章中，我们专注于 JavaScript 和 C/C++之间的互联，Emscripten 提供的一些功能，以及如何有效地调试在浏览器中使用 Wasm 的 Web 应用程序。我们回顾了从 JavaScript 调用编译后的 C/C++函数的各种方法，以及如何将 JavaScript 与您的 C/C++代码集成。Emscripten 的 API 被提出作为一种理解如何通过在编译后的 Wasm 文件中包含粘合代码来克服 WebAssembly 当前限制的方法。即使 Emscripten 提供的功能不在官方的 WebAssembly *Core Specification*中（也许永远不会），这也不应该阻止您利用它们。最后，我们简要介绍了如何在浏览器中调试 Wasm 文件，以及 Emscripten 模块或 WebAssembly 实例的上下文。

在下一章中，我们将从头开始构建一个真实的 WebAssembly 应用程序。

# 问题

1.  您用于与浏览器中的编译代码交互的`Module`对象上的两个函数的名称是什么？

1.  您需要用什么来包装您的 C++代码，以确保函数名称不会被搅乱？

1.  `EM_ASM()`和`EM_JS()`之间有什么区别？

1.  `emscripten_run_script()`和`EM_ASM()`/`EM_JS()`中哪个更有效？

1.  如果您想在 C/C++代码之外使用它，您需要在函数上面的行中包含什么（提示：它以`EMSCRIPTEN`开头）？

1.  在哪里可以定义需要传递到`importObj.env`对象中的函数，当实例化模块时？

1.  Emscripten 提供了哪些额外的 API？

1.  源映射的目的是什么？

# 进一步阅读

+   Emscripten API 参考：[`kripken.github.io/emscripten-site/docs/api_reference/index.html`](http://kripken.github.io/emscripten-site/docs/api_reference/index.html)

+   源映射简介：[`blog.teamtreehouse.com/introduction-source-maps`](http://blog.teamtreehouse.com/introduction-source-maps)

+   使用浏览器调试 WebAssembly：[`webassemblycode.com/using-browsers-debug-webassembly`](http://webassemblycode.com/using-browsers-debug-webassembly)


# 第七章：从头开始创建一个应用程序

现在是应用你的知识的时候了！由于 WebAssembly 的主要设计目标之一是在现有的 Web 平台内执行并与之很好地集成，因此构建一个 Web 应用程序来测试它是有意义的。即使 WebAssembly 的当前功能集相当有限，我们仍然可以在基本水平上利用这项技术。在本章中，我们将从头开始构建一个单页应用程序，该应用程序在*核心规范*的上下文中利用 Wasm 模块。

在本章结束时，您将知道如何：

+   编写使用 C 执行简单计算的函数

+   使用 Vue 构建一个基本的 JavaScript 应用程序

+   将 Wasm 集成到您的 JavaScript 应用程序中

+   确定 WebAssembly 在当前形式下的能力和限制

+   使用`browser-sync`运行和测试 JavaScript 应用程序

# Cook the Books – 使 WebAssembly 负责

如前所述，WebAssembly 的当前功能集相当有限。我们可以使用 Emscripten 大大扩展 Web 应用程序的功能，但这会带来与官方规范的不兼容以及添加粘合代码的成本。我们仍然可以有效地使用 WebAssembly，这就是我们将在本章中构建的应用程序。在本节中，我们将回顾构建应用程序所使用的库和工具，以及其功能的简要概述。

# 概述和功能

在 WebAssembly 的当前形式中，我们可以相对容易地在 Wasm 模块和 JavaScript 代码之间传递数字。在现实世界中，会计应用程序似乎是一个合乎逻辑的选择。我对会计软件唯一的争议是它有点无聊（无意冒犯）。我们将通过一些不道德的会计实践来*调味*一下。该应用程序被命名为*Cook the Books*，这是与会计欺诈相关的术语。Investopedia 提供了对 Cook the Books 的以下定义：

"Cook the Books 是一个成语，用来描述公司为了伪造其财务报表而进行的欺诈活动。通常，Cook the Books 涉及增加财务数据以产生以前不存在的收益。用于 Cook the Books 的技术示例包括加速收入，延迟支出，操纵养老金计划以及实施合成租赁。"

Investopedia 页面[`www.investopedia.com/terms/c/cookthebooks.asp`](https://www.investopedia.com/terms/c/cookthebooks.asp)提供了构成 Cook the Books 的详细示例。我们将为我们的应用程序采取简单的方法。我们将允许用户输入一个交易，包括原始金额和虚假金额。原始金额代表实际存入或取出的金额，而虚假金额是其他人看到的金额。该应用程序将生成显示原始或虚假交易的按类别显示支出和收入的饼图。用户可以轻松地在两种视图之间切换。该应用程序包括以下组件：

+   用于在交易和图表之间切换的选项卡

+   显示交易的表格

+   允许用户添加、编辑或删除交易的按钮

+   用于添加/更新交易的模态对话框

+   显示按类别的收入/支出的饼图

# 使用的 JavaScript 库

应用程序的 JavaScript 部分将使用从 CDN 提供的几个库。它还将使用一个本地安装的库来监视代码的更改。以下各节将描述每个库及其在应用程序中的目的。

# Vue

Vue 是一个 JavaScript 框架，允许您将应用程序拆分为单独的组件，以便于开发和调试。我们使用它来避免一个包含所有应用程序逻辑的单片 JavaScript 文件和另一个包含整个 UI 的单片 HTML 文件。选择 Vue 是因为它不需要构建系统的额外复杂性，并且允许我们在不进行任何转换的情况下使用 HTML、CSS 和 JavaScript。官方网站是[`vuejs.org`](https://vuejs.org)。

# UIkit

UIkit 是我们将用来为应用程序添加样式和布局的前端框架。有数十种替代方案，如 Bootstrap 或 Bulma，它们提供了类似的组件和功能。但我选择了 UIkit，因为它具有有用的实用类和附加的 JavaScript 功能。您可以在[`getuikit.com`](https://getuikit.com)上查看文档。

# Lodash

Lodash 是一个出色的实用程序库，提供了在 JavaScript 中执行常见操作的方法，这些方法在语言中尚未内置。我们将使用它来执行计算和操作交易数据。文档和安装说明可以在[`lodash.com`](https://lodash.com)找到。

# 数据驱动文档

**数据驱动文档**（**D3**）是一个多功能库，允许您将数据转化为令人印象深刻的可视化效果。D3 的 API 由几个模块组成，从数组操作到图表和过渡。我们将主要使用 D3 来创建饼图，但我们也将利用它提供的一些实用方法。您可以在[`d3js.org`](https://d3js.org)找到更多信息。

# 其他库

为了以正确的格式显示货币值并确保用户输入有效的美元金额，我们将利用**accounting.js**（[`openexchangerates.github.io/accounting.js`](http://openexchangerates.github.io/accounting.js)）和**vue-numeric**（[`kevinongko.github.io/vue-numeric`](https://kevinongko.github.io/vue-numeric)）库。为了简化开发，我们将设置一个基本的`npm`项目，并使用**browser-sync** （[`www.browsersync.io`](https://www.browsersync.io)）来立即看到运行应用程序中的代码更改。

# C 和构建过程

该应用程序使用 C，因为我们正在进行基本代数的简单计算。在这种情况下使用 C++是没有意义的。这将引入一个额外的步骤，确保我们需要从 JavaScript 调用的函数被包装在`extern`块中。我们将在一个单独的 C 文件中编写计算函数，并将其编译成一个单独的 Wasm 模块。我们可以继续使用 VS Code 的任务功能来执行构建，但是参数将需要更新，因为我们只编译一个文件。让我们继续进行项目配置。

# 项目设置

WebAssembly 还没有存在足够长的时间来建立关于文件夹结构、文件命名约定等方面的最佳实践。如果您搜索 C/C++或 JavaScript 项目的最佳实践，您会遇到大量相互矛盾的建议和坚定的观点。考虑到这一点，让我们在本节中花时间设置我们的项目所需的配置文件。

该项目的代码位于`learn-webassembly`存储库中的`/chapter-07-cook-the-books`文件夹中。当我们进行应用程序的 JavaScript 部分时，您必须拥有此代码。我不会提供书中所有 Vue 组件的源代码，因此您需要从存储库中复制它们。

# 为 Node.js 配置

为了尽可能保持应用程序的简单性，我们将避免使用 Webpack 或 Rollup.js 等构建/捆绑工具。这样可以减少所需的依赖项数量，并确保您遇到的任何问题都不是由构建依赖项的重大更改引起的。

我们将创建一个 Node.js 项目，因为它允许我们运行脚本并为开发目的本地安装依赖项。到目前为止，我们使用了`/book-examples`文件夹，但我们将在`/book-examples`之外创建一个新的项目文件夹，以配置 VS Code 中不同的默认构建任务。打开终端，`cd`到所需的文件夹，并输入以下命令：

```cpp
// Create a new directory and cd into it:
mkdir cook-the-books
cd cook-the-books

// Create a package.json file with default values
npm init -y
```

`-y`命令跳过提示，并使用合理的默认值填充`package.json`文件。完成后，运行以下命令安装`browser-sync`：

```cpp
npm install -D browser-sync@².24.4
```

`-D`是可选的，表示该库是开发依赖项。如果您正在构建和分发应用程序，您将使用`-D`标志，因此我包含它以遵循常见做法。我建议安装特定版本以确保`start`脚本可以正常运行。安装完`browser-sync`后，将以下条目添加到`package.json`文件中的`scripts`条目中：

```cpp
...
"scripts": {
 ...
 "start": "browser-sync start --server \"src\" --files \"src/**\" --single --no-open --port 4000"
},
…
```

如果您使用`-y`标志运行`npm init`，应该会有一个名为`test`的现有脚本，为了清晰起见，我省略了它。如果您没有使用`-y`标志运行它，您可能需要创建`scripts`条目。

如果需要，您可以填写`"description"`和`"author"`键。文件最终应该看起来类似于这样：

```cpp
{
  "name": "cook-the-books",
  "version": "1.0.0",
  "description": "Example application for Learn WebAssembly",
  "main": "src/index.js",
  "scripts": {
    "start": "browser-sync start --server \"src\" --files \"src/**\" --single --no-open --port 4000",
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "keywords": [],
  "author": "Mike Rourke",
  "license": "MIT",
  "devDependencies": {
    "browser-sync": "².24.4"
  }
}
```

如果您从`start`脚本中省略了`--no-open`标志，浏览器将自动打开。该标志被包含在其中以防止用户在无头环境中运行时出现问题。

# 添加文件和文件夹

在根文件夹中创建两个新文件夹：`/lib`和`/src`。JavaScript、HTML、CSS 和 Wasm 文件将位于`/src`文件夹中，而 C 文件将位于`/lib`文件夹中。我只想在`/src`中包含 Web 应用程序使用的文件。我们永远不会直接从应用程序中使用 C 文件，只会使用编译后的输出。

将`/book-examples`项目中的`/.vscode`文件夹复制到根文件夹中。这将确保您使用现有的 C/C++设置，并为构建任务提供一个良好的起点。

如果您使用的是 macOS 或 Linux，您将需要使用终端来复制文件夹；您可以通过运行`cp -r`命令来实现这一点。

# 配置构建步骤

我们需要修改`/.vscode/tasks.json`文件中的默认构建步骤，以适应我们更新后的工作流。我们在`/book-examples`项目中使用的构建步骤的参数允许我们编译当前在编辑器中活动的任何文件。它还将`.wasm`文件输出到与源 C 文件相同的文件夹中。然而，这个配置对于这个项目来说是没有意义的。我们将始终编译相同的 C 文件，并将输出到特定文件夹中的编译后的`.wasm`文件。为了实现这一点，在`/.vscode/tasks.json`中的`Build`任务的`args`数组中更新为以下内容：

```cpp
"args": [
  "${workspaceFolder}/lib/main.c",
  "-Os",
  "-s", "WASM=1",
  "-s", "SIDE_MODULE=1",
  "-s", "BINARYEN_ASYNC_COMPILATION=0",
  "-o", "${workspaceFolder}/src/assets/main.wasm"
],
```

我们更改了输入和输出路径，它们是`args`数组中的第一个和最后一个元素。现在两者都是静态路径，无论打开的是哪个文件，都会编译和输出相同的文件。

# 设置模拟 API

我们需要一些模拟数据和一种持久化任何更新的方法。如果您将数据存储在本地的 JSON 文件中，那么您对交易所做的任何更改都将在刷新页面后丢失。我们可以使用 Express 这样的库来设置一个本地服务器，模拟一个数据库，编写路由等等。但是，相反地，我们将利用在线可用的优秀开发工具。在线工具 jsonstore.io 允许您为小型项目存储 JSON 数据，并提供开箱即用的端点。按照以下步骤来启动和运行您的模拟 API：

1.  转到[`www.jsonstore.io/`](https://www.jsonstore.io/)并点击复制按钮将端点复制到剪贴板；这是您将发出 HTTP 请求的端点。

1.  转到 JSFiddle 网站[`jsfiddle.net/mikerourke/cta0km6d`](https://jsfiddle.net/mikerourke/cta0km6d)，将您的 jsonstore.io 端点粘贴到输入中，然后按“填充数据”按钮。

1.  打开一个新标签，并在地址栏中粘贴您的 jsonstore.io 端点，然后在 URL 的末尾添加`/transactions`，然后按*Enter*。如果您在浏览器中看到 JSON 文件的内容，则 API 设置成功。

将 jsonstore.io 端点保持方便——在构建应用程序的 JavaScript 部分时会用到它。

# 下载 C stdlib Wasm

我们需要 C 标准库中的`malloc()`和`free()`函数来实现我们 C 代码中的功能。WebAssembly 没有内置这些函数，因此我们需要提供自己的实现。

幸运的是，有人已经为我们构建了这个；我们只需要下载模块并将其包含在实例化步骤中。该模块可以从 Guy Bedford 的`wasm-stdlib-hack` GitHub 存储库[`github.com/guybedford/wasm-stdlib-hack`](https://github.com/guybedford/wasm-stdlib-hack)中下载。您需要从`/dist`文件夹中下载`memory.wasm`文件。下载文件后，在项目的`/src`文件夹中创建一个名为`/assets`的文件夹，并将`memory.wasm`文件复制到其中。

您可以从`learn-webassembly`存储库的`/chapter-07-cook-the-books/src/assets`文件夹中复制`memory.wasm`文件，而不是从 GitHub 上下载它。

# 最终结果

执行这些步骤后，您的项目应如下所示：

```cpp
├── /.vscode
│    ├── tasks.json
│    └── c_cpp_properties.json
├── /lib
├── /src
│    └── /assets
│         └── memory.wasm
├── package.json
└── package-lock.json
```

# 构建 C 部分

应用程序的 C 部分将聚合交易和类别金额。我们在 C 中执行的计算可以很容易地在 JavaScript 中完成，但 WebAssembly 非常适合计算。我们将在第八章《使用 Emscripten 移植游戏》中深入探讨 C/C++的更复杂用法，但现在我们试图限制我们的范围，以符合“核心规范”的限制。在本节中，我们将编写一些 C 代码，以演示如何在不使用 Emscripten 的情况下将 WebAssembly 与 Web 应用程序集成。

# 概述

我们将编写一些 C 函数，用于计算原始和烹饪交易的总额以及结余。除了计算总额外，我们还需要计算每个类别的总额，以在饼图中显示。所有这些计算将在单个 C 文件中执行，并编译为单个 Wasm 文件，该文件将在应用程序加载时实例化。对于未经培训的人来说，C 可能有点令人生畏，因此为了清晰起见，我们的代码将牺牲一些效率。我想抽出一点时间向阅读本书的 C/C++程序员道歉；你们可能不会喜欢你们所看到的 C 代码。

为了动态执行计算，我们需要在添加和删除交易时分配和释放内存。为此，我们将使用**双向链表**。双向链表是一种数据结构，允许我们在列表内部删除项目或*节点*，并根据需要添加和编辑节点。节点使用`malloc()`添加，使用`free()`删除，这两者都是在上一节中下载的`memory.wasm`模块提供的。

# 关于工作流程的说明

开发操作的顺序并不反映通常构建使用 WebAssembly 的应用程序的方式。工作流程将包括在 C/C++和 JavaScript 之间跳转，以实现所需的结果。在这种情况下，我们从 JavaScript 中转移到 WebAssembly 的功能已经知道，因此我们将首先编写 C 代码。

# C 文件内容

让我们逐个讨论 C 文件的每个部分。在`/lib`文件夹中创建一个名为`main.c`的文件，并在每个部分中填充以下内容。如果我们将其分成较小的块，那么更容易理解 C 文件中发生的事情。让我们从*声明*部分开始。

# 声明

第一部分包含我们将用于创建和遍历双向链表的声明，如下所示：

```cpp
#include <stdlib.h>

struct Node {
  int id;
  int categoryId;
  float rawAmount;
  float cookedAmount;
  struct Node *next;
  struct Node *prev;
};

typedef enum {
  RAW = 1,
  COOKED = 2
} AmountType;

struct Node *transactionsHead = NULL;
struct Node *categoriesHead = NULL;
```

`Node`结构用于表示交易或类别。`transactionsHead`和`categoriesHead`节点实例表示我们将使用的每个链表中的第一个节点（一个用于交易，一个用于类别）。`AmountType`枚举不是必需的，但当我们到达使用它的代码部分时，我们将讨论它的用途。

# 链表操作

第二部分包含用于向链表中添加和删除节点的两个函数：

```cpp
void deleteNode(struct Node **headNode, struct Node *delNode) {
    // Base case:
    if (*headNode == NULL || delNode == NULL) return;

    // If node to be deleted is head node:
    if (*headNode == delNode) *headNode = delNode->next;

    // Change next only if node to be deleted is NOT the last node:
    if (delNode->next != NULL) delNode->next->prev = delNode->prev;

    // Change prev only if node to be deleted is NOT the first node:
    if (delNode->prev != NULL) delNode->prev->next = delNode->next;

    // Finally, free the memory occupied by delNode:
    free(delNode);
}

void appendNode(struct Node **headNode, int id, int categoryId,
                float rawAmount, float cookedAmount) {
    // 1\. Allocate node:
    struct Node *newNode = (struct Node *) malloc(sizeof(struct Node));
    struct Node *last = *headNode; // Used in Step 5

    // 2\. Populate with data:
    newNode->id = id;
    newNode->categoryId = categoryId;
    newNode->rawAmount = rawAmount;
    newNode->cookedAmount = cookedAmount;

    // 3\. This new node is going to be the last node, so make next NULL:
    newNode->next = NULL;

    // 4\. If the linked list is empty, then make the new node as head:
    if (*headNode == NULL) {
        newNode->prev = NULL;
        *headNode = newNode;
        return;
    }

    // 5\. Otherwise, traverse till the last node:
    while (last->next != NULL) {
        last = last->next;
    }

    // 6\. Change the next of last node:
    last->next = newNode;

    // 7\. Make last node as previous of new node:
    newNode->prev = last;
}
```

代码中的注释描述了每个步骤发生的情况。当我们需要向列表中添加一个节点时，我们必须使用`malloc()`分配`struct` `Node`占用的内存，并将其附加到链表中的最后一个节点。如果我们需要删除一个节点，我们必须从链表中删除它，并通过调用`free()`函数释放节点使用的内存。

# 交易操作

第三部分包含用于向`transactions`链表中添加、编辑和删除交易的函数，如下所示：

```cpp
struct Node *findNodeById(int id, struct Node *withinNode) {
    struct Node *node = withinNode;
    while (node != NULL) {
        if (node->id == id) return node;
        node = node->next;
    }
    return NULL;
}

void addTransaction(int id, int categoryId, float rawAmount,
                    float cookedAmount) {
    appendNode(&transactionsHead, id, categoryId, rawAmount, cookedAmount);
}

void editTransaction(int id, int categoryId, float rawAmount,
                     float cookedAmount) {
    struct Node *foundNode = findNodeById(id, transactionsHead);
    if (foundNode != NULL) {
        foundNode->categoryId = categoryId;
        foundNode->rawAmount = rawAmount;
        foundNode->cookedAmount = cookedAmount;
    }
}

void removeTransaction(int id) {
    struct Node *foundNode = findNodeById(id, transactionsHead);
    if (foundNode != NULL) deleteNode(&transactionsHead, foundNode);
}
```

我们在上一部分中审查的`appendNode()`和`deleteNode()`函数并不打算从 JavaScript 代码中调用。相反，调用`addTransaction()`、`editTransaction()`和`removeTransaction()`用于更新本地链表。`addTransaction()`函数调用`appendNode()`函数将传递的数据添加到本地链表中的新节点中。`removeTransaction()`调用`deleteNode()`函数删除相应的交易节点。`findNodeById()`函数用于根据指定的 ID 确定需要在链表中更新或删除的节点。

# 交易计算

第四部分包含用于计算原始和处理后`transactions`的总额和最终余额的函数，如下所示：

```cpp
void calculateGrandTotals(float *totalRaw, float *totalCooked) {
    struct Node *node = transactionsHead;
    while (node != NULL) {
        *totalRaw += node->rawAmount;
        *totalCooked += node->cookedAmount;
        node = node->next;
    }
}

float getGrandTotalForType(AmountType type) {
    float totalRaw = 0;
    float totalCooked = 0;
    calculateGrandTotals(&totalRaw, &totalCooked);

    if (type == RAW) return totalRaw;
    if (type == COOKED) return totalCooked;
    return 0;
}

float getFinalBalanceForType(AmountType type, float initialBalance) {
    float totalForType = getGrandTotalForType(type);
    return initialBalance + totalForType;
}
```

我们在声明部分中声明的`AmountType enum`在这里用于避免**魔术数字**。这使得很容易记住`1`代表原始交易，`2`代表处理后的交易。原始和处理后的交易的总额都是在`calculateGrandTotals()`函数中计算的，即使在`getGrandTotalForType()`中只请求一个类型。由于我们只能从 Wasm 函数中返回一个值，当我们为原始和处理后的交易都调用`getGrandTotalForType()`时，我们最终会循环遍历所有交易两次。对于相对较少的交易量和计算的简单性，这并不会产生任何问题。`getFinalBalanceForType()`返回指定`initialBalance`加上总额。当我们在 Web 应用程序中添加更改初始余额的功能时，您将看到这一点。

# 类别计算

第五和最后一部分包含用于按类别计算总额的函数，我们将在饼图中使用，如下所示：

```cpp
void upsertCategoryNode(int categoryId, float transactionRaw,
                        float transactionCooked) {
    struct Node *foundNode = findNodeById(categoryId, categoriesHead);
    if (foundNode != NULL) {
        foundNode->rawAmount += transactionRaw;
        foundNode->cookedAmount += transactionCooked;
    } else {
        appendNode(&categoriesHead, categoryId, categoryId, transactionRaw,
                   transactionCooked);
    }
}

void buildValuesByCategoryList() {
    struct Node *node = transactionsHead;
    while (node != NULL) {
        upsertCategoryNode(node->categoryId, node->rawAmount,
                           node->cookedAmount);
        node = node->next;
    }
}

void recalculateForCategories() {
    categoriesHead = NULL;
    buildValuesByCategoryList();
}

float getCategoryTotal(AmountType type, int categoryId) {
    // Ensure the category totals have been calculated:
    if (categoriesHead == NULL) buildValuesByCategoryList();

    struct Node *categoryNode = findNodeById(categoryId, categoriesHead);
    if (categoryNode == NULL) return 0;

    if (type == RAW) return categoryNode->rawAmount;
    if (type == COOKED) return categoryNode->cookedAmount;
    return 0;
}
```

每当调用`recalculateForCategories()`或`getCategoryTotal()`函数时，都会调用`buildValuesByCategoryList()`函数。该函数循环遍历`transactions`链表中的所有交易，并为每个对应的类别创建一个节点，其中包含聚合的原始和总金额。`upsertCategoryNode()`函数在`categories`链表中查找与`categoryId`对应的节点。如果找到，则将原始和处理后的交易金额添加到该节点上的现有金额中，否则为该类别创建一个新节点。调用`recalculateForCategories()`函数以确保类别总额与任何交易更改保持最新。

# 编译为 Wasm

填充文件后，我们需要将其编译为 Wasm，以便在应用程序的 JavaScript 部分中使用。通过从菜单中选择任务 | 运行构建任务... 或使用键盘快捷键*Cmd*/*Ctrl* + *Shift* + *B*来运行构建任务。如果构建成功，您将在`/src/assets`文件夹中看到一个名为`main.wasm`的文件。如果出现错误，终端应提供有关如何解决错误的详细信息。

如果您没有使用 VS Code，请在`/cook-the-books`文件夹中打开终端实例，并运行以下命令：

```cpp
emcc lib/main.c -Os -s WASM=1 -s SIDE_MODULE=1 -s BINARYEN_ASYNC_COMPILATION=0 -o src/assets/main.wasm
```

C 代码就是这样。让我们继续进行 JavaScript 部分。

# 构建 JavaScript 部分

应用程序的 JavaScript 部分向用户呈现交易数据，并允许他们轻松添加、编辑和删除交易。该应用程序分为几个文件，以简化开发过程，并使用本章节中描述的库。在本节中，我们将逐步构建应用程序，从 API 和全局状态交互层开始。我们将编写函数来实例化和与我们的 Wasm 模块交互，并审查构建用户界面所需的 Vue 组件。

# 概述

该应用程序被分解为上下文，以简化开发过程。我们将从底层开始构建应用程序，以确保在编写代码时不必在不同的上下文之间来回跳转。我们将从 Wasm 交互代码开始，然后转向全局存储和 API 交互。我将描述每个 Vue 组件的目的，但只会为少数几个提供源代码。如果您正在跟随并希望在本地运行应用程序，则需要将`learn-webassembly`存储库中`/chapter-07-cook-the-books`文件夹中的`/src/components`文件夹复制到您的项目的`/src`文件夹中。

# 关于浏览器兼容性的说明

在我们开始编写任何代码之前，您必须确保您的浏览器支持我们将在应用程序中使用的较新的 JavaScript 功能。您的浏览器必须支持 ES 模块（`import`和`export`）、Fetch API 和`async`/`await`。您至少需要 Google Chrome 的版本 61 或 Firefox 的版本 60。您可以通过从菜单栏中选择关于 Chrome 或关于 Firefox 来检查您当前使用的版本。我目前正在使用 Chrome 版本 67 和 Firefox 版本 61 运行应用程序，没有任何问题。

# 在 initializeWasm.js 中创建一个 Wasm 实例

您的项目的`/src/assets`文件夹中应该有两个编译好的 Wasm 文件：`main.wasm`和`memory.wasm`。由于我们需要在`main.wasm`代码中使用从`memory.wasm`导出的`malloc()`和`free()`函数，我们的加载代码将与之前的示例有所不同。在`/src/store`文件夹中创建一个名为`initializeWasm.js`的文件，并填充以下内容：

```cpp
/**
 * Returns an array of compiled (not instantiated!) Wasm modules.
 * We need the main.wasm file we created, as well as the memory.wasm file
 * that allows us to use C functions like malloc() and free().
 */
const fetchAndCompileModules = () =>
  Promise.all(
    ['../assets/main.wasm', '../assets/memory.wasm'].map(fileName =>
      fetch(fileName)
        .then(response => {
          if (response.ok) return response.arrayBuffer();
          throw new Error(`Unable to fetch WebAssembly file: ${fileName}`);
        })
        .then(bytes => WebAssembly.compile(bytes))
    )
  );

/**
 * Returns an instance of the compiled "main.wasm" file.
 */
const instantiateMain = (compiledMain, memoryInstance, wasmMemory) => {
  const memoryMethods = memoryInstance.exports;
  return WebAssembly.instantiate(compiledMain, {
    env: {
      memoryBase: 0,
      tableBase: 0,
      memory: wasmMemory,
      table: new WebAssembly.Table({ initial: 16, element: 'anyfunc' }),
      abort: console.log,
      _consoleLog: value => console.log(value),
      _malloc: memoryMethods.malloc,
      _free: memoryMethods.free
    }
  });
};

/**
 * Compiles and instantiates the "memory.wasm" and "main.wasm" files and
 * returns the `exports` property from main's `instance`.
 */
export default async function initializeWasm() {
  const wasmMemory = new WebAssembly.Memory({ initial: 1024 });
  const [compiledMain, compiledMemory] = await fetchAndCompileModules();

  const memoryInstance = await WebAssembly.instantiate(compiledMemory, {
    env: {
      memory: wasmMemory
    }
  });

  const mainInstance = await instantiateMain(
    compiledMain,
    memoryInstance,
    wasmMemory
  );

  return mainInstance.exports;
}
```

文件的默认`export`函数`initializeWasm()`执行以下步骤：

1.  创建一个新的`WebAssembly.Memory`实例（`wasmMemory`）。

1.  调用`fetchAndCompileModules()`函数以获取`memory.wasm`（`compiledMemory`）和`main.wasm`（`compiledMain`）的`WebAssembly.Module`实例。

1.  实例化`compiledMemory`（`memoryInstance`）并将`wasmMemory`传递给`importObj`。

1.  将`compiledMain`、`memoryInstance`和`wasmMemory`传递给`instantiateMain()`函数。

1.  实例化`compiledMain`并将从`memoryInstance`导出的`malloc()`和`free()`函数以及`wasmMemory`传递给`importObj`。

1.  返回从`instantiateMain`返回的`Instance`的`exports`属性。

如您所见，当 Wasm 模块内部存在依赖关系时，该过程更加复杂。

您可能已经注意到`memoryInstance`的`exports`属性上的`malloc`和`free`方法没有用下划线前缀。这是因为`memory.wasm`文件是使用 LLVM 而不是 Emscripten 编译的，后者不会添加下划线。

# 在 WasmTransactions.js 中与 Wasm 交互

我们将使用 JavaScript 的`class`语法来创建一个封装 Wasm 交互函数的包装器。这使我们能够快速更改 C 代码，而无需搜索整个应用程序以找到调用 Wasm 函数的位置。如果您在 C 文件中重命名一个方法，您只需要在一个地方重命名它。在`/src/store`文件夹中创建一个名为`WasmTransactions.js`的新文件，并填充以下内容：

```cpp
import initializeWasm from './initializeWasm.js';

/**
 * Class used to wrap the functionality from the Wasm module (rather
 * than access it directly from the Vue components or store).
 * @class
 */
export default class WasmTransactions {
  constructor() {
    this.instance = null;
    this.categories = [];
  }

  async initialize() {
    this.instance = await initializeWasm();
    return this;
  }

  getCategoryId(category) {
    return this.categories.indexOf(category);
  }

  // Ensures the raw and cooked amounts have the proper sign (withdrawals
  // are negative and deposits are positive).
  getValidAmounts(transaction) {
    const { rawAmount, cookedAmount, type } = transaction;
    const getAmount = amount =>
      type === 'Withdrawal' ? -Math.abs(amount) : amount;
    return {
      validRaw: getAmount(rawAmount),
      validCooked: getAmount(cookedAmount)
    };
  }

  // Adds the specified transaction to the linked list in the Wasm module.
  addToWasm(transaction) {
    const { id, category } = transaction;
    const { validRaw, validCooked } = this.getValidAmounts(transaction);
    const categoryId = this.getCategoryId(category);
    this.instance._addTransaction(id, categoryId, validRaw, validCooked);
  }

  // Updates the transaction node in the Wasm module:
  editInWasm(transaction) {
    const { id, category } = transaction;
    const { validRaw, validCooked } = this.getValidAmounts(transaction);
    const categoryId = this.getCategoryId(category);
    this.instance._editTransaction(id, categoryId, validRaw, validCooked);
  }

  // Removes the transaction node from the linked list in the Wasm module:
  removeFromWasm(transactionId) {
    this.instance._removeTransaction(transactionId);
  }

  // Populates the linked list in the Wasm module. The categories are
  // needed to set the categoryId in the Wasm module.
  populateInWasm(transactions, categories) {
    this.categories = categories;
    transactions.forEach(transaction => this.addToWasm(transaction));
  }

  // Returns the balance for raw and cooked transactions based on the
  // specified initial balances.
  getCurrentBalances(initialRaw, initialCooked) {
    const currentRaw = this.instance._getFinalBalanceForType(
      AMOUNT_TYPE.raw,
      initialRaw
    );
    const currentCooked = this.instance._getFinalBalanceForType(
      AMOUNT_TYPE.cooked,
      initialCooked
    );
    return { currentRaw, currentCooked };
  }

  // Returns an object that has category totals for all income (deposit)
  // and expense (withdrawal) transactions.
  getCategoryTotals() {
    // This is done to ensure the totals reflect the most recent
    // transactions:
    this.instance._recalculateForCategories();
    const categoryTotals = this.categories.map((category, idx) => ({
      category,
      id: idx,
      rawTotal: this.instance._getCategoryTotal(AMOUNT_TYPE.raw, idx),
      cookedTotal: this.instance._getCategoryTotal(AMOUNT_TYPE.cooked, idx)
    }));

    const totalsByGroup = { income: [], expenses: [] };
    categoryTotals.forEach(categoryTotal => {
      if (categoryTotal.rawTotal < 0) {
        totalsByGroup.expenses.push(categoryTotal);
      } else {
        totalsByGroup.income.push(categoryTotal);
      }
    });
    return totalsByGroup;
  }
}
```

当对类的实例调用`initialize（）`函数时，`initializeWasm（）`函数的返回值被分配给类的`instance`属性。`class`方法调用`this.instance`中的函数，并在适用的情况下返回所需的结果。请注意`getCurrentBalances（）`和`getCategoryTotals（）`函数中引用的`AMOUNT_TYPE`对象。这对应于我们 C 文件中的`AmountType enum`。`AMOUNT_TYPE`对象在加载应用程序的`/src/main.js`文件中全局声明。现在我们已经编写了 Wasm 交互代码，让我们继续编写 API 交互代码。

# 在 api.js 中利用 API

API 提供了在 fetch 调用上定义的 HTTP 方法的方式来添加、编辑、删除和查询交易。为了简化执行这些操作的过程，我们将编写一些 API“包装”函数。在`/src/store`文件夹中创建一个名为`api.js`的文件，并填充以下内容：

```cpp
// Paste your jsonstore.io endpoint here (no ending slash):
const API_URL = '[JSONSTORE.IO ENDPOINT]';

/**
 * Wrapper for performing API calls. We don't want to call response.json()
 * each time we make a fetch call.
 * @param {string} endpoint Endpoint (e.g. "/transactions" to make API call to
 * @param {Object} init Fetch options object containing any custom settings
 * @returns {Promise<*>}
 * @see https://developer.mozilla.org/en-US/docs/Web/API/WindowOrWorkerGlobalScope/fetch
 */
const performApiFetch = (endpoint = '', init = {}) =>
  fetch(`${API_URL}${endpoint}`, {
    headers: {
      'Content-type': 'application/json'
    },
    ...init
  }).then(response => response.json());

export const apiFetchTransactions = () =>
  performApiFetch('/transactions').then(({ result }) =>
    /*
     * The response object looks like this:
     * {
     *   "result": {
     *     "1": {
     *       "category": "Sales Revenue",
     *       ...
     *     },
     *     "2": {
     *       "category": "Hotels",
     *       ...
     *     },
     *     ...
     *   }
     * }
     * We need the "1" and "2" values for deleting or editing existing
     * records, so we store that in the transaction record as "apiId".
     */
    Object.keys(result).map(apiId => ({
      ...result[apiId],
      apiId
    }))
  );

export const apiEditTransaction = transaction =>
  performApiFetch(`/transactions/${transaction.apiId}`, {
    method: 'POST',
    body: JSON.stringify(transaction)
  });

export const apiRemoveTransaction = transaction =>
  performApiFetch(`/transactions/${transaction.apiId}`, {
    method: 'DELETE'
  });

export const apiAddTransaction = transaction =>
  performApiFetch(`/transactions/${transaction.apiId}`, {
    method: 'POST',
    body: JSON.stringify(transaction)
  });
```

您需要在*设置项目*部分创建的 jsonstore.io 端点才能与 API 交互。将`[JSONSTORE.IO ENDPOINT]`替换为您的 jsonstore.io 端点。确保端点不以斜杠或单词 transactions 结尾。

# 在 store.js 中管理全局状态

在应用程序中管理全局状态的文件有很多组成部分。因此，我们将代码分解成较小的块，并逐个部分地进行讲解。在`/src/store`文件夹中创建一个名为`store.js`的文件，并填充以下各部分的内容。

# 导入和存储声明

第一部分包含`import`语句和导出的`store`对象上的`wasm`和`state`属性，如下所示：

```cpp
import {
  apiFetchTransactions,
  apiAddTransaction,
  apiEditTransaction,
  apiRemoveTransaction
} from './api.js';
import WasmTransactions from './WasmTransactions.js';

export const store = {
  wasm: null,
  state: {
    transactions: [],
    activeTransactionId: 0,
    balances: {
      initialRaw: 0,
      currentRaw: 0,
      initialCooked: 0,
      currentCooked: 0
    }
  },
  ...
```

所有 API 交互都限于`store.js`文件。由于我们需要操作、添加和搜索交易，所以从`api.js`导出的所有函数都被导入。`store`对象在`wasm`属性中保存了`WasmTransactions`实例，并在`state`属性中保存了初始状态。`state`中的值在应用程序的多个位置引用。当应用程序加载时，`store`对象将被添加到全局`window`对象中，因此所有组件都可以访问全局状态。

# 交易操作

第二部分包含管理 Wasm 实例（通过`WasmTransactions`实例）和 API 中的交易的函数，如下所示：

```cpp
...
  getCategories() {
    const categories = this.state.transactions.map(
      ({ category }) => category
    );
    // Remove duplicate categories and sort the names in ascending order:
    return _.uniq(categories).sort();
  },

  // Populate global state with the transactions from the API response:
  populateTransactions(transactions) {
    const sortedTransactions = _.sortBy(transactions, [
      'transactionDate',
      'id'
    ]);
    this.state.transactions = sortedTransactions;
    store.wasm.populateInWasm(sortedTransactions, this.getCategories());
    this.recalculateBalances();
  },

  addTransaction(newTransaction) {
    // We need to assign a new ID to the transaction, so this just adds
    // 1 to the current maximum transaction ID:
    newTransaction.id = _.maxBy(this.state.transactions, 'id').id + 1;
    store.wasm.addToWasm(newTransaction);
    apiAddTransaction(newTransaction).then(() => {
      this.state.transactions.push(newTransaction);
      this.hideTransactionModal();
    });
  },

  editTransaction(editedTransaction) {
    store.wasm.editInWasm(editedTransaction);
    apiEditTransaction(editedTransaction).then(() => {
      this.state.transactions = this.state.transactions.map(
        transaction => {
          if (transaction.id === editedTransaction.id) {
            return editedTransaction;
          }
          return transaction;
        }
      );
      this.hideTransactionModal();
    });
  },

  removeTransaction(transaction) {
    const transactionId = transaction.id;
    store.wasm.removeFromWasm(transactionId);

    // We're passing the whole transaction record into the API call
    // for the sake of consistency:
    apiRemoveTransaction(transaction).then(() => {
      this.state.transactions = this.state.transactions.filter(
        ({ id }) => id !== transactionId
      );
      this.hideTransactionModal();
    });
  },
...
```

populateTransactions（）函数从 API 中获取所有交易，并将它们加载到全局状态和 Wasm 实例中。类别名称是从`getCategories（）`函数中的`transactions`数组中推断出来的。当调用`store.wasm.populateInWasm（）`时，结果将传递给`WasmTransactions`实例。

`addTransaction()`、`editTransaction()`和`removeTransaction()`函数执行与它们的名称相对应的操作。所有三个函数都操作 Wasm 实例，并通过 fetch 调用更新 API 上的数据。每个函数都调用`this.hideTransactionModal()`，因为只能通过`TransactionModal`组件对交易进行更改。一旦更改成功，模态应该关闭。接下来让我们看一下`TransactionModal`管理代码。

# 交易模态管理

第三部分包含管理`TransactionModal`组件（位于`/src/components/TransactionsTab/TransactionModal.js`）的可见性和内容的函数，如下所示：

```cpp
...
  showTransactionModal(transactionId) {
    this.state.activeTransactionId = transactionId || 0;
    const transactModal = document.querySelector('#transactionModal');
    UIkit.modal(transactModal).show();
  },

  hideTransactionModal() {
    this.state.activeTransactionId = 0;
    const transactModal = document.querySelector('#transactionModal');
    UIkit.modal(transactModal).hide();
  },

  getActiveTransaction() {
    const { transactions, activeTransactionId } = this.state;
    const foundTransaction = transactions.find(transaction =>
      transaction.id === activeTransactionId);
    return foundTransaction || { id: 0 };
  },
...
```

`showTransactionModal()`和`hideTransactionModal()`函数应该是不言自明的。在代表`TransactionModal`的 DOM 元素上调用`UIkit.modal()`的`hide()`或`show()`方法。`getActiveTransaction()`函数返回与全局状态中的`activeTransactionId`值相关联的交易记录。

# 余额计算

第四部分包含计算和更新全局状态中`balances`对象的函数：

```cpp
...
  updateInitialBalance(amount, fieldName) {
    this.state.balances[fieldName] = amount;
  },

  // Update the "balances" object in global state based on the current
  // initial balances:
  recalculateBalances() {
    const { initialRaw, initialCooked } = this.state.balances;
    const { currentRaw, currentCooked } = this.wasm.getCurrentBalances(
      initialRaw,
      initialCooked
    );
    this.state.balances = {
      initialRaw,
      currentRaw,
      initialCooked,
      currentCooked
    };
  }
};
```

`updateInitialBalance()`函数根据`amount`和`fieldName`参数设置全局状态中`balances`对象的属性值。`recalculateBalances()`函数更新`balances`对象上的所有字段，以反映对初始余额或交易所做的任何更改。

# 存储初始化

文件中的最后一部分代码初始化了存储：

```cpp
/**
 * This function instantiates the Wasm module, fetches the transactions
 * from the API endpoint, and loads them into state and the Wasm
 * instance.
 */
export const initializeStore = async () => {
  const wasmTransactions = new WasmTransactions();
  store.wasm = await wasmTransactions.initialize();
  const transactions = await apiFetchTransactions();
  store.populateTransactions(transactions);
};
```

`initializeStore()`函数实例化 Wasm 模块，从 API 获取所有交易，并填充状态的内容。这个函数是从`/src/main.js`中的应用程序加载代码中调用的，我们将在下一节中介绍。

# 在 main.js 中加载应用程序

我们需要一个入口点来加载我们的应用程序。在`/src`文件夹中创建一个名为`main.js`的文件，并填充以下内容：

```cpp
import App from './components/App.js';
import { store, initializeStore } from './store/store.js';

// This allows us to use the <vue-numeric> component globally:
Vue.use(VueNumeric.default);

// Create a globally accessible store (without having to pass it down
// as props):
window.$store = store;

// Since we can only pass numbers into a Wasm function, these flags
// represent the amount type we're trying to calculate:
window.AMOUNT_TYPE = {
  raw: 1,
  cooked: 2
};

// After fetching the transactions and initializing the Wasm module,
// render the app.
initializeStore()
  .then(() => {
    new Vue({ render: h => h(App), el: '#app' });
  })
  .catch(err => {
    console.error(err);
  });
```

这个文件是在从`/src/index.html`中的 CDN 中获取和加载库之后加载的。我们使用全局的`Vue`对象来指定我们要使用`VueNumeric`组件。我们将从`/store/store.js`导出的`store`对象添加到`window`中作为`$store`。这不是最健壮的解决方案，但在应用程序的范围内将足够。如果你正在创建一个生产应用程序，你会使用像**Vuex**或**Redux**这样的库来进行全局状态管理。出于简化的目的，我们将放弃这种方法。

我们还将`AMOUNT_TYPE`添加到`window`对象中。这样做是为了确保整个应用程序可以引用`AMOUNT_TYPE`值，而不是指定一个魔术数字。在将值分配给`window`之后，将调用`initializeStore()`函数。如果`initializeStore()`函数成功触发，将创建一个新的`Vue`实例来渲染应用程序。接下来让我们添加 web 资源，然后转向 Vue 组件。

# 添加 web 资源

在我们开始向应用程序添加 Vue 组件之前，让我们创建包含我们标记和样式的 HTML 和 CSS 文件。在`/src`文件夹中创建一个名为`index.html`的文件，并填充以下内容：

```cpp
<!doctype html>
<html lang="en-us">
<head>
  <title>Cook the Books</title>
  <link
    rel="stylesheet"
    type="text/css"
    href="https://cdnjs.cloudflare.com/ajax/libs/uikit/3.0.0-rc.6/css/uikit.min.css"
  />
  <link rel="stylesheet" type="text/css" href="styles.css" />
  <script src="img/uikit.min.js"></script>
  <script src="img/uikit-icons.min.js"></script>
  <script src="img/accounting.umd.js"></script>
  <script src="img/lodash.min.js"></script>
  <script src="img/d3.min.js"></script>
  <script src="img/vue.min.js"></script>
  <script src="img/vue-numeric.min.js"></script>
  <script src="img/main.js" type="module"></script>
</head>
<body>
  <div id="app"></div>
</body>
</html>
```

我们只使用 HTML 文件从 CDN 中获取库，指定 Vue 可以渲染的`<div>`，并加载`main.js`来启动应用程序。请注意最后一个`<script>`元素上的`type="module"`属性。这允许我们在整个应用程序中使用 ES 模块。现在让我们添加 CSS 文件。在`/src`文件夹中创建一个名为`styles.css`的文件，并填充以下内容：

```cpp
@import url("https://fonts.googleapis.com/css?family=Quicksand");

:root {
  --blue: #2889ed;
}

* {
  font-family: "Quicksand", Helvetica, Arial, sans-serif !important;
}

#app {
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

.addTransactionButton {
  color: white;
  height: 64px;
  width: 64px;
  background: var(--blue);
  position: fixed;
  bottom: 24px;
  right: 24px;
}

.addTransactionButton:hover {
  color: white;
  background-color: var(--blue);
  opacity: .6;
}

.errorText {
  color: white;
  font-size: 36px;
}

.appHeader {
  height: 80px;
  margin: 0;
}

.balanceEntry {
  font-size: 2rem;
}

.tableAmount {
  white-space: pre;
}
```

这个文件只有几个类，因为大部分的样式将在组件级别处理。在下一节中，我们将回顾构成我们应用程序的 Vue 组件。

# 创建 Vue 组件

使用 Vue，我们可以创建单独的组件，封装其自身的功能，然后组合这些组件来构建应用程序。这比将应用程序存储在单个庞大文件中更容易进行调试、扩展和变更管理。

该应用程序使用单文件组件开发方法。在开始审查组件文件之前，让我们看看最终产品。以下屏幕截图显示了选择了 TRANSACTIONS 选项卡的应用程序：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/5fd7ee43-480d-4d13-8b0c-370bd2f851ba.png)

使用 TRANSACTIONS 选项卡运行应用程序

以下是应用程序的屏幕截图，选择了 CHARTS 选项卡：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/593e5d7b-16ae-416e-91c6-a44a890d495c.png)

使用 CHARTS 选项卡运行应用程序

# Vue 组件的结构

Vue 组件只是一个包含属性的导出对象文件，定义了该组件的外观和行为。这些属性必须具有符合 Vue API 的名称。您可以在[`vuejs.org/v2/api`](https://vuejs.org/v2/api)上阅读有关这些属性和 Vue API 的其他方面。以下代码代表包含此应用程序中使用的 Vue API 元素的示例组件：

```cpp
import SomeComponent from './SomeComponent.js';

export default {
  name: 'dummy-component',

  // Props passed from other components:
  props: {
    label: String,
  },

  // Other Vue components to render within the template:
  components: {
    SomeComponent
  },

  // Used to store local data/state:
  data() {
    return {
      amount: 0
    }
  },

  // Used to store complex logic that outside of the `template`:
  computed: {
    negativeClass() {
      return {
        'negative': this.amount < 0
      };
    }
  },

  // Methods that can be performed within the component:
  methods: {
    addOne() {
      this.amount += 1;
    }
  },

  // Perform actions if the local data changes:
  watch: {
    amount(val, oldVal) {
      console.log(`New: ${val} | Old: ${oldVal}`);
    }
  },

  // Contains the HTML to render the component:
  template: `
    <div>
      <some-component></some-component>
      <label for="someAmount">{{ label }}</label>
      <input
        id="someAmount"
        :class="negativeClass"
        v-model="amount"
        type="number"
      />
      <button @click="addOne">Add One</button>
    </div>
  `
};
```

上面每个属性的注释描述了其目的，尽管在非常高的层次上。让我们通过审查`App`组件来看看 Vue 的实际运行情况。

# App 组件

`App`组件是渲染应用程序中所有子组件的基本组件。我们将简要审查`App`组件的代码，以更好地理解 Vue。接下来，我们将描述每个剩余组件的作用，但只审查相应代码的部分。`App`组件文件的内容，位于`/src/components/App.js`，如下所示：

```cpp
import BalancesBar from './BalancesBar/BalancesBar.js';
import ChartsTab from './ChartsTab/ChartsTab.js';
import TransactionsTab from './TransactionsTab/TransactionsTab.js';

/**
 * This component is the entry point for the application. It contains the
 * header, tabs, and content.
 */
export default {
  name: 'app',
  components: {
    BalancesBar,
    ChartsTab,
    TransactionsTab
  },
  data() {
    return {
      balances: $store.state.balances,
      activeTab: 0
    };
  },
  methods: {
    // Any time a transaction is added, edited, or removed, we need to
    // ensure the balance is updated:
    onTransactionChange() {
      $store.recalculateBalances();
      this.balances = $store.state.balances;
    },

    // When the "Charts" tab is activated, this ensures that the charts
    // get automatically updated:
    onTabClick(event) {
      this.activeTab = +event.target.dataset.tab;
    }
  },
  template: `
    <div>
      <div class="appHeader uk-background-primary uk-flex uk-flex-middle">
        <h2 class="uk-light uk-margin-remove-bottom uk-margin-left">
          Cook the Books
        </h2>
      </div>
      <div class="uk-position-relative">
        <ul uk-tab class="uk-margin-small-bottom uk-margin-top">
          <li class="uk-margin-small-left">
            <a href="#" data-tab="0" @click="onTabClick">Transactions</a>
          </li>
          <li>
            <a href="#" data-tab="1" @click="onTabClick">Charts</a>
          </li>
        </ul>
        <balances-bar
          :balances="balances"
          :onTransactionChange="onTransactionChange">
        </balances-bar>
        <ul class="uk-switcher">
          <li>
            <transactions-tab :onTransactionChange="onTransactionChange">
            </transactions-tab>
          </li>
          <li>
            <charts-tab :isActive="this.activeTab === 1"></charts-tab>
          </li>
        </ul>
      </div>
    </div>
  `
};
```

我们使用`components`属性指定在`App`组件的`template`中渲染的其他 Vue 组件。`data()`函数返回本地状态，用于跟踪余额和活动的选项卡（TRANSACTIONS 或 CHARTS）。`methods`属性包含两个函数：`onTransactionChange()`和`onTabClick()`。`onTransactionChange()`函数调用`$store.recalculateBalances()`，如果对交易记录进行更改，则更新本地状态中的`balances`。`onTabClick()`函数将本地状态中的`activeTab`值更改为所点击选项卡的`data-tab`属性。最后，`template`属性包含用于渲染组件的标记。

如果您在 Vue 中不使用单文件组件（`.vue`扩展名），则需要将模板属性中的组件名称转换为 kebab case。例如，在前面显示的`App`组件中，`BalancesBar`被更改为`<balances-bar>`。

# BalancesBar

`/components/BalancesBar`文件夹包含两个组件文件：`BalanceCard.js`和`BalancesBar.js`。`BalancesBar`组件跨越 TRANSACTIONS 和 CHARTS 选项卡，并直接位于选项卡控制下方。它包含四个`BalanceCard`组件，分别对应四种余额类型：初始原始、当前原始、初始熟练和当前熟练。代表初始余额的第一和第三张卡包含输入，因此余额可以更改。代表当前余额的第二和第四张卡在 Wasm 模块中动态计算（使用`getFinalBalanceForType()`函数）。以下代码片段来自`BalancesBar`组件，演示了 Vue 的绑定语法：

```cpp
<balance-card
  title="Initial Raw Balance"
  :value="balances.initialRaw"
  :onChange="amount => onBalanceChange(amount, 'initialRaw')">
</balance-card>
```

`value`和`onChange`属性之前的`:`表示这些属性绑定到了 Vue 组件。如果`balances.initialRaw`的值发生变化，`BalanceCard`中显示的值也会更新。此卡的`onBalanceChange()`函数会更新全局状态中`balances.initialRaw`的值。

# TransactionsTab

`/components/TransactionsTab`文件夹包含以下四个组件文件：

+   `ConfirmationModal.js`

+   `TransactionModal.js`

+   `TransactionsTab.js`

+   `TransactionsTable.js`

`TransactionsTab`组件包含`TransactionsTable`和`TransactionsModal`组件，以及用于添加新交易的按钮。更改和添加是通过`TransactionModal`组件完成的。`TransactionsTable`包含所有当前的交易，每行都有按钮，可以编辑或删除交易。如果用户按下删除按钮，`ConfirmationModal`组件将出现并提示用户继续。如果用户按下“是”，则删除交易。以下摘录来自`TransactionsTable`组件的`methods`属性，演示了如何格式化显示值：

```cpp
getFormattedTransactions() {
  const getDisplayAmount = (type, amount) => {
    if (amount === 0) return accounting.formatMoney(amount);
    return accounting.formatMoney(amount, {
      format: { pos: '%s %v', neg: '%s (%v)' }
    });
  };

  const getDisplayDate = transactionDate => {
    if (!transactionDate) return '';
    const parsedTime = d3.timeParse('%Y-%m-%d')(transactionDate);
    return d3.timeFormat('%m/%d/%Y')(parsedTime);
  };

  return $store.state.transactions.map(
    ({
      type,
      rawAmount,
      cookedAmount,
      transactionDate,
      ...transaction
    }) => ({
      ...transaction,
      type,
      rawAmount: getDisplayAmount(type, rawAmount),
      cookedAmount: getDisplayAmount(type, cookedAmount),
      transactionDate: getDisplayDate(transactionDate)
    })
  );
}
```

上述`getFormattedTransactions()`函数应用格式化到每个`transaction`记录中的`rawAmount`、`cookedAmount`和`transactionDate`字段。这样做是为了确保显示的值包括美元符号（对于金额）并以用户友好的格式呈现。

# ChartsTab

`/components/ChartsTab`文件夹包含两个组件文件：`ChartsTab.js`和`PieChart.js`。`ChartsTab`组件包含两个`PieChart`组件的实例，一个用于收入，一个用于支出。每个`PieChart`组件显示按类别的原始或烹饪百分比。用户可以通过图表上方的按钮在原始或烹饪视图之间切换。`PieChart.js`中的`drawChart()`方法使用 D3 来渲染饼图和图例。它使用 D3 的内置动画在加载时对饼图的每个部分进行动画处理：

```cpp
arc
  .append('path')
  .attr('fill', d => colorScale(d.data.category))
  .transition()
  .delay((d, i) => i * 100)
  .duration(500)
  .attrTween('d', d => {
    const i = d3.interpolate(d.startAngle + 0.1, d.endAngle);
    return t => {
      d.endAngle = i(t);
      return arcPath(d);
    };
  });
```

```cpp
https://bl.ocks.org. That's it for the components review; let's try running the application.
```

# 运行应用程序

您已经编写并编译了 C 代码，并添加了前端逻辑。现在是时候启动应用程序并与之交互了。在本节中，我们将验证应用程序的`/src`文件夹，运行应用程序，并测试功能，以确保一切都正常工作。

# 验证/src 文件夹

在启动应用程序之前，请参考以下结构，确保您的/src 文件夹结构正确，并包含以下内容：

```cpp
├── /assets
│    ├── main.wasm
│    └── memory.wasm
├── /components
│    ├── /BalancesBar
│    │    ├── BalanceCard.js
│    │    └── BalancesBar.js
│    ├── /ChartsTab
│    │    ├── ChartsTab.js
│    │    └── PieChart.js
│    ├── /TransactionsTab
│    │    ├── ConfirmationModal.js
│    |    ├── TransactionModal.js
│    |    ├── TransactionsTab.js
│    |    └── TransactionsTable.js
│    └── App.js
├── /store
│    ├── api.js
│    ├── initializeWasm.js
│    ├── store.js
│    └── WasmTransactions.js
├── index.html
├── main.js
└── styles.css
```

如果一切匹配，您就可以继续了。

# 启动它！

要启动应用程序，请在`/cook-the-books`文件夹中打开终端并运行以下命令：

```cpp
npm start
```

`browser-sync`是我们在本章第一节安装的开发依赖项，它充当本地服务器（类似于`serve`库）。它使应用程序可以从`package.json`文件中指定的端口（在本例中为`4000`）在浏览器中访问。如果您在浏览器中导航到`http://localhost:4000/index.html`，您应该会看到这个：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/fc07674b-a7b5-4fd6-8593-6a0429558e2e.png)

初始加载的应用程序

我们使用`browser-sync`而不是`serve`，因为它会监视文件的更改，并在您进行更改时自动重新加载应用程序。要看到它的效果，请尝试将`App.js`中标题栏的内容从`Cook the Books`更改为`Broil the Books`。浏览器将刷新，您将在标题栏中看到更新后的文本。

# 测试一下

为了确保一切都正常工作，请测试一下应用程序。以下各节描述了应用程序特定功能的操作和预期行为。跟着操作，看看是否得到了预期结果。如果遇到问题，您可以随时参考`learn-webassembly`存储库中`/chapter-07-cook-the-books`文件夹。

# 更改初始余额

尝试更改“INITIAL RAW BALANCE”和“INITIAL COOKED BALANCE”`BalanceCard`组件上的输入值。当前的“CURRENT RAW BALANCE”和“CURRENT COOKED BALANCE”卡片数值应该更新以反映您的更改。

# 创建新交易

记下当前的原始和处理后的余额，然后按下窗口右下角的蓝色添加按钮。它应该加载`TransactionModal`组件。填写输入，记下**类型**，**原始金额**和**处理后的金额**，然后按保存按钮。

余额应该已经更新以反映新的金额。如果您选择了“提款”作为**类型**，则余额应该减少，否则，它们会增加（存款）如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/dace2c59-c6f4-4039-ae01-3b6f3293777a.png)

添加新交易时的 TransactionModal

# 删除现有交易

在`TransactionsTable`组件中选择一行，注意金额，然后按下该记录的垃圾桶按钮。`ConfirmationModal`组件应该出现。当您按下**是**按钮时，交易记录应该不再出现在表中，并且当前余额应该更新以反映与已删除交易相关的金额，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/850ece1d-3df5-4919-9380-e268ba3975b6.png)

在按下删除按钮后显示确认模态

# 编辑现有交易

按照创建新交易的相同步骤，除了更改现有金额。检查当前余额以确保它们反映了更新后的交易金额。

# 测试图表选项卡

选择“图表”选项卡以加载`ChartsTab`组件。按下每个`PieChart`组件中的按钮以在原始视图和处理后的视图之间切换。饼图应该重新渲染以显示更新后的值：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/lrn-wasm/img/24cbe04a-2d49-49cb-9d5b-09cb6f6c3699.png)

选择 CHARTS 选项卡的内容，选择不同的金额类型

# 总结

恭喜，您刚刚构建了一个使用 WebAssembly 的应用程序！告诉您的朋友！现在您了解了 WebAssembly 的能力和限制，是时候扩展我们的视野，并使用 Emscripten 提供的一些出色功能了。

# 摘要

在本章中，我们从头开始构建了一个会计应用程序，该应用程序使用 WebAssembly 而没有 Emscripten 提供的任何额外功能。通过遵守*核心规范*，我们展示了 WebAssembly 在其当前形式下的限制。然而，我们能够通过使用 Wasm 模块快速执行计算，这非常适合会计。我们使用 Vue 将应用程序拆分为组件，使用 UIkit 进行设计和布局，并使用 D3 从我们的交易数据创建饼图。在第八章中，*使用 Emscripten 移植游戏*，我们将充分利用 Emscripten 将现有的 C++代码库移植到 WebAssembly。

# 问题

1.  为什么我们在这个应用程序中使用 Vue（而不是 React 或 Angular）？

1.  为什么我们在这个项目中使用 C 而不是 C++？

1.  为什么我们需要使用 jsonstore.io 设置一个模拟 API，而不是在本地的 JSON 文件中存储数据？

1.  我们在 C 文件中使用的数据结构的名称是什么？

1.  我们从`memory.wasm`文件中需要哪些函数，它们用于什么？

1.  为什么我们要在 Wasm 模块周围创建一个包装类？

1.  为什么我们将`$store`对象设为全局？

1.  在生产应用程序中，您可以使用哪些库来管理全局状态？

1.  我们为什么使用`browser-sync`而不是`serve`来运行应用程序？

# 进一步阅读

+   Vue: [`vuejs.org`](https://vuejs.org)
