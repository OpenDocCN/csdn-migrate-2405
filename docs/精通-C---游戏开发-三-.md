# 精通 C++ 游戏开发（三）

> 原文：[`annas-archive.org/md5/C9DEE6A3AC368562ED493911597C48C0`](https://annas-archive.org/md5/C9DEE6A3AC368562ED493911597C48C0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：高级渲染

玩家对游戏的第一印象通常来自屏幕上的视觉效果。深入了解创建高级渲染技术对于构建引人入胜和沉浸式体验至关重要。在本章中，我们将探讨如何通过实现着色器技术来创建一些高级渲染效果。

+   着色器简介

+   照明技术

+   使用着色器创建效果

# 着色器简介

简而言之，着色器是用于进行图像处理的计算机程序，例如特效、颜色效果、照明和着色。在运行时，可以使用在着色器程序中构建的算法改变屏幕上所有像素、顶点或纹理的位置、亮度、对比度、色调和其他效果，以产生最终图像。如今，大多数着色器程序都是为了直接在**图形处理单元**（**GPU**）上运行而构建的。着色器程序是并行执行的。这意味着，例如，一个着色器可能会在每个像素上执行一次，每次执行都在 GPU 上的不同线程上同时运行。同时执行的线程数量取决于图形卡特定的 GPU，现代卡配备了数千个处理器。所有这些意味着着色器程序可以非常高效，并为开发人员提供了很多创造性的灵活性。在本节中，我们将熟悉着色器并为示例引擎实现自己的着色器基础设施。

# 着色器语言

随着图形卡技术的进步，渲染管线增加了更多的灵活性。曾经开发人员对于固定功能管线渲染等概念几乎没有控制权，新的进步使程序员能够更深入地控制图形硬件来渲染他们的作品。最初，这种更深入的控制是通过使用汇编语言编写着色器来实现的，这是一项复杂而繁琐的任务。不久之后，开发人员渴望有一个更好的解决方案。着色器编程语言应运而生。让我们简要地看一下一些常用的语言。

**图形 C**（**Cg**）是由 Nvidia 图形公司最初开发的着色语言。Cg 基于 C 编程语言，尽管它们共享相同的语法，但对 C 的一些特性进行了修改，并添加了新的数据类型，使 Cg 更适合于编程 GPU。Cg 编译器可以输出由 DirectX 和 OpenGL 都支持的着色器程序。虽然 Cg 大部分已经被淘汰，但它在 Unity 游戏引擎中的使用使其以一种新形式复兴。

**高级着色语言**（**HLSL**）是由微软公司为 DirectX 图形 API 开发的着色语言。HLSL 再次是基于 C 编程语言建模，并且与 Cg 着色语言有许多相似之处。HLSL 仍在开发中，并且继续是 DirectX 的首选着色语言。自 DirectX 12 发布以来，HLSL 语言甚至支持更低级的硬件控制，并且性能有了显著的改进。

**OpenGL 着色语言**（**GLSL**）是一种基于 C 编程语言的着色语言。它是由**OpenGL 架构审查委员会**（**OpenGL ARB**）创建的，旨在使开发人员能够更直接地控制图形管线，而无需使用 ARB 汇编语言或其他硬件特定语言。该语言仍在开发中，并且将是我们在示例中专注的语言。

# 构建着色器程序基础设施

大多数现代着色器程序由多达五种不同类型的着色器文件组成：片段或像素着色器、顶点着色器、几何着色器、计算着色器和镶嵌着色器。构建着色器程序时，每个这些着色器文件必须被编译和链接在一起以供使用，就像 C++程序的编译和链接一样。接下来，我们将带您了解这个过程是如何工作的，看看我们如何构建一个基础设施，以便更轻松地与我们的着色器程序进行交互。

首先，让我们看看如何编译 GLSL 着色器。GLSL 编译器是 OpenGL 库的一部分，我们的着色器可以在 OpenGL 程序中进行编译。我们将构建一个支持内部编译的架构。编译着色器的整个过程可以分解为一些简单的步骤。首先，我们必须创建一个着色器对象，然后将源代码提供给着色器对象。然后我们可以要求着色器对象被编译。这些步骤可以用以下三个基本调用来表示 OpenGL API。

首先，我们创建着色器对象：

```cpp
GLuint vertexShader = glCreateShader(GL_VERTEX_SHADER);
```

我们使用`glCreateShader()`函数创建着色器对象。我们传递的参数是我们要创建的着色器的类型。着色器的类型可以是`GL_VERTEX_SHADER`、`GL_FRAGMENT_SHADER`、`GL_GEOMETRY_SHADER`、`GL_TESS_EVALUATION_SHADER`、`GL_TESS_CONTROL_SHADER`或`GL_COMPUTE_SHADER`。在我们的示例中，我们尝试编译一个顶点着色器，所以我们使用`GL_VERTEX_SHADER`类型。

接下来，我们将着色器源代码复制到着色器对象中：

```cpp
GLchar* shaderCode = LoadShader("shaders/simple.vert");
glShaderSource(vertexShader, 1, shaderCode, NULL);
```

在这里，我们使用`glShaderSource()`函数将我们的着色器源代码加载到内存中。这个函数接受一个字符串数组，所以在调用`glShaderSource()`之前，我们使用一个尚未创建的方法创建一个指向`shaderCode`数组对象开头的指针。`glShaderSource()`的第一个参数是着色器对象的句柄。第二个是包含在数组中的源代码字符串的数量。第三个参数是指向源代码字符串数组的指针。最后一个参数是包含前一个参数中每个源代码字符串的长度的`GLint`值的数组。

最后，我们编译着色器：

```cpp
glCompileShader(vertexShader);
```

最后一步是编译着色器。我们通过调用 OpenGL API 方法`glCompileShader()`来实现这一点，并传递我们想要编译的着色器的句柄。

当然，因为我们正在使用内存来存储着色器，我们应该知道如何在完成后进行清理。要删除着色器对象，我们可以调用`glDeleteShader()`函数。

删除着色器对象当不再需要着色器对象时，可以通过调用`glDeleteShader()`来删除。这将释放着色器对象使用的内存。应该注意，如果着色器对象已经附加到程序对象，即链接到着色器程序，它不会立即被删除，而是被标记为删除。如果对象被标记为删除，它将在从链接的着色器程序对象中分离时被删除。

一旦我们编译了我们的着色器，我们在将它们用于程序之前需要采取的下一步是将它们链接在一起成为一个完整的着色器程序。链接步骤的核心方面之一涉及从一个着色器的输入变量到另一个着色器的输出变量之间建立连接，并在着色器的输入/输出变量与 OpenGL 程序本身的适当位置之间建立连接。

链接与编译着色器非常相似。我们创建一个新的着色器程序，并将每个着色器对象附加到它上。然后我们告诉着色器程序对象将所有内容链接在一起。在 OpenGL 环境中实现这些步骤可以分解为对 API 的几个调用，如下所示：

首先，我们创建着色器程序对象：

```cpp
GLuint shaderProgram = glCreateProgram();
```

首先，我们调用`glCreateProgram()`方法创建一个空的程序对象。这个函数返回一个句柄给着色器程序对象，这个例子中我们将其存储在一个名为`shaderProgram`的变量中。

接下来，我们将着色器附加到程序对象：

```cpp
glAttachShader(shaderProgram, vertexShader);
glAttachShader(shaderProgram, fragmentShader);
```

为了将每个着色器加载到着色器程序中，我们使用`glAttachShader()`方法。这个方法接受两个参数。第一个参数是着色器程序对象的句柄，第二个是要附加到着色器程序的着色器对象的句柄。

最后，我们链接程序：

```cpp
glLinkProgram(programHandle);
```

当我们准备将着色器链接在一起时，我们调用`glLinkProgram()`方法。这个方法只有一个参数：我们要链接的着色器程序的句柄。

重要的是，我们记得清理掉我们不再使用的任何着色器程序。要从 OpenGL 内存中删除着色器程序，我们调用`glDeleteProgram()`方法。`glDeleteProgram()`方法接受一个参数：要删除的着色器程序的句柄。这个方法调用使句柄无效，并释放着色器程序使用的内存。重要的是要注意，如果着色器程序对象当前正在使用，它不会立即被删除，而是被标记为删除。这类似于删除着色器对象。还要注意，删除着色器程序将分离在链接时附加到着色器程序的任何着色器对象。然而，这并不意味着着色器对象会立即被删除，除非这些着色器对象已经被之前调用`glDeleteShader()`方法标记为删除。

这些就是创建、编译和链接着色器程序所需的简化 OpenGL API 调用。现在我们将继续实现一些结构，使整个过程更容易处理。为此，我们将创建一个名为`ShaderManager`的新类。这个类将充当编译、链接和管理着色器程序清理的接口。首先，让我们看一下`ShaderManager.cpp`文件中`CompileShaders()`方法的实现。我应该指出，我将专注于与架构实现相关的代码的重要方面。本章的完整源代码可以在 GitHub 存储库的`Chapter07`文件夹中找到。

```cpp
void ShaderManager::CompileShaders(const std::string&                        
                        vertexShaderFilePath, const std::string&      
                        fragmentShaderFilepath)
{
   m_programID = glCreateProgram();
   m_vertexShaderID = glCreateShader(GL_VERTEX_SHADER);
   if (m_vertexShaderID == 0){
      Exception("Vertex shader failed to be created!");
   }
   m_fragmentShaderID = glCreateShader(GL_FRAGMENT_SHADER);
   if (m_fragmentShaderID == 0){
    Exception("Fragment shader failed to be created!");
   }
   CompileShader(vertexShaderFilePath, m_vertexShaderID);
   CompileShader(fragmentShaderFilepath, m_fragmentShaderID);
}
```

首先，对于这个示例，我们专注于两种着色器类型，所以我们的`ShaderManager::CompileShaders()`方法接受两个参数。第一个参数是顶点着色器文件的文件路径位置，第二个是片段着色器文件的文件路径位置。两者都是字符串。在方法体内，我们首先使用`glCreateProgram()`方法创建着色器程序句柄，并将其存储在`m_programID`变量中。接下来，我们使用`glCreateShader()`命令创建顶点和片段着色器的句柄。我们在创建着色器句柄时检查是否有任何错误，如果有，我们会抛出一个带有失败的着色器名称的异常。一旦句柄被创建，我们接下来调用`CompileShader()`方法，接下来我们将看到。`CompileShader()`函数接受两个参数：第一个是着色器文件的路径，第二个是编译后的着色器将被存储的句柄。

以下是完整的`CompileShader()`函数。它处理了从存储中查找和加载着色器文件，以及在着色器文件上调用 OpenGL 编译命令。我们将逐块地分解它：

```cpp
void ShaderManager::CompileShader(const std::string& filePath, GLuint id) 
{
  std::ifstream shaderFile(filePath);
  if (shaderFile.fail()){
     perror(filePath.c_str());
     Exception("Failed to open " + filePath);
  }
    //File contents stores all the text in the file
     std::string fileContents = "";
    //line is used to grab each line of the file
    std::string line;
   //Get all the lines in the file and add it to the contents
    while (std::getline(shaderFile, line)){
    fileContents += line + "n";
 }
   shaderFile.close();
   //get a pointer to our file contents c string
   const char* contentsPtr = fileContents.c_str();   //tell opengl that        
   we want to use fileContents as the contents of the shader file 
  glShaderSource(id, 1, &contentsPtr, nullptr);
  //compile the shader
  glCompileShader(id);
  //check for errors
  GLint success = 0;
  glGetShaderiv(id, GL_COMPILE_STATUS, &success);
  if (success == GL_FALSE){
    GLint maxLength = 0;
    glGetShaderiv(id, GL_INFO_LOG_LENGTH, &maxLength);
    //The maxLength includes the NULL character
    std::vector<char> errorLog(maxLength);
    glGetShaderInfoLog(id, maxLength, &maxLength, &errorLog[0]);
    //Provide the infolog in whatever manor you deem best.
    //Exit with failure.
    glDeleteShader(id); //Don't leak the shader.
    //Print error log and quit
    std::printf("%sn", &(errorLog[0]));
        Exception("Shader " + filePath + " failed to compile");
  }
}
```

首先，我们使用一个`ifstream`对象打开包含着色器代码的文件。我们还检查是否有任何加载文件的问题，如果有，我们会抛出一个异常通知我们文件打开失败：

```cpp
std::ifstream shaderFile(filePath);
if (shaderFile.fail()) {
  perror(filePath.c_str());
  Exception("Failed to open " + filePath);
}
```

接下来，我们需要解析着色器。为此，我们创建一个名为`fileContents`的字符串变量，它将保存着色器文件中的文本。然后，我们创建另一个名为 line 的字符串变量；这将是我们试图解析的着色器文件的每一行的临时持有者。接下来，我们使用`while`循环逐行遍历着色器文件，逐行解析内容并将每个循环保存到`fileContents`字符串中。一旦所有行都被读入持有变量，我们调用`shaderFile`的`ifstream`对象上的 close 方法，以释放用于读取文件的内存：

```cpp
std::string fileContents = "";
std::string line;
while (std::getline(shaderFile, line)) {
  fileContents += line + "n";
}
shaderFile.close();
```

您可能还记得本章前面提到的，当我们使用`glShaderSource()`函数时，我们必须将着色器文件文本作为指向字符数组开头的指针传递。为了满足这一要求，我们将使用一个巧妙的技巧，即利用字符串类内置的 C 字符串转换方法，允许我们返回指向我们着色器字符数组开头的指针。如果您不熟悉，这本质上就是一个字符串：

```cpp
const char* contentsPtr = fileContents.c_str();
```

现在我们有了指向着色器文本的指针，我们可以调用`glShaderSource()`方法告诉 OpenGL 我们要使用文件的内容来编译我们的着色器。最后，我们使用着色器的句柄作为参数调用`glCompileShader()`方法：

```cpp
glShaderSource(id, 1, &contentsPtr, nullptr);
glCompileShader(id);
```

这处理了编译，但是为自己提供一些调试支持是个好主意。我们通过在`CompileShader()`函数中首先检查编译过程中是否有任何错误来实现这种编译调试支持。我们通过请求来自着色器编译器的信息来做到这一点，通过`glGetShaderiv()`函数，其中，它的参数之一是指定我们想要返回的信息。在这个调用中，我们请求编译状态：

```cpp
GLint success = 0;
glGetShaderiv(id, GL_COMPILE_STATUS, &success);
```

接下来，我们检查返回的值是否为`GL_FALSE`，如果是，那意味着我们出现了错误，应该向编译器请求更多关于编译问题的信息。我们首先询问编译器错误日志的最大长度。我们使用这个最大长度值来创建一个名为 errorLog 的字符值向量。然后，我们可以通过使用`glGetShaderInfoLog()`方法请求着色器编译日志，传入着色器文件的句柄、我们要提取的字符数以及我们要保存日志的位置：

```cpp
if (success == GL_FALSE){
  GLint maxLength = 0;
  glGetShaderiv(id, GL_INFO_LOG_LENGTH, &maxLength);
  std::vector<char> errorLog(maxLength); 
  glGetShaderInfoLog(id, maxLength, &maxLength, &errorLog[0]);
```

一旦我们保存了日志文件，我们继续使用`glDeleteShader()`方法删除着色器。这确保我们不会因为着色器而产生任何内存泄漏：

```cpp
glDeleteShader(id);
```

最后，我们首先将错误日志打印到控制台窗口。这对于运行时调试非常有用。我们还会抛出一个异常，其中包括着色器名称/文件路径以及编译失败的消息：

```cpp
std::printf("%sn", &(errorLog[0]));
Exception("Shader " + filePath + " failed to compile");
}
...
```

通过提供简单的接口来调用底层 API，这真的简化了编译着色器的过程。现在，在我们的示例程序中，要加载和编译着色器，我们使用类似以下的一行简单代码：

```cpp
shaderManager.CompileShaders("Shaders/SimpleShader.vert",
"Shaders/SimpleShader.frag");
```

现在编译了着色器，我们已经完成了可用着色器程序的一半。我们仍然需要添加一个部分，即链接。为了抽象出一些链接着色器的过程并为我们提供一些调试功能，我们将为我们的`ShaderManager`类创建`LinkShaders()`方法。让我们看一下，然后分解它：

```cpp
void ShaderManager::LinkShaders() {
//Attach our shaders to our program
glAttachShader(m_programID, m_vertexShaderID);
glAttachShader(m_programID, m_fragmentShaderID);
//Link our program
glLinkProgram(m_programID);
//Note the different functions here: glGetProgram* instead of glGetShader*.
GLint isLinked = 0;
glGetProgramiv(m_programID, GL_LINK_STATUS, (int *)&isLinked);
if (isLinked == GL_FALSE){
  GLint maxLength = 0;
  glGetProgramiv(m_programID, GL_INFO_LOG_LENGTH, &maxLength);
  //The maxLength includes the NULL character
  std::vector<char> errorLog(maxLength);
  glGetProgramInfoLog(m_programID, maxLength, &maxLength,   
  &errorLog[0]);
  //We don't need the program anymore.
  glDeleteProgram(m_programID);
  //Don't leak shaders either.
  glDeleteShader(m_vertexShaderID);
  glDeleteShader(m_fragmentShaderID);
  //print the error log and quit
  std::printf("%sn", &(errorLog[0]));
  Exception("Shaders failed to link!");
}
  //Always detach shaders after a successful link.
  glDetachShader(m_programID, m_vertexShaderID);
  glDetachShader(m_programID, m_fragmentShaderID);
  glDeleteShader(m_vertexShaderID);
  glDeleteShader(m_fragmentShaderID);
}
```

要开始我们的`LinkShaders()`函数，我们调用`glAttachShader()`方法两次，分别使用先前创建的着色器程序对象的句柄和我们希望链接的每个着色器的句柄：

```cpp
glAttachShader(m_programID, m_vertexShaderID);
glAttachShader(m_programID, m_fragmentShaderID);
```

接下来，我们通过调用`glLinkProgram()`方法，使用程序对象的句柄作为参数，执行实际的着色器链接，将它们链接成一个可用的着色器程序：

```cpp
glLinkProgram(m_programID);
```

然后我们可以检查链接过程是否已经完成，没有任何错误，并提供任何调试信息，如果有任何错误的话。我不会逐行讲解这段代码，因为它几乎与我们使用`CompileShader()`函数时所做的工作完全相同。但是请注意，从链接器返回信息的函数略有不同，使用的是`glGetProgram*`而不是之前的`glGetShader*`函数：

```cpp
GLint isLinked = 0;
glGetProgramiv(m_programID, GL_LINK_STATUS, (int *)&isLinked);
if (isLinked == GL_FALSE){
  GLint maxLength = 0;
  glGetProgramiv(m_programID, GL_INFO_LOG_LENGTH, &maxLength);
  //The maxLength includes the NULL character
  std::vector<char> errorLog(maxLength);  
  glGetProgramInfoLog(m_programID, maxLength, &maxLength,   
  &errorLog[0]);
  //We don't need the program anymore.
  glDeleteProgram(m_programID);
  //Don't leak shaders either.
  glDeleteShader(m_vertexShaderID);
  glDeleteShader(m_fragmentShaderID);
  //print the error log and quit
  std::printf("%sn", &(errorLog[0]));
  Exception("Shaders failed to link!");
}
```

最后，如果我们在链接过程中成功了，我们需要稍微清理一下。首先，我们使用`glDetachShader()`方法从链接器中分离着色器。接下来，由于我们有一个完成的着色器程序，我们不再需要保留着色器在内存中，所以我们使用`glDeleteShader()`方法删除每个着色器。同样，这将确保我们在着色器程序创建过程中不会泄漏任何内存：

```cpp
  glDetachShader(m_programID, m_vertexShaderID);
  glDetachShader(m_programID, m_fragmentShaderID);
  glDeleteShader(m_vertexShaderID);
  glDeleteShader(m_fragmentShaderID);
}
```

现在我们有了一个简化的方式将我们的着色器链接到一个工作的着色器程序中。我们可以通过简单地使用一行代码来调用这个接口到底层的 API 调用，类似于以下的代码：

```cpp
  shaderManager.LinkShaders();
```

这样处理了编译和链接着色器的过程，但与着色器一起工作的另一个关键方面是将数据传递给运行在 GPU 上的程序/游戏和着色器程序之间的数据传递。我们将看看这个过程，以及如何将其抽象成一个易于使用的接口，用于我们引擎。接下来。

# 处理着色器数据

与着色器一起工作的最重要的方面之一是能够将数据传递给运行在 GPU 上的着色器程序，并从中传递数据。这可能是一个深入的话题，就像本书中的其他话题一样，有专门的书籍来讨论。在讨论这个话题时，我们将保持在较高的层次上，并再次专注于基本渲染所需的两种着色器类型：顶点和片段着色器。

首先，让我们看看如何使用顶点属性和**顶点缓冲对象**（**VBO**）将数据发送到着色器。顶点着色器的工作是处理与顶点连接的数据，进行任何修改，然后将其传递到渲染管线的下一阶段。这是每个顶点发生一次。为了使着色器发挥作用，我们需要能够传递数据给它。为此，我们使用所谓的顶点属性，它们通常与所谓的 VBO 紧密配合工作。

对于顶点着色器，所有每个顶点的输入属性都使用关键字`in`进行定义。例如，如果我们想要定义一个名为`VertexColour`的三维向量输入属性，我们可以写如下内容：

```cpp
in vec3 VertexColour;
```

现在，`VertexColour`属性的数据必须由程序/游戏提供。这就是 VBO 发挥作用的地方。在我们的主游戏或程序中，我们建立输入属性和顶点缓冲对象之间的连接，还必须定义如何解析或遍历数据。这样，当我们渲染时，OpenGL 可以从缓冲区中为每个顶点着色器调用提取属性的数据。

让我们来看一个非常简单的顶点着色器：

```cpp
#version 410
in vec3 VertexPosition;
in vec3 VertexColour;
out vec3 Colour;
void main(){
  Colour = VertexColour;
  gl_Position = vec4(VertexPosition, 1.0);
}
```

在这个例子中，这个顶点着色器只有两个输入变量，`VertexPosition`和`VertexColor`。我们的主 OpenGL 程序需要为每个顶点提供这两个属性的数据。我们将通过将我们的多边形/网格数据映射到这些变量来实现。我们还有一个名为`Colour`的输出变量，它将被发送到渲染管线的下一阶段，即片段着色器。在这个例子中，`Colour`只是`VertexColour`的一个未经处理的副本。`VertexPosition`属性只是被扩展并传递到 OpenGL API 输出变量`gl_Position`以进行更多处理。

接下来，让我们来看一个非常简单的片段着色器：

```cpp
#version 410
in vec3 Colour;
out vec4 FragColour;
void main(){
  FragColour = vec4(Colour, 1.0);
}
```

在这个片段着色器示例中，只有一个输入属性`Colour`。这个输入对应于前一个渲染阶段的输出，顶点着色器的`Colour`输出。为了简单起见，我们只是扩展了`Colour`并将其输出为下一个渲染阶段的变量`FragColour`。

这总结了连接的着色器部分，那么我们如何在引擎内部组合和发送数据呢？我们可以基本上通过四个步骤来完成这个过程。

首先，我们创建一个**顶点数组对象**（**VAO**）实例来保存我们的数据：

```cpp
GLunit vao;
```

接下来，我们为每个着色器的输入属性创建和填充 VBO。我们首先创建一个 VBO 变量，然后使用`glGenBuffers()`方法生成缓冲对象的内存。然后，我们为我们需要缓冲区的不同属性创建句柄，并将它们分配给 VBO 数组中的元素。最后，我们通过首先调用`glBindBuffer()`方法为每个属性填充缓冲区，指定要存储的对象类型。在这种情况下，对于两个属性，它是`GL_ARRAY_BUFFER`。然后我们调用`glBufferData()`方法，传递类型、大小和绑定句柄。`glBufferData()`方法的最后一个参数是一个提示 OpenGL 如何最好地管理内部缓冲区的参数。有关此参数的详细信息，请参阅 OpenGL 文档：

```cpp
GLuint vbo[2];
glGenBuffers(2, vbo);
GLuint positionBufferHandle = vbo[0];
GLuint colorBufferHandle = vbo[1];
glBindBuffer(GL_ARRAY_BUFFER,positionBufferHandle);
glBufferData(GL_ARRAY_BUFFER,
             9 * sizeof(float),
             positionData,
             GL_STATIC_DRAW);
glBindBuffer(GL_ARRAY_BUFFER,
             colorBufferHandle);
glBufferData(GL_ARRAY_BUFFER,
             9 * sizeof(float),
             colorData,
             GL_STATIC_DRAW);
```

第三步是创建和定义 VAO。这是我们将定义着色器的输入属性和我们刚刚创建的缓冲区之间关系的方法。VAO 包含了关于这些连接的信息。要创建一个 VAO，我们使用`glGenVertexArrays()`方法。这给了我们一个新对象的句柄，我们将其存储在之前创建的 VAO 变量中。然后，我们通过调用`glEnableVertexAttribArray()`方法来启用通用顶点属性索引 0 和 1。通过调用启用属性，我们指定它们将被访问和用于渲染。最后一步是将我们创建的缓冲对象与通用顶点属性索引进行匹配：

```cpp
glGenVertexArrays( 1, &vao );
glBindVertexArray(vao);
glEnableVertexAttribArray(0);
glEnableVertexAttribArray(1);
glBindBuffer(GL_ARRAY_BUFFER, positionBufferHandle);
glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 0, NULL);
glBindBuffer(GL_ARRAY_BUFFER, colorBufferHandle);
glVertexAttribPointer(1, 3, GL_FLOAT, GL_FALSE, 0, NULL);
```

最后，在我们的`Draw()`函数调用中，我们绑定到 VAO 并调用`glDrawArrays()`来执行实际的渲染：

```cpp
glBindVertexArray(vaoHandle);glDrawArrays(GL_TRIANGLES, 0, 3 );
```

在我们继续传递数据到着色器的另一种方式之前，我们需要讨论这种属性连接结构的另一个部分。如前所述，着色器中的输入变量在链接时与我们刚刚看到的通用顶点属性相关联。当我们需要指定关系结构时，我们有几种不同的选择。我们可以在着色器代码本身中使用称为布局限定符的内容。以下是一个例子：

```cpp
layout (location=0) in vec3 VertexPosition;
```

另一种选择是让链接器在链接时创建映射，然后在之后查询它们。我个人更喜欢的第三种方法是在链接过程之前指定关系，通过调用`glBindAttribLocation()`方法。我们将在讨论如何抽象这些过程时很快看到这是如何实现的。

我们已经描述了如何使用属性将数据传递给着色器，但还有另一个选择：统一变量。统一变量专门用于不经常更改的数据。例如，矩阵非常适合作为统一变量的候选对象。在着色器内部，统一变量是只读的。这意味着该值只能从着色器外部更改。它们还可以出现在同一着色器程序中的多个着色器中。它们可以在程序中的一个或多个着色器中声明，但是如果具有给定名称的变量在多个着色器中声明，则其类型在所有着色器中必须相同。这使我们了解到统一变量实际上是在整个着色器程序的共享命名空间中保存的。

要在着色器中使用统一变量，首先必须在着色器文件中使用统一标识符关键字声明它。以下是这可能看起来的样子：

```cpp
uniform mat4 ViewMatrix;
```

然后我们需要从游戏/程序内部提供统一变量的数据。我们通过首先使用`glGetUniformLocation()`方法找到变量的位置，然后使用`glUniform()`方法之一为找到的位置赋值。这个过程的代码可能看起来像下面这样：

```cpp
GLuint location = glGetUniformLocation(programHandle," ViewMatrix ");
if( location >= 0 )
{
glUniformMatrix4fv(location, 1, GL_FALSE, &viewMatrix [0][0])
}
```

然后我们使用`glUniformMatrix4fv()`方法为统一变量的位置赋值。第一个参数是统一变量的位置。第二个参数是正在分配的矩阵的数量。第三个是 GL `bool`类型，指定矩阵是否应该被转置。由于我们在矩阵中使用 GLM 库，不需要转置。如果您使用的是按行顺序而不是按列顺序的数据来实现矩阵，您可能需要对这个参数使用`GL_TRUE`类型。最后一个参数是统一变量的数据的指针。

统一变量可以是任何 GLSL 类型，包括结构和数组等复杂类型。OpenGL API 提供了与每种类型匹配的不同后缀的`glUniform()`函数。例如，要分配给`vec3`类型的变量，我们将使用`glUniform3f()`或`glUniform3fv()`方法（*v*表示数组中的多个值）。

因此，这些是将数据传递给着色器程序和从着色器程序传递数据的概念和技术。然而，就像我们为编译和链接着色器所做的那样，我们可以将这些过程抽象成我们`ShaderManager`类中的函数。我们将专注于处理属性和统一变量。我们有一个很好的类来抽象模型/网格的 VAO 和 VBO 的创建，我们在第四章中详细讨论了这一点，*构建游戏系统*，当时我们讨论了构建资产流水线。要查看它是如何构建的，要么翻回到[第四章](https://cdp.packtpub.com/mastering_c___game_development/wp-admin/post.php?post=325&action=edit#post_245)，*构建游戏系统*，要么查看`BookEngine`解决方案的`Mesh.h`和`Mesh.cpp`文件中的实现。

首先，我们将看一下使用`ShaderManger`类的`AddAttribute()`函数添加属性绑定的抽象。这个函数接受一个参数，作为字符串绑定的属性名称。然后我们调用`glBindAttribLocation()`函数，传递程序的句柄和当前属性的索引或数量，我们在调用时增加，最后是`attributeName`字符串的 C 字符串转换，它提供了指向字符串数组中第一个字符的指针。这个函数必须在编译之后调用，但在着色器程序链接之前调用。

```cpp
void ShaderManager::AddAttribute(const std::string& attributeName)
{
glBindAttribLocation(m_programID,
                     m_numAttributes++,
                     attributeName.c_str());
 }
```

对于统一变量，我们创建一个抽象查找着色器程序中统一变量位置的函数`GetUniformLocation()`。这个函数再次只接受一个变量，即以字符串形式的统一变量名称。然后我们创建一个临时持有者来保存位置，并将其赋值为`glGetUniformLocation()`方法调用的返回值。我们检查位置是否有效，如果不是，我们抛出一个异常，让我们知道错误。最后，如果找到，我们返回有效的位置。

```cpp
GLint ShaderManager::GetUniformLocation(const std::string& uniformName)
{
    GLint location = glGetUniformLocation(m_programID,
    uniformName.c_str());
    if (location == GL_INVALID_INDEX) 
    {
     Exception("Uniform " + uniformName + " not found in shader!");
    }
  return location;
}
```

这为我们绑定数据提供了抽象，但我们仍然需要指定哪个着色器应该用于某个绘制调用，并激活我们需要的任何属性。为了实现这一点，我们在`ShaderManager`中创建一个名为`Use()`的函数。这个函数将首先使用`glUseProgram()`API 方法调用将当前着色器程序设置为活动的着色器程序。然后我们使用一个 for 循环来遍历着色器程序的属性列表，激活每一个：

```cpp
void ShaderManager::Use(){
  glUseProgram(m_programID);
  for (int i = 0; i < m_numAttributes; i++) { 
    glEnableVertexAttribArray(i);
  }
}
```

当然，由于我们有一种抽象的方法来启用着色器程序，所以我们应该有一个函数来禁用着色器程序。这个函数与`Use()`函数非常相似，但在这种情况下，我们将正在使用的程序设置为 0，有效地使其为`NULL`，并使用`glDisableVertexAtrribArray()`方法在 for 循环中禁用属性：

```cpp
void ShaderManager::UnUse() {
  glUseProgram(0);
  for (int i = 0; i < m_numAttributes; i++) {
    glDisableVertexAttribArray(i);
 }
}
```

这种抽象的净效果是，我们现在可以通过几个简单的调用来设置整个着色器程序结构。类似以下的代码将创建和编译着色器，添加必要的属性，将着色器链接到程序中，找到一个统一变量，并为网格创建 VAO 和 VBO：

```cpp
shaderManager.CompileShaders("Shaders/SimpleShader.vert",
                             "Shaders/SimpleShader.frag");
shaderManager.AddAttribute("vertexPosition_modelspace");
shaderManager.AddAttribute("vertexColor");
shaderManager.LinkShaders();
MatrixID = shaderManager.GetUniformLocation("ModelViewProjection");
m_model.Init("Meshes/Dwarf_2_Low.obj", "Textures/dwarf_2_1K_color.png");
```

然后，在我们的`Draw`循环中，如果我们想要使用这个着色器程序进行绘制，我们可以简单地使用抽象函数来激活和停用我们的着色器，类似于以下代码：

```cpp
  shaderManager.Use();
  m_model.Draw();
  shaderManager.UnUse();
```

这使得我们更容易使用着色器来测试和实现高级渲染技术。我们将使用这种结构来构建本章剩余部分以及实际上整本书的示例。

# 光照效果

着色器最常见的用途之一是创建光照和反射效果。通过使用着色器实现的光照效果有助于提供每个现代游戏都追求的一定程度的光泽和细节。在接下来的部分，我们将看一些用于创建不同表面外观效果的知名模型，并提供可以实现所讨论的光照效果的着色器示例。

# 每顶点漫反射

首先，我们将看一下其中一个较为简单的光照顶点着色器，即漫反射反射着色器。漫反射被认为更简单，因为我们假设我们正在渲染的表面看起来在所有方向上均匀地散射光线。通过这个着色器，光线与表面接触并在稍微穿透后在所有方向上被投射出去。这意味着一些光的波长至少部分被吸收。漫反射着色器的一个很好的例子是哑光油漆。表面看起来非常暗淡，没有光泽。

让我们快速看一下漫反射的数学模型。这个反射模型需要两个向量。一个是表面接触点到初始光源的方向，另一个是同一表面接触点的法向量。这看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/61cd3123-d51e-46a5-9e49-fe95a5c7b232.png)

值得注意的是，击中表面的光量部分取决于表面与光源的关系，而达到单个点的光量在法向量上最大，在法向量垂直时最低。通过计算点法向量和入射光线的点积，我们可以表达这种关系。这可以用以下公式表示：

*光密度（源向量）法向量*

这个方程中的源向量和法向量被假定为归一化。

如前所述，表面上的一些光线在重新投射之前会被吸收。为了将这种行为添加到我们的数学模型中，我们可以添加一个反射系数，也称为漫反射率。这个系数值成为入射光的缩放因子。我们指定出射光强度的新公式现在看起来像下面这样：

出射光 = (漫反射系数 x 光密度 x 光源向量) 法向量

有了这个新的公式，我们现在有了一个代表全向均匀散射的光照模型。

好了，现在我们知道了理论，让我们看看如何在 GLSL 着色器中实现这个光照模型。这个例子的完整源代码可以在 GitHub 存储库的`Chapter07`文件夹中找到，从以下所示的顶点着色器开始：

```cpp
#version 410
in vec3 vertexPosition_modelspace;
in vec2 vertexUV;
in vec3 vertexNormal;
out vec2 UV;
out vec3 LightIntensity;
uniform vec4 LightPosition;
uniform vec3 DiffuseCoefficient ;
uniform vec3 LightSourceIntensity;
uniform mat4 ModelViewProjection;
uniform mat3 NormalMatrix;
uniform mat4 ModelViewMatrix;
uniform mat4 ProjectionMatrix;
void main(){
    vec3 tnorm = normalize(NormalMatrix * vertexNormal);
    vec4 CameraCoords = ModelViewMatrix *
    vec4(vertexPosition_modelspace,1.0);
    vec3 IncomingLightDirection = normalize(vec3(LightPosition -
    CameraCoords));
    LightIntensity = LightSourceIntensity * DiffuseCoefficient *
                     max( dot( IncomingLightDirection, tnorm ), 0.0 );
    gl_Position = ModelViewProjection *                   
                  vec4(vertexPosition_modelspace,1);
                  UV = vertexUV;
 }
```

我们将逐块地浏览这个着色器。首先，我们有我们的属性，`vertexPosition_modelspace`，`vertexUV`和`vertexNormal`。这些将由我们的游戏应用程序设置，在我们浏览完着色器之后我们会看到。然后我们有我们的输出变量，UV 和`LightIntensity`。这些值将在着色器中计算。然后我们有我们的 uniform 变量。这些包括我们讨论过的反射计算所需的值。它还包括所有必要的矩阵。与属性一样，这些 uniform 值将通过我们的游戏设置。

在这个着色器的主函数内部，我们的漫反射将在相机相对坐标中计算。为了实现这一点，我们首先通过将顶点法线乘以法线矩阵来归一化顶点法线，并将结果存储在一个名为`tnorm`的向量 3 变量中。接下来，我们通过使用模型视图矩阵将目前在模型空间中的顶点位置转换为相机坐标，从而计算出入射光方向，归一化，通过从相机坐标中的顶点位置减去光的位置。接下来，我们通过使用我们之前讨论过的公式计算出射光强度。这里需要注意的一点是使用 max 函数。这是当光线方向大于 90 度时的情况，就像光线是从物体内部发出一样。由于在我们的情况下，我们不需要支持这种情况，所以当出现这种情况时，我们只使用`0.0`的值。为了关闭着色器，我们将在裁剪空间中计算的模型视图投影矩阵存储在内置的输出变量`gl_position`中。我们还传递纹理的 UV，未更改，这在这个例子中实际上并没有使用。

现在我们已经有了着色器，我们需要提供计算所需的值。正如我们在本章的第一节中所学的，我们通过设置属性和 uniform 来实现这一点。我们构建了一个抽象层来帮助这个过程，所以让我们看看我们如何在游戏代码中设置这些值。在`GamePlayScreen.cpp`文件中，我们在`Draw()`函数中设置这些值。我应该指出，这是一个例子，在生产环境中，出于性能原因，你只想在循环中设置变化的值。由于这是一个例子，我想让它稍微容易一些：

```cpp
GLint DiffuseCoefficient =    
        shaderManager.GetUniformLocation("DiffuseCoefficient ");
glUniform3f(DiffuseCoefficient, 0.9f, 0.5f, 0.3f);
GLint LightSourceIntensity =    
       shaderManager.GetUniformLocation("LightSourceIntensity ");
glUniform3f(LightSourceIntensity, 1.0f, 1.0f, 1.0f);
glm::vec4 lightPos = m_camera.GetView() * glm::vec4(5.0f, 5.0f, 2.0f,              
                     1.0f);
GLint lightPosUniform =      
                shaderManager.GetUniformLocation("LightPosition");
glUniform4f(lightPosUniform, lightPos[0], lightPos[1], lightPos[2],    
             lightPos[3]);
glm::mat4 modelView = m_camera.GetView() * glm::mat4(1.0f);
GLint modelViewUniform =           
               shaderManager.GetUniformLocation("ModelViewMatrix");
glUniformMatrix4fv(modelViewUniform, 1, GL_FALSE, &modelView[0][0]);
glm::mat3 normalMatrix = glm::mat3(glm::vec3(modelView[0]),     
                         glm::vec3(modelView[1]),  
                         glm::vec3(modelView[2]));
GLint normalMatrixUniform =     
                   shaderManager.GetUniformLocation("NormalMatrix");
glUniformMatrix3fv(normalMatrixUniform, 1, GL_FALSE, &normalMatrix[0][0]);
glUniformMatrix4fv(MatrixID, 1, GL_FALSE, &m_camera.GetMVPMatrix()[0][0]);
```

我不会逐行进行，因为我相信你可以看到模式。我们首先使用着色器管理器的`GetUniformLocation()`方法返回 uniform 的位置。接下来，我们使用 OpenGL 的`glUniform*()`方法设置这个 uniform 的值，该方法与值类型匹配。我们对所有需要的 uniform 值都这样做。我们还必须设置我们的属性，并且正如本章开头讨论的那样，我们要在编译和链接过程之间进行这样的操作。在这个例子中，我们在`GamePlayScreen()`类的`OnEntry()`方法中设置这些值：

```cpp
shaderManager.AddAttribute("vertexPosition_modelspace");
shaderManager.AddAttribute("vertexColor");
shaderManager.AddAttribute("vertexNormal");
```

这样就处理了顶点着色器和传入所需的值，接下来，让我们看看这个例子的片段着色器：

```cpp
#version 410
in vec2 UV;
in vec3 LightIntensity;
// Ouput data
out vec3 color;
// Values that stay constant for the whole mesh.
uniform sampler2D TextureSampler;
void main(){
  color = vec3(LightIntensity);
}
```

对于这个示例，我们的片段着色器非常简单。首先，我们有我们的 UV 和`LightIntensity`的输入值，这次我们只使用`LightIntensity`。然后，我们声明了我们的输出颜色值，指定为一个矢量 3。接下来，我们有用于纹理的`sampler2D`统一变量，但在这个示例中我们也不会使用这个值。最后，我们有主函数。这是我们通过简单地将`LightIntensity`传递到管道中的下一个阶段来设置最终输出颜色的地方。

如果你运行示例项目，你会看到漫反射的效果。输出应该看起来像下面的屏幕截图。正如你所看到的，这种反射模型对于非常迟钝的表面效果很好，但在实际环境中的使用有限。接下来，我们将看一下一个反射模型，它将允许我们描绘更多的表面类型：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/8e83e885-ac5e-4c00-91b7-03998dd9380e.png)

# 每顶点环境、漫反射和镜面

**环境**、**漫反射**和**镜面**（**ADS**）反射模型，也通常被称为**冯氏反射模型**，提供了一种创建反射光照着色器的方法。这种技术使用三种不同组件的组合来模拟光线在表面上的相互作用。环境组件模拟来自环境的光线；这意味着模拟光线被反射多次的情况，看起来好像它从任何地方都发出。我们在之前的示例中建模的漫反射组件代表了一个全向反射。最后一个组件，镜面组件，旨在表示在一个首选方向上的反射，提供了光*眩光*或明亮的点的外观。

这些组件的组合可以使用以下图表来可视化：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/45633898-8754-47a0-b4b8-f102297cca8f.png)

来源：维基百科

这个过程可以分解成讨论各个组件。首先，我们有环境组件，代表将均匀照亮所有表面并在所有方向上均匀反射的光线。这种光照效果不依赖于光线的入射或出射向量，因为它是均匀分布的，可以简单地通过将光源强度与表面反射性相乘来表示。这在数学公式 *I[a] = L[a]K[a]* 中显示。

下一个组件是我们之前讨论过的漫反射组件。漫反射组件模拟了一个粗糙或粗糙的表面，将光线散射到所有方向。同样，这可以用数学公式 *I[d] = L[d]Kd* 来表示。

最后一个组件是镜面组件，它用于模拟表面的*光泽*。这会产生一个*眩光*或明亮的点，在表现出光滑特性的表面上很常见。我们可以使用以下图表来可视化这种反射效果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/46525544-c9ce-4200-b03c-bf4de5fc5118.png)

对于镜面分量，理想情况下，我们希望当与反射向量对齐时，反射最明显，然后随着角度的增加或减小而逐渐减弱。我们可以使用我们的观察向量和反射角之间的角度的余弦来模拟这种效果，然后将其提高到某个幂，如下面的方程所示：*(r v) ^p*。在这个方程中，*p*代表镜面高光，*眩光*点。输入的*p*值越大，点的大小就会越小，表面看起来就会*更光滑*。在添加了表示表面反射性和镜面光强度的值之后，用于计算表面镜面效果的公式如下：*I[s] = L[s]Ks ^p*。

现在，如果我们将所有组件放在一起并用一个公式表示，我们得到 *I = I[a] + I[d] + I[s]* 或者更详细地分解为 *I = L[a]K[a] + L[d]Kd + L[s]Ks ^p*。

有了我们的理论基础，让我们看看如何在每顶点着色器中实现这一点，从我们的顶点着色器开始如下：

```cpp
#version 410
// Input vertex data, different for all executions of this shader.
in vec3 vertexPosition_modelspace;
in vec2 vertexUV;
in vec3 vertexNormal;
// Output data ; will be interpolated for each fragment.
out vec2 UV;
out vec3 LightIntensity;
struct LightInfo {
  vec4 Position; // Light position in eye coords.
  vec3 La; // Ambient light intensity
  vec3 Ld; // Diffuse light intensity
  vec3 Ls; // Specular light intensity
};
uniform LightInfo Light;
struct MaterialInfo {
  vec3 Ka; // Ambient reflectivity
  vec3 Kd; // Diffuse reflectivity
  vec3 Ks; // Specular reflectivity
  float Shininess; // Specular shininess factor
};
  uniform MaterialInfo Material;
  uniform mat4 ModelViewMatrix;
  uniform mat3 NormalMatrix;
  uniform mat4 ProjectionMatrix;
  uniform mat4 ModelViewProjection;
  void main(){
     vec3 tnorm = normalize( NormalMatrix * vertexNormal);
     vec4 CameraCoords = ModelViewMatrix *                
                     vec4(vertexPosition_modelspace,1.0);
     vec3 s = normalize(vec3(Light.Position - CameraCoords));
     vec3 v = normalize(-CameraCoords.xyz);
     vec3 r = reflect( -s, tnorm );
     float sDotN = max( dot(s,tnorm), 0.0 );
     vec3 ambient = Light.La * Material.Ka;
     vec3 diffuse = Light.Ld * Material.Kd * sDotN;
     vec3 spec = vec3(0.0);
     if( sDotN > 0.0 )
      spec = Light.Ls * Material.Ks *
      pow( max( dot(r,v), 0.0 ), Material.Shininess );
      LightIntensity = ambient + diffuse + spec;
      gl_Position = ModelViewProjection *
                vec4(vertexPosition_modelspace,1.0);
}
```

让我们先看看有什么不同。在这个着色器中，我们引入了一个新概念，即统一结构。我们声明了两个`struct`，一个用于描述光线，`LightInfo`，一个用于描述材质，`MaterialInfo`。这是一种非常有用的方式，可以将代表公式中一部分的值作为集合来包含。我们很快就会看到如何设置这些`struct`元素的值从游戏代码中。接着是函数的主要部分。首先，我们像在上一个例子中一样开始。我们计算`tnorm`，`CameraCoords`和光源向量。接下来，我们计算指向观察者/摄像机的向量(v)，这是规范化的`CameraCoords`的负值。然后，我们使用提供的 GLSL 方法计算*纯*反射的方向。然后我们继续计算我们三个分量的值。环境光通过将光环境强度和表面的环境反射值相乘来计算。`diffuse`使用光强度、表面漫反射值和光源向量与`tnorm`的点积的结果来计算，我们刚刚在环境值之前计算了这个值。在计算镜面反射值之前，我们检查了`sDotN`的值。如果`sDotN`为零，则没有光线到达表面，因此没有计算镜面分量的意义。如果`sDotN`大于零，我们计算镜面分量。与前面的例子一样，我们使用 GLSL 方法将点积的值限制在`1`和`0`之间。GLSL 函数`pow`将点积提升到表面光泽指数的幂，我们之前在着色器方程中定义为`p`。

最后，我们将这三个分量值相加，并将它们的总和作为 out 变量`LightIntensity`传递给片段着色器。最后，我们将顶点位置转换为裁剪空间，并通过将其分配给`gl_Position`变量将其传递到下一个阶段。

对于我们着色器所需的属性和统一变量的设置，我们处理过程与前面的例子中一样。这里的主要区别在于，我们需要在获取统一位置时指定我们正在分配的`struct`的元素。一个示例看起来类似于以下内容，您可以在 GitHub 存储库的`Chapter07`文件夹中的示例解决方案中看到完整的代码：

```cpp
GLint Kd = shaderManager.GetUniformLocation("Material.Kd");
glUniform3f(Kd, 0.9f, 0.5f, 0.3f);
```

这个例子使用的片段着色器与我们用于漫反射的片段着色器相同，所以我在这里不再介绍它。

当您从 GitHub 存储库的`Chapter07`代码解决方案中运行 ADS 示例时，您将看到我们新创建的着色器生效，输出类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/1b255e28-0a5a-4456-8efc-86158d5d6514.png)

在这个例子中，我们在顶点着色器中计算了阴影方程；这被称为每顶点着色器。这种方法可能会出现的一个问题是我们

*眩光*点，镜面高光，可能会出现扭曲或消失的现象。这是由于阴影被插值而不是针对脸部的每个点进行计算造成的。例如，设置在脸部中间附近的点可能不会出现，因为方程是在镜面分量接近零的顶点处计算的。在下一个例子中，我们将看一种可以通过在片段着色器中计算反射来消除这个问题的技术。

# 每片段 Phong 插值

在以前的例子中，我们一直在使用顶点着色器来处理光照计算。使用顶点着色器来评估每个顶点的颜色时会出现一个问题，就像在上一个例子中提到的那样，即颜色然后在整个面上进行插值。这可能会导致一些不太理想的效果。有另一种方法可以实现相同的光照效果，但精度更高。我们可以将计算移到片段着色器中。在片段着色器中，我们不是在整个面上进行插值，而是在法线和位置上进行插值，并使用这些值来在每个片段上计算。这种技术通常被称为**冯氏插值**。这种技术的结果比使用每个顶点实现的结果要准确得多。然而，由于这种按片段实现会评估每个片段，而不仅仅是顶点，所以这种实现比按顶点的技术运行得更慢。

让我们从查看这个例子的顶点着色器开始实现着色器的实现：

```cpp
#version 410
in vec3 vertexPosition_modelspace;
in vec2 vertexUV;
in vec3 vertexNormal;
out vec2 UV;
out vec3 Position;
out vec3 Normal;
uniform mat4 ModelViewMatrix;
uniform mat3 NormalMatrix;
uniform mat4 ProjectionMatrix;
uniform mat4 ModelViewProjection;
void main(){
    UV = vertexUV;
    Normal = normalize( NormalMatrix * vertexNormal);
    Position = vec3( ModelViewMatrix *        
               vec4(vertexPosition_modelspace,1.0));
    gl_Position = ModelViewProjection *
                 vec4(vertexPosition_modelspace,1.0);
}
```

由于这种技术使用片段着色器来执行计算，我们的顶点着色器相当轻。在大多数情况下，我们正在进行一些简单的方程来计算法线和位置，然后将这些值传递到下一个阶段。

接下来，我们将看一下这种技术在片段着色器中的核心实现。以下是完整的片段着色器，我们将介绍与以前例子的不同之处：

```cpp
#version 410
in vec3 Position;
in vec3 Normal;
in vec2 UV;
uniform sampler2D TextureSampler;
struct LightInfo {
  vec4 Position; // Light position in eye coords.
  vec3 Intensity; // A,D,S intensity
};
uniform LightInfo Light;
struct MaterialInfo {
  vec3 Ka; // Ambient reflectivity
  vec3 Kd; // Diffuse reflectivity
  vec3 Ks; // Specular reflectivity
  float Shininess; // Specular shininess factor
};
uniform MaterialInfo Material;
out vec3 color;
void phongModel( vec3 pos, vec3 norm, out vec3 ambAndDiff, out vec3
spec ) {
  vec3 s = normalize(vec3(Light.Position) - pos);
  vec3 v = normalize(-pos.xyz);
  vec3 r = reflect( -s, norm );
  vec3 ambient = Light.Intensity * Material.Ka;
  float sDotN = max( dot(s,norm), 0.0 );
  vec3 diffuse = Light.Intensity * Material.Kd * sDotN;
  spec = vec3(0.0);
  if( sDotN > 0.0 )
   spec = Light.Intensity * Material.Ks *
        pow( max( dot(r,v), 0.0 ), Material.Shininess );
        ambAndDiff = ambient + diffuse;
}
void main() {
   vec3 ambAndDiff, spec;
   vec3 texColor = texture( TextureSampler, UV ).rbg;
   phongModel( Position, Normal, ambAndDiff, spec );
   color = (vec3(ambAndDiff * texColor) + vec3(spec));
 }
```

这个片段着色器应该看起来非常熟悉，因为它几乎与我们以前的例子中的顶点着色器相同。除了这将按片段而不是按顶点运行之外，另一个重要的区别是我们通过实现一个处理冯氏模型计算的函数来清理着色器。这次我们还要传递一个纹理，把纹理还给小矮人。冯氏模型计算与我们以前看到的完全相同，所以我不会再次介绍它。我们将它移到一个函数中的原因主要是为了可读性，因为它使主函数保持整洁。在 GLSL 中创建函数几乎与在 C++和 C 中相同。你有一个返回类型，一个函数名，后面跟着参数和一个主体。我强烈建议在任何比几行更复杂的着色器中使用函数。

为了将我们的着色器连接到游戏中的值，我们遵循与之前相同的技术，在那里我们设置所需的属性和统一值。在这个例子中，我们必须提供 Ka、Kd、Ks、材料光泽度、`LightPosition`和`LightIntensity`的值。这些值与先前描述的 ADS 方程相匹配。我们还需要传递通常的矩阵值。完整的代码可以再次在 GitHub 存储库的`Chapter07`文件夹中找到。

如果我们运行`Chapter07`解决方案中的`Phong_Example`，我们将看到新的着色器在运行中，包括纹理和更准确的反射表示。以下是输出的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/5fcd5f76-14f7-4684-a7a6-45e392f66a21.png)

我们将在这里结束我们对光照技术的讨论，但我鼓励你继续研究这个主题。使用着色器可以实现许多有趣的光照效果，我们只是刚刚开始涉及。在下一节中，我们将看一下着色器的另一个常见用途：渲染效果。

# 使用着色器创建效果

着色器不仅仅局限于创建光照效果。您可以使用不同的着色器技术创建许多不同的视觉效果。在本节中，我们将介绍一些有趣的效果，包括使用丢弃关键字来*丢弃*像素，并使用着色器创建一个简单的粒子效果系统。

# 丢弃片段

通过使用片段着色器工具，我们能够创建一些很酷的效果。其中一个工具就是使用丢弃关键字。丢弃关键字，顾名思义，移除或丢弃片段。当使用丢弃关键字时，着色器立即停止执行并跳过片段，不向输出缓冲区写入任何数据。创建的效果是多边形面上的孔洞，而不使用混合效果。丢弃关键字也可以与 alpha 贴图结合使用，以允许纹理指定应丢弃哪些片段。在建模损坏对象等效果时，这可能是一个方便的技术。

在这个例子中，我们将创建一个片段着色器，使用丢弃关键字根据 UV 纹理坐标移除某些片段。效果将是我们的小矮人模型呈现出格子或穿孔的外观。

让我们从查看这个例子的顶点着色器开始：

```cpp
#version 410
// Input vertex data, different for all executions of this shader.
in vec3 vertexPosition_modelspace;
in vec2 vertexUV;
in vec3 vertexNormal;
out vec3 FrontColor;
out vec3 BackColor;
out vec2 UV;
struct LightInfo {
vec4 Position; // Light position in eye coords.
vec3 La; // Ambient light intensity
vec3 Ld; // Diffuse light intensity
vec3 Ls; // Specular light intensity
};
uniform LightInfo Light;
struct MaterialInfo {vec3 Ka; // Ambient reflectivity
vec3 Kd; // Diffuse reflectivity
vec3 Ks; // Specular reflectivity
float Shininess; // Specular shininess factor
};
uniform MaterialInfo Material;
uniform mat4 ModelViewMatrix;
uniform mat3 NormalMatrix;
uniform mat4 ProjectionMatrix;
uniform mat4 ModelViewProjection;
void getCameraSpace( out vec3 norm, out vec4 position )
{
norm = normalize( NormalMatrix * vertexNormal);
position = ModelViewMatrix * vec4(vertexPosition_modelspace,1.0);
}
vec3 phongModel( vec4 position, vec3 norm )
{
...
//Same as previous examples
...}
void main()
{
vec3 cameraNorm;
vec4 cameraPosition;
UV = vertexUV;
// Get the position and normal in eye space
getCameraSpace(cameraNorm, cameraPosition);
FrontColor = phongModel( cameraPosition, cameraNorm );
BackColor = phongModel( cameraPosition, -cameraNorm );
gl_Position = ModelViewProjection *
vec4(vertexPosition_modelspace,1.0);
}
```

在这个例子中，我们将光照计算移回到顶点着色器。您可能已经注意到，这个顶点着色器与上一个例子非常相似，只是有一些细微的变化。要注意的第一个变化是，我们在这个例子中使用了 UV 纹理坐标。我们使用纹理坐标来确定要丢弃的片段，并且这次我们不打算渲染模型的纹理。由于我们将丢弃一些小矮人模型的片段，我们将能够看到模型的内部和另一侧。这意味着我们需要为脸的正面和背面都计算光照方程。我们通过为每一侧计算冯氏模型来实现这一点，改变传入的法向量。然后我们将这些值存储在`FrontColor`和`BackColor`变量中，以便传递到片段着色器。为了使我们的主类再次更易于阅读，我们还将相机空间转换移到一个函数中。

接下来，让我们看一下这个例子的片段着色器：

```cpp
#version 410
in vec3 FrontColor;
in vec3 BackColor;
in vec2 UV;
out vec4 FragColor;
void main() {
const float scale = 105.0;
bvec2 toDiscard = greaterThan( fract(UV * scale), vec2(0.2,0.2) );
if( all(toDiscard) )
discard;
else {
if( gl_FrontFacing )
FragColor = vec4(FrontColor, 1.0);
else
FragColor = vec4(BackColor, 1.0);
}
}
```

在我们的片段着色器中，我们正在计算要丢弃的片段，以实现所需的穿孔效果。为了实现这一点，我们首先使用我们的缩放因子来缩放 UV 坐标。这个缩放因子代表每个纹理坐标的穿孔矩形的数量。接下来，我们使用 GLSL 函数`fract()`来计算纹理坐标分量的小数部分。然后，我们使用另一个 GLSL 函数`greaterThan()`将每个*x*和*y*分量与 0.2 的浮点值进行比较。

如果`toDiscard`变量中的向量的*x*和*y*分量都评估为 true，这意味着片段位于穿孔矩形的边框内，我们希望丢弃它。我们可以使用 GLSL 函数来帮助我们执行这个检查。如果函数调用返回 true，我们执行`discard`语句来丢弃该片段。

接下来，我们有一个`else`块，根据片段是背面还是正面多边形来着色。为了帮助我们，我们使用`gl_FronFacing()`函数根据多边形的法线返回 true 或 false。

就像我们在之前的例子中一样，我们必须再次确保在游戏程序中设置着色器所需的属性和统一变量。要查看示例的完整实现，请参见`Chapter07`，`DiscardExample`项目。如果我们运行这个例子程序，您将看到我们的小矮人模型看起来好像是由格子制成的。以下是输出的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/e90cca70-3782-4848-8bee-a2e50889ee8d.png)

# 生成粒子

通过使用着色器，您可以实现的另一个效果是通常称为粒子效果的效果。您可以将粒子系统视为一组对象，这些对象一起用于创建烟雾、火灾、爆炸等的视觉外观。系统中的单个粒子被认为是一个具有位置但没有大小的点对象。要渲染这些点对象，`GL_POINTS`原语通常是最常见的方法。但是，您也可以像渲染任何其他对象一样渲染粒子，使用三角形或四边形。

在我们的示例中，我们将实现一个简单的粒子系统，它将呈现出一个喷泉的外观。我们系统中的每个粒子都将遵循这些规则。它将有一个有限的寿命，它将根据定义的标准被创建和动画化，然后终止。在一些粒子系统中，您可以回收粒子，但为了简单起见，我们的示例不会这样做。粒子的动画标准通常基于运动方程，这些方程定义了粒子的运动，基于重力加速度、风、摩擦和其他因素。同样，为了保持我们的示例简单，我们将使用标准的运动学计算来对粒子进行动画处理。以下方程描述了给定时间*t*时粒子的位置，其中*P[0]*是初始位置，*V[0]t*是初始速度，*a*代表加速度：

*P(t) = P[0]+ V­[0]t + ½at²*

在我们的示例中，我们将定义粒子的初始位置为原点(0,0,0)。初始速度将在一个范围内随机计算。由于每个粒子将在我们方程中的不同时间间隔内创建，时间将相对于该粒子的创建时间。

由于所有粒子的初始位置相同，我们不需要将其作为着色器的属性提供。我们只需要提供两个顶点属性：粒子的初始速度和开始时间。如前所述，我们将使用`GL_POINTS`来渲染每个粒子。使用`GL_POINTS`的好处是很容易将纹理应用到点精灵上，因为 OpenGL 会自动生成纹理坐标并通过 GLSL 变量`gl_PointCoord`将其传递给片段着色器。为了使粒子看起来逐渐消失，我们还将在粒子的寿命内线性增加点对象的透明度。

让我们从这个示例的顶点着色器开始：

```cpp
#version 410
in vec3 VertexInitVel; // Particle initial velocity
in float StartTime; // Particle "birth" time
out float Transp; // Transparency of the particle
uniform float Time; // Animation time
uniform vec3 Gravity = vec3(0.0,-0.05,0.0); // world coords
uniform float ParticleLifetime; // Max particle lifetime
uniform mat4 ModelViewProjection;
void main()
{
// Assume the initial position is (0,0,0).
vec3 pos = vec3(0.0);
Transp = 0.0;
// Particle dosen't exist until the start time
if( Time > StartTime ) {
float t = Time - StartTime;
if( t < ParticleLifetime ) {
pos = VertexInitVel * t + Gravity * t * t;
Transp = 1.0 - t / ParticleLifetime;
}
}
// Draw at the current position
gl_Position = ModelViewProjection * vec4(pos, 1.0);
}
```

我们的着色器以两个必需的输入属性开始，即粒子的初始速度`VertexInitVel`和粒子的开始时间`StartTime`。然后我们有输出变量`Transp`，它将保存粒子透明度的计算结果传递到下一个着色器阶段。接下来，我们有我们的统一变量：时间，动画运行时间，重力，用于计算恒定加速度，以及`ParticleLifetime`，它指定粒子可以保持活动状态的最长时间。在主函数中，我们首先将粒子的初始位置设置为原点，在本例中为(0,0,0)。然后我们将透明度设置为 0。接下来，我们有一个条件，检查粒子是否已激活。如果当前时间大于开始时间，则粒子处于活动状态，否则粒子处于非活动状态。如果粒子处于非活动状态，则位置保持在原点，并且以完全透明度渲染粒子。然后，如果粒子仍然存活，我们通过从当前时间减去开始时间来确定粒子的当前*年龄*，并将结果存储在浮点值`t`中。然后我们将`t`与`ParticleLiftime`值进行比较，如果`t`大于粒子的寿命值，则粒子已经完成了其寿命动画，然后以完全透明度渲染。如果`t`不大于寿命值，则粒子处于活动状态，我们对粒子进行动画处理。我们使用我们之前讨论的方程来实现这种动画。透明度是根据粒子的运行时间或*年龄*进行插值确定的。

现在让我们看一下这个例子的片段着色器：

```cpp
#version 410
in float Transp;
uniform sampler2D ParticleTex;
out vec4 FragColor;
void main()
{
FragColor = texture(ParticleTex, gl_PointCoord);
FragColor.a *= Transp;
}
```

我们这个例子的片段着色器非常基本。在这里，我们根据其纹理查找值设置片段的颜色。如前所述，因为我们使用`GL_POINT`原语，所以纹理坐标由 OpenGL 的`gl_PointCoord`变量自动计算。最后，我们将片段的最终颜色的 alpha 值乘以`Transp`输入变量。这将在我们的粒子运行时消逝时给我们淡出效果。

在我们的游戏代码中，我们需要创建两个缓冲区。第一个缓冲区将存储每个粒子的初始速度。第二个缓冲区将存储每个粒子的开始时间。我们还必须设置所需的统一变量，包括`ParticleTex`用于粒子纹理，`Time`变量用于表示动画开始后经过的时间量，`Gravity`变量用于表示加速度常数，以及`ParticleLifetime`变量用于定义粒子运行动画的持续时间。为了简洁起见，我不会在这里介绍代码，但您可以查看`Chapter07`文件夹中粒子示例项目的实现。

在测试我们的示例之前，我们还需要确保深度测试关闭，并且启用了 alpha 混合。您可以使用以下代码来实现：

```cpp
glDisable(GL_DEPTH_TEST);
glEnable(GL_BLEND);
glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
```

您可能还想将点对象的大小更改为更合理的值。您可以使用以下代码将值设置为 10 像素：

```cpp
glPointSize(10.0f);
```

如果我们现在运行我们的示例项目，我们将看到类似喷泉的粒子效果。可以看到一些捕获的帧如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/245c79e2-56a5-44c1-9414-d1040716729a.png)![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/e5b65410-4810-4b6b-94d4-6aeba4eca42e.png)

虽然这只是一个简单的例子，但它有很大的性能和灵活性提升空间，应该为您实现基于 GPU 的粒子系统提供了一个很好的起点。请随意尝试不同的输入值，甚至可以添加更多因素到粒子动画计算中。实验可能会带来很多有趣的结果。

# 总结

在本章中，我们介绍了使用着色器的基础知识。我们学习了如何构建编译器和链接抽象层，以节省时间。我们了解了光照技术理论以及如何在着色器语言中实现它们。最后，我们通过研究着色器的其他用途，比如创建粒子效果，结束了本章。在下一章中，我们将通过创建高级游戏玩法系统进一步扩展我们的示例游戏框架。


# 第八章：高级游戏系统

游戏不仅仅是简单的机制和基础引擎。它们由复杂的游戏系统组成，使我们能够与游戏世界互动，让我们感到被包容和沉浸其中。这些系统通常需要大量的时间和开发者专业知识来实现。在本章中，我们将看一下一些高级游戏系统以及在我们自己的项目中实现它们时如何给自己一层帮助。

本章包括以下主题：

+   实现脚本语言

+   构建对话系统

+   脚本任务

# 实现脚本语言

正如之前提到的，实现一个高级游戏系统通常需要许多编码小时，并且可能需要开发人员对该特定系统具有专业知识。然而，我们可以通过包含对脚本语言的支持来使这一切变得更容易，对我们自己和其他人在项目上的工作也更容易。

# 为什么要使用脚本语言

也许你会想知道，既然这是一本关于 C++的书，为什么我们要花时间谈论脚本语言呢？为什么要加入脚本语言？我们难道不能只用 C++来构建整个引擎和游戏吗？是的，我们可以！然而，一旦你开始着手更大的项目，你会很快注意到每次需要进行更改时所花费的编译和重新编译的时间。虽然有一些方法可以解决这个问题，比如将游戏和引擎分成较小的模块并动态加载它们，或者使用 JSON 或 XML 描述性文件系统，但是这些技术不能提供实现脚本系统的所有好处。

那么，将脚本语言添加到游戏引擎中有什么好处呢？首先，你将使用的大多数脚本语言都是解释性语言，这意味着与 C++不同，你不需要编译代码。相反，你的代码在运行时加载和执行。这样做的一个巨大优势是你可以对脚本文件进行更改并快速看到结果，而无需重新编译整个游戏。事实上，你可以在游戏运行时重新加载脚本并立即看到更改。使用脚本语言的另一个可能好处是相对于 C++这样的语言，它被认为更易于使用。大多数脚本语言都是动态类型的，具有简化的语法和结构。这可以为团队的创造性一面，比如艺术家和设计师，提供机会，他们可以在不需要理解 C++这样的语言复杂性的情况下对项目进行小的更改。想象一下 GUI 设计师能够创建、放置和修改 GUI 元素，而无需知道 IGUI 框架是如何实现的。添加脚本支持还为社区内容支持打开了一条道路——想象一下地图、关卡和物品都是由游戏玩家设计的。这对于新游戏来说已经成为一个巨大的卖点，并为你的游戏提供了一些可能的长期性。在谈到长期性时，DLC 的实施可以通过脚本完成。这可以实现更快的开发周转，并且可以在不需要庞大补丁的情况下投入游戏中。

这些是使用脚本语言的一些好处，但并不总是在每种情况下都是最佳解决方案。脚本语言以运行速度较慢而臭名昭著，正如我们所知，性能在构建游戏时很重要。那么，什么时候应该使用脚本而不是使用 C++呢？我们将更仔细地看一些系统示例，但作为一个简单的遵循规则，你应该总是使用 C++来处理任何可以被认为是 CPU 密集型的东西。程序流程和其他高级逻辑是脚本的绝佳候选对象。让我们看看脚本可以在我们的游戏引擎组件中使用的地方。

让我们从物理组件开始。当然，当我们想到物理时，我们立刻想到大量的 CPU 使用。在大多数情况下，这是正确的。物理系统的核心应该是用 C++构建的，但也有机会在这个系统中引入脚本。例如，物理材料的概念。我们可以在脚本中定义材料的属性，比如质量，摩擦力，粘度等。我们甚至可以从脚本内部修改这些值。物理系统中脚本的另一个潜在用途是定义碰撞的响应。我们可以处理声音的生成，特效和其他事件，都可以在脚本中完成。

那么 AI 系统呢？这可以说是游戏引擎中脚本语言最常见的用途之一，我们将在下一章更深入地研究这一点。AI 系统的许多组件可以移入脚本中。这些包括复杂的行为定义，AI 目标的规定，AI 之间的通信，AI 个性和特征的定义，以及更多。虽然列表很长，但你应该注意到给出的示例并不占用 CPU，并且 AI 系统的复杂组件，如路径查找，模糊逻辑和其他密集算法应该在 C++代码中处理。

甚至可以将脚本添加到看似 CPU 和 GPU 密集的系统中，比如图形引擎。脚本可以处理设置光照参数，调整雾等效果，甚至在屏幕上添加和删除游戏元素。正如你所看到的，引擎中几乎没有什么是不能用某种形式的脚本抽象来补充的。

那么，你应该使用哪种脚本语言？有很多选择，从游戏特定的语言，如 GameMonkey（在撰写本书时似乎已经停用），到更通用的语言，如 Python 和 JavaScript。选择取决于你的具体需求。虽然 Python 和 JavaScript 等语言具有一些令人惊叹的功能，但为了获得这些功能，学习和执行会更加复杂。在本书的示例中，我们将使用一种称为 Lua 的语言。Lua 已经存在多年，虽然近年来其流行度有所下降，但在游戏开发行业中有着非常强大的记录。在本章的下一部分，我们将更好地了解 Lua，并看看如何将其纳入我们现有的引擎系统中。

# 介绍 LUA

Lua，发音为 LOO-ah，是一种轻量级的可嵌入脚本语言。它支持现代编程方法论，如面向对象，数据驱动，函数式和过程式编程。Lua 是一种可移植的语言，几乎可以在提供标准 C 编译器的所有系统上构建。Lua 可以在各种 Unix，Windows 和 Mac 系统上运行。Lua 甚至可以在运行 Android，iOS，Windows Phone 和 Symbian 的移动设备上找到。这使得它非常适合大多数游戏标题，并且是包括暴雪娱乐在内的公司使用它的主要原因之一，例如《魔兽世界》。Lua 也是免费的，根据 MIT 权限许可分发，并且可以用于任何商业目的而不产生任何费用。

Lua 也是一种简单但强大的语言。在 Lua 中，只有一种数据结构被称为**table**。这种表数据结构可以像简单数组一样使用，也可以像键值字典一样使用，我们甚至可以使用表作为原型来实现一种面向对象编程。这与在其他语言中进行 OOP 非常相似，比如 JavaScript。

虽然我们不会详细介绍语言，但有一些很好的资源可供参考，包括 Lua 文档网站。我们将简要介绍一些关键的语言概念，这些概念将在示例中得到体现。

让我们从变量和简单的程序流开始。在 Lua 中，所有数字都是双精度浮点数。您可以使用以下语法分配一个数字：

```cpp
number = 42 
```

请注意缺少类型标识符和分号来表示语句结束。

Lua 中的字符串可以用几种方式定义。您可以用单引号定义它们，如下所示：

```cpp
string = 'single quote string' 
```

您也可以使用双引号：

```cpp
string = "double quotes string" 
```

对于跨多行的字符串，您可以使用双方括号来表示字符串的开始和结束：

```cpp
string  = [[ multi-line  
             string]] 
```

Lua 是一种垃圾收集语言。您可以通过将对象设置为`nil`来删除定义，这相当于 C++中的*NULL*：

```cpp
string = nil 
```

Lua 中的语句块用语言关键字来表示，比如`do`和`end`。`while`循环块将如下所示：

```cpp
while number < 100 do 
    number = number + 1 
end 
```

您可能会注意到我们在这里使用了`number + 1`，因为 Lua 语言中没有增量和减量运算符(`++`，`--`)。

`if`条件代码块将如下所示：

```cpp
if number > 100 then 
    print('Number is over 100') 
elseif number == 50 then 
    print('Number is 50') 
else 
    print(number) 
end 
```

Lua 中的函数构造方式类似，使用 end 来表示函数代码语句块的完成。一个简单的计算斐波那契数的函数将类似于以下示例：

```cpp
function fib(number) 
    if number < 2 then 
        return 1 
    end 
    return fib(number - 2) + fib(number -1) 
end 
```

如前所述，表是 Lua 语言中唯一的复合数据结构。它们被视为关联数组对象，非常类似于 JavaScript 对象。表是哈希查找字典，也可以被视为列表。使用表作为映射/字典的示例如下：

```cpp
table = { key1 = 'value1', 
          key2 = 100, 
          key3 = false }
```

在处理表时，您还可以使用类似 JavaScript 的点表示法。例如：

```cpp
print (table.key1) 
Prints the text value1 

table.key2 = nil 
```

这将从表中删除`key2`。

```cpp
table.newKey = {}  
```

这将向表中添加一个新的键/值对。

这就结束了我们对 Lua 语言特定内容的快速介绍；随着我们构建示例，您将有机会了解更多。如果您想了解更多关于 Lua 的信息，我再次建议阅读官方网站上的文档[`www.lua.org/manual/5.3/`](http://www.lua.org/manual/5.3/)。

在下一节中，我们将看看如何在我们的示例游戏引擎项目中包含 Lua 语言支持的过程。

# 实现 LUA

为了在我们的示例引擎中使用 Lua，我们需要采取一些步骤。首先，我们需要获取 Lua 解释器作为一个库，然后将其包含在我们的项目中。接下来，我们将不得不获取或构建我们自己的辅助桥梁，以使我们的 C++代码和 Lua 脚本之间的交互更容易。最后，我们将不得不*公开*或*绑定*函数、变量和其他对象，以便我们的 Lua 脚本可以访问它们。虽然这些步骤对于每个实现可能略有不同，但这将为我们的下一个示例提供一个很好的起点。

首先，我们需要一个 Lua 库的副本，以便在我们的引擎中使用。在我们的示例中，我们将使用 Lua 5.3.4，这是当时的最新版本。我选择在示例中使用动态库。您可以在 Lua 项目网站的预编译二进制文件页面([`luabinaries.sourceforge.net/`](http://luabinaries.sourceforge.net/))上下载动态和静态版本的库，以及必要的包含文件。下载预编译库后，解压缩并将必要的文件包含在我们的项目中。我不打算再次详细介绍如何在项目中包含库。如果您需要复习，请翻回到第二章，*理解库*，在那里我们详细介绍了步骤。

与我们在整本书中看到的其他示例一样，有时创建辅助类和函数以允许各种库和组件之间更容易地进行交互是很重要的。当我们使用 Lua 时，这又是一个例子。为了使开发者更容易地进行交互，我们需要创建一个桥接类和函数来提供我们需要的功能。我们可以使用 Lua 本身提供的接口来构建这个桥接，Lua 有很好的文档，但也可以选择使用为此目的创建的众多库之一。在本章和整本书的示例中，我选择使用`sol2`库（[`github.com/ThePhD/sol2`](https://github.com/ThePhD/sol2)），因为这个库是轻量级的（只有一个头文件），速度快，并且提供了我们示例中需要的所有功能。有了这个库，我们可以抽象出很多桥接的维护工作，并专注于实现。要在我们的项目中使用这个库，我们只需要将单个头文件实现复制到我们的`include`文件夹中，它就可以使用了。

现在我们已经有了 Lua 引擎和`sol2`桥接库，我们可以继续进行最后一步，实现脚本。如前所述，为了我们能够使用底层游戏引擎组件，它们必须首先暴露给 Lua。这就是`sol2`库的作用所在。为了演示在我们的示例引擎中如何实现这一点，我创建了一个名为`Bind_Example`的小项目。您可以在代码存储库的`Chapter08`文件夹中找到完整的源代码。

首先让我们看一下 Lua 脚本本身。在这种情况下，我把我的脚本命名为`BindExample.lua`，并将它放在示例项目父目录的`Scripts`文件夹中：

```cpp
player = { 
    name = "Bob", 
    isSpawned = false 
} 

function fib(number) 
    if number < 2 then 
        return 1 
    end 
    return fib(number - 2) + fib(number -1) 
end 
```

在这个示例中，我们的 Lua 脚本非常基本。我们有一个名为`player`的表，有两个元素。一个带有键`name`和值`Bob`的元素，以及一个带有键`isSpawned`和值`false`的元素。接下来，我们有一个名为`fib`的简单 Lua 函数。这个函数将计算斐波那契数列中直到传入的数字的所有数字。我觉得在这个例子中加入一点数学会很有趣。我应该指出，这个计算在序列越高时可能会变得相当消耗处理器，所以如果您希望它快速处理，请不要传入一个大于，比如说，20 的数字。

这给了我们一些快速的 Lua 代码示例来使用。现在我们需要将我们的程序和它的逻辑连接到这个新创建的脚本中。在这个示例中，我们将把这个连接代码添加到我们的`GameplayScreen`类中。

我们首先添加了`sol2`库的必要包含：

```cpp
#include <sol/sol.hpp> 
```

接下来，我们将创建 Lua 状态。在 Lua 中，`state`可以被视为代码的操作环境。将其视为虚拟机。这个`state`是您的代码将被执行的地方，也是通过这个`state`您将能够访问正在运行的代码的地方：

```cpp
    sol::state lua; 
```

然后我们打开了一些我们在 Lua 代码交互中需要的辅助库。这些库可以被视为 C++中`#include`的等价物。Lua 的理念是保持核心的精简，并通过这些库提供更多的功能：

```cpp
    lua.open_libraries(sol::lib::base, sol::lib::package); 
```

在我们打开了库之后，我们可以继续加载实际的 Lua 脚本文件。我们通过调用之前创建的 Lua`state`的`script_file`方法来实现这一点。这个方法接受一个参数：文件的位置作为一个字符串。当执行这个方法时，文件将被自动加载和执行：

```cpp
    lua.script_file("Scripts/PlayerTest.lua"); 
```

现在脚本已经加载，我们可以开始与它交互。首先，让我们看看如何从 Lua 的变量（表）中提取数据并在我们的 C++代码中使用它：

```cpp
    std::string stringFromLua = lua["player"]["name"]; 
    std::cout << stringFromLua << std::endl; 
```

从 Lua 脚本中检索数据的过程非常简单。在这种情况下，我们创建了一个名为`stringFromLua`的字符串，并将其赋值为 Lua 表 players 的`name`元素中存储的值。语法看起来类似于调用数组元素，但在这里我们用字符串指定元素。如果我们想要`isSpawned`元素的值，我们将使用`lua["player"]["isSpawned"]`，在我们的例子中，这将当前返回一个布尔值`false`。

调用 Lua 函数和检索值一样简单，而且非常类似：

```cpp
    double numberFromLua = lua"fib"; 
    std::cout << numberFromLua << std::endl; 
```

在这里，我们创建了一个名为`numberFromLua`的双精度类型的变量，并将其赋值为 Lua 函数`fib`的返回值。在这里，我们将函数名指定为一个字符串`fib`，然后指定该函数需要的任何参数。在这个例子中，我们传入值 20 来计算斐波那契数列直到第 20 个数字。

如果你运行`Bind_Example`项目，你将在引擎的命令窗口中看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/5c1eeb50-54c3-410b-bb35-75080880eaef.png)

虽然这涵盖了我们的 C++代码与 Lua 脚本系统之间的交互基础知识，但还有很多可以发现的地方。在接下来的几节中，我们将探讨如何利用这种脚本结构来增强各种高级游戏系统，并为我们提供一种灵活的方式来扩展我们的游戏项目。

# 构建对话系统

与游戏世界互动的最常见形式之一是通过某种对话形式。能够与`NPC`类进行交流，获取信息和任务，当然，通过对话推动故事叙述在大多数现代游戏标题中都是必不可少的。虽然你可以轻松地硬编码交互，但这种方法会让我们的灵活性非常有限。每次我们想要对任何对话或交互进行轻微更改时，我们都必须打开源代码，搜索项目，进行必要的更改，然后重新编译以查看效果。显然，这是一个繁琐的过程。想想你玩过多少游戏出现拼写、语法或其他错误。好消息是我们还有另一种方法。使用 Lua 这样的脚本语言，我们可以以动态方式驱动我们的交互，这将允许我们快速进行更改，而无需进行先前描述的繁琐过程。在本节中，我们将详细介绍构建对话系统的过程，它在高层描述上将加载一个脚本，将其附加到一个`NPC`，向玩家呈现带有选择的对话，最后，根据返回的玩家输入驱动对话树。

# 构建 C++基础设施

首先，我们需要在我们的示例引擎中构建基础设施，以支持对话系统的脚本化。实际上有成千上万种不同的方法可以实现这个实现。对于我们的示例，我会尽力保持简单。我们将使用我们在之前章节中学到的一些技术和模式，包括状态和更新模式，以及我们构建的 GUI 系统来处理交互和显示。

他们说一张图片胜过千言万语，所以为了让你对这个系统的连接方式有一个大致的了解，让我们来看一下一个代码映射图，它描述了所有类之间的连接：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/c014d784-590f-4a51-aba9-60a48686ceb6.png)

这里有一些事情要做，所以我们将逐个类地分解它。首先，让我们看一下`DialogGUI`类。这个类是基于我们在之前章节中构建的 IGUI 示例。由于我们已经深入讨论了 IGUI 类的设计，我们只会涵盖我们添加的特定方面，以提供我们对话系统所需的功能。

首先，我们需要一些变量来保存对话和我们想要为玩家提供的任何选择。在`DialogGUI.h`中，我们有以下内容：选择的`IGUILabel`对象的向量和对话的单个`IGUILabel`。有关`IGUILabel`类的实现，请查看其源代码：

```cpp
std::vector<BookEngine::IGUILabel*> choices; 
BookEngine::IGUILabel* m_dialog;
```

接下来，我们需要添加一些新的函数，为我们的 GUI 提供所需的交互和脚本提供的数据。为此，我们将在`DialogGUI`类中添加三种方法：

```cpp
void SetDialog(std::string text); 
void SetOption(std::string text, int choiceNumber); 
void RemoveAllPanelElements(); 
```

`SetDialog`函数，顾名思义，将处理为每个交互屏幕设置对话框文本的工作。该函数只接受一个参数，即我们想要放置在 GUI 上的交互文本：

```cpp
void DialogGUI::SetDialog(std::string text) 
{ 
    m_dialog = new BookEngine::IGUILabel(glm::vec4(0, 110, 250, 30), 
        glm::vec2(110, -10), 
        text, 
        new BookEngine::SpriteFont("Fonts/Impact_Regular.ttf", 72), 
        glm::vec2(0.3f), m_panel); 

    AddGUIElement(*m_dialog); 
} 
```

在函数体中，我们将`m_dialog`标签变量分配给`IGUILabel`对象的新实例。构造函数应该类似于之前看到的`IGUIButton`，其中传入了文本值。最后，我们通过调用`AddGUIElement`方法将标签添加到 GUI 面板中。

`SetOption`函数，顾名思义，再次设置当前交互屏幕上每个选项的文本。此函数接受两个参数。第一个是我们要将`IGUILabel`设置为的文本，第二个是选择编号，它是在呈现的选择选项列表中的编号。我们使用这个来查看选择了哪个选项：

```cpp
void DialogGUI::SetOption(std::string text, int choiceNumber) 
{ 
    choices.resize(m_choices.size() + 1); 
    choices[choiceNumber] =  
new BookEngine::IGUILabel(glm::vec4(0, 110, 250, 20), 
            glm::vec2(110, 10), 
            text, 
            new BookEngine::SpriteFont("Fonts/Impact_Regular.ttf", 72), 
            glm::vec2(0.3f), m_panel); 

    AddGUIObject(*choices[choiceNumber]); 
}
```

在函数体中，我们正在执行与`SetDialog`函数非常相似的过程。这里的区别在于，我们将向选择向量添加`IGUILabel`实例。首先，我们进行一个小技巧，将向量的大小增加一，然后这将允许我们将新的标签实例分配给传入的选择编号值的向量位置。最后，我们通过调用`AddGUIElement`方法将`IGUILabel`添加到面板中。

我们添加到`DialogGUI`类的最后一个函数是`RemoveAllPanelElements`，它当然将处理删除我们添加到当前对话框屏幕的所有元素。我们正在删除这些元素，以便我们可以重用面板并避免每次更改交互时重新创建面板：

```cpp
void DialogGUI::RemoveAllPanelElements() 
{ 
    m_panel->RemoveAllGUIElements(); 
} 
```

`RemoveAllGUIElements`函数反过来只是调用`m_panel`对象上的相同方法。`IGUIPanel`类的实现只是调用向量上的 clear 方法，删除所有元素：

```cpp
void RemoveAllGUIObjects() { m_GUIObjectsList.clear(); }; 
```

这样就完成了对话系统的 GUI 设置，现在我们可以继续构建`NPC`类，该类将处理大部分脚本到引擎的桥接。

正如我之前提到的，我们将利用之前学到的一些模式来帮助我们构建对话系统。为了帮助我们控制何时构建 GUI 元素以及何时等待玩家做出选择，我们将使用有限状态机和更新模式。首先，在`NPC.h`文件中，我们有一个将定义我们将使用的状态的`enum`。在这种情况下，我们只有两个状态，`Display`和`WaitingForInput`：

```cpp
... 
    enum InteractionState 
    { 
        Display, 
        WaitingForInput, 
    }; 
...
```

当然，我们还需要一种方式来跟踪状态，所以我们有一个名为`currentState`的`InteractionState`变量，我们将把它设置为我们当前所处的状态。稍后，我们将在`Update`函数中看到这个状态机的完成：

```cpp
InteractionState currentState; 
```

我们还需要一个变量来保存我们的 Lua 状态，这是本章前一节中看到的：

```cpp
    sol::state lua; 
```

您可能还记得之前显示的代码映射图中，我们的`NPC`将拥有一个`DialogGUI`的实例，用于处理对话内容的显示和与玩家的交互，因此我们还需要一个变量来保存它：

```cpp
    DialogGUI* m_gui; 
```

继续实现`NPC`类，我们首先将查看`NPC.cpp`文件中该类的构造函数：

```cpp
NPC::NPC(DialogGUI& gui) : m_gui(&gui) 
{ 
    std::cout << "Loading Scripts n"; 
    lua.open_libraries(sol::lib::base, sol::lib::package, sol::lib::table); 
    lua.script_file("Scripts/NPC.lua"); 
    currentState = InteractionState::Display; 
} 
```

构造函数接受一个参数，即我们将用于交互的对话实例的引用。我们将此引用设置为成员变量 `m_gui` 以供以后使用。然后，我们处理将要使用的 Lua 脚本的加载。最后，我们将内部状态机的当前状态设置为 `Display` 状态。

让我们重新查看我们的代码地图，看看我们需要实现的不同连接，以将 `NPC` 类的加载的脚本信息传递给我们已附加的 GUI 实例：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/eae789ce-a9e9-4382-b250-d184582e7da9.png)

正如我们所看到的，有两个处理连接的方法。`Say` 函数是其中较简单的一个。在这里，`NPC` 类只是在附加的 GUI 上调用 `SetDialog` 方法，传递包含要显示的对话的字符串：

```cpp
 void NPC::Say(std::string stringToSay) 
{ 
    m_gui->SetDialog(stringToSay); 
} 
```

`PresentOptions` 函数稍微复杂一些。首先，该函数从 Lua 脚本中检索一个表，该表表示当前交互的选择，我们很快就会看到脚本是如何设置的。接下来，我们将遍历该表（如果它是有效的），并简单地在附加的 GUI 上调用 `SetOption` 方法，传递选择文本作为字符串和用于选择的选择编号：

```cpp
void NPC::PresentOptions() 
{ 

    sol::table choices = lua["CurrentDialog"]["choices"]; 
    int i = 0; 
    if (choices.valid()) 
    { 
        choices.for_each(& 
        { 
            m_gui->SetOption(value.as<std::string>(), i); 
            i++; 
        }); 
    } 
}
```

我们需要放置在引擎端对话系统的最后一部分是 `Update` 方法。正如我们已经多次看到的那样，这个方法将推动系统向前。通过连接到引擎的现有 `Update` 事件系统，我们的 `NPC` 类的 `Update` 方法将能够控制每一帧对话系统中发生的事情：

```cpp
void NPC::Update(float deltaTime) 
{ 
    switch (currentState) 
    { 
    case InteractionState::Display: 
        Say(lua["CurrentDialog"]["say"]); 
        PresentOptions(); 
        currentState = InteractionState::WaitingForInput; 
        break; 
    case InteractionState::WaitingForInput: 
        for (int i = 0; i < m_gui->choices.size(); i++) 
        { 
            if (m_gui->choices[i]->GetClickedStatus() == true) 
            { 
                lua["CurrentDialog"]"onSelection"); 
                currentState = InteractionState::Display; 
                m_gui->choices.clear(); 
                m_gui->RemoveAllPanelElements (); 
            } 
        } 
        break; 
    } 
} 
```

与我们之前的有限状态机实现一样，我们将使用 switch case 来确定基于当前状态应该运行什么代码。在这个例子中，我们的 `Display` 状态是我们将调用连接方法 `Say` 和 `PresentOptions` 的地方。在这里，`Say` 调用单独传递了它从已加载的脚本文件中提取的文本。我们将在接下来的脚本中看到这是如何工作的。如果在这个例子中，我们处于 `WaitingForInput` 状态，我们将遍历我们已加载的每个选择，并查看玩家是否已经选择了其中任何一个。如果找到了一个，我们将回调脚本并告诉它已选择了哪个选项。然后，我们将切换我们的状态到 `Display` 状态，这将启动加载下一个对话屏幕。然后，我们将清除附加的 `DisplayGUI` 中的选择向量，允许它随后加载下一组选择，并最后调用 `RemoveAllPanelElements` 方法来清理我们的 GUI 以便重用。

有了 `Update` 方法，我们现在已经设置好了处理加载、显示和输入处理所需的框架，用于我们的 `NPC` 交互脚本。接下来，我们将看看如何构建其中一个这样的脚本，以便与我们引擎新创建的对话系统一起使用。

# 创建对话树脚本

对话或会话树可以被视为交互的确定流程。实质上，它首先提供一个陈述，然后，基于呈现的响应选择，交互可以分支出不同的路径。我们示例对话流程的可视化表示如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/6ce1e167-083a-4863-a04d-41230fa52cf7.png)

在这里，我们以一个介绍开始对话树。然后用户被呈现两个选择：**是，需要帮助**和**不，离开我**。如果用户选择**是**路径，那么我们继续到**表达帮助**对话。如果用户选择**不**，我们移动到**再见**对话。从**表达帮助**对话，我们呈现三个选择：**好的**，**重新开始**和**虚弱**。根据选择，我们再次移动到对话树的下一个阶段。**好的**导致**离开愉快**对话。**虚弱**导致**再见**对话，**重新开始**，嗯，重新开始。这是一个基本的例子，但它演示了对话树如何工作的整体概念。

现在让我们看看如何在我们的 Lua 脚本引擎中实现这个示例树。以下是完整的脚本，我们将在接下来的部分深入了解细节：

```cpp
intro = { 
    say = 'Hello I am the Helper NPC, can I help you?', 
    choices = { 
                 choice1 = "Yes! I need help", 
                 choice2 = "No!! Leave me alone" 
    }, 

    onSelection = function (choice)  
        if choice == CurrentDialog["choices"]["choice1"] then CurrentDialog = getHelp end 
        if choice  == CurrentDialog["choices"]["choice2"] then CurrentDialog = goodbye_mean end 
    end 
} 

getHelp = { 
    say = 'Ok I am still working on my helpfulness', 
    choices = { 
                 choice1 = "That's okay! Thank you!", 
                 choice2 = "That's weak, what a waste!", 
                 choice3 = "Start over please." 
        }, 
    onSelection = function (choice)  
        if choice  == CurrentDialog["choices"]["choice1"] then CurrentDialog = goodbye  
        elseif choice  == CurrentDialog["choices"]["choice2"] then CurrentDialog = goodbye_mean  
        elseif choice  == CurrentDialog["choices"]["choice3"] then CurrentDialog = intro end 
    end 

} 

goodbye = { 
    say = "See you soon, goodbye!" 
} 

goodbye_mean = { 
    say = "Wow that is mean, goodbye!" 
} 

CurrentDialog = intro 
```

正如你所看到的，整个脚本并不长。我们有一些概念使得这个脚本工作。首先是一个非常简单的状态机版本。我们有一个名为`CurrentDialog`的变量，这个变量将指向活动对话。在我们的脚本的最后，我们最初将其设置为`intro`对话对象，这将在加载脚本时启动对话树。我们在脚本设计中的下一个重要概念是将每个交互屏幕描述为一个表对象。让我们以介绍对话表为例。

```cpp
intro = { 
    say = 'Hello I am the Helper NPC, can I help you?', 
    choices = { 
                 choice1 = "Yes! I need help", 
                 choice2 = "No!! Leave me alone" 
    }, 

    onSelection = function (choice)  
        if choice == CurrentDialog["choices"]["choice1"] then CurrentDialog = getHelp end 
        if choice  == CurrentDialog["choices"]["choice2"] then CurrentDialog = goodbye_mean end 
    end 
} 
```

每个对话表对象都有一个`Say`元素，这个元素是当`Say`函数询问脚本其对话内容时将显示的文本。接下来，我们有两个可选元素，但如果你想与玩家进行交互，这些元素是必需的。第一个是一个名为`choices`的嵌套表，其中包含了对话系统在玩家请求时将呈现给玩家的选择。第二个可选元素实际上是一个函数。当用户选择一个选项时，将调用此函数，并由一些`if`语句组成。这些`if`语句将测试选择了哪个选项，并根据选择将`CurrentDialog`对象设置为对话树路径上的下一个对话。

这就是全部。以这种方式设计我们的对话树系统的最大优点是，即使没有太多指导，甚至非程序员也可以设计一个像之前展示的简单脚本。

如果你继续使用`Chapter08`解决方案运行`Dialog_Example`项目，你将看到这个脚本的运行并能与之交互。以下是一些截图，展示输出的样子：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/90b8913b-b9d6-4f62-9c06-f50dcb30720d.png)

尽管这是一个简单的系统实现，但它非常灵活。再次需要指出的是，这些脚本不需要重新编译即可进行更改。自己试试吧。对`NPC.lua`文件进行一些更改，重新运行示例程序，你会看到你的更改出现。

在下一节中，我们将看到如何通过 Lua 脚本实现一个由任务系统驱动的对话树。

# 脚本任务

另一个非常常见的高级游戏玩法系统是任务系统。虽然任务更常见于角色扮演游戏中，但也可以出现在其他类型的游戏中。通常，这些其他类型会通过不同的名称来掩饰任务系统。例如，一些游戏有挑战，本质上与任务是一样的。

任务可以简单地被认为是为了实现特定结果而进行的尝试。通常，任务将涉及必须在任务被视为完成之前进行的一定数量的步骤。一些常见类型的任务包括击杀任务，玩家通常必须击败一定数量的敌人，通常被称为**刷怪**，以及**交付**任务，玩家必须扮演信使的角色，并经常需要前往游戏世界的新位置交付货物。当然，这是一个很好的方式，可以让玩家前往下一个期望的位置而不强迫他们。在收集任务中，玩家必须收集一定数量的特定物品。在护送任务中，玩家经常因为历史上糟糕的实现而感到害怕，玩家经常必须陪同一个`NPC`前往新的位置，并保护他们免受伤害。最后，混合任务通常是上述类型的混合，并且通常是更长的任务。

任务系统的另一个常见部分是支持所谓的任务链或任务线。在任务链中，每个任务的完成都是开始序列中下一个任务的先决条件。随着玩家在任务链中的进展，这些任务通常涉及越来越复杂的任务。这些任务是逐渐揭示情节的一个很好的方式。

这解释了任务是什么。在下一节中，我们将讨论在我们的游戏项目中添加任务支持的几种不同方式。然而，在我们查看实现的具体细节之前，对于我们来说定义每个任务对象需要的是很有用的。

为了简单起见，我们将假设任务对象将由以下内容组成：

+   **任务名称**：任务的名称

+   **目标**：完成任务所必须采取的行动

+   **奖励**：玩家完成任务后将获得的奖励

+   **描述**：关于任务的一些信息，也许是玩家为什么要承担这项任务的背景故事

+   **任务给予者**：给予任务的`NPC`

有了这些简单的元素，我们就可以构建我们的基本任务系统。

正如我们在先前的游戏玩法系统示例中所看到的，我们可以以许多不同的方式来实现我们在示例引擎中的任务系统。现在让我们简要地看一下其中的一些，并讨论它们的优点和缺点。

# 引擎支持

我们支持任务系统的一种方式是将其构建到游戏引擎本身中。整个系统将设计得靠近引擎代码，并且使用本机引擎语言，对于我们来说是 C++。我们将创建基础设施来支持任务，使用我们已经多次看到的技术。通过继承，我们可以公开所需的基本函数和变量，并让开发人员构建这个结构。然后，一个简单的高级任务类可能看起来类似于以下内容：

```cpp
class Quest 
{ 
public: 
    Quest(std::string name,  
    std::vector<GameObjects> rewards,  
    std::string description,  
    NPC questGiver); 
    ~Quest(); 
    Accept(); //accept the quest 
    TurnIn(); //complete the quest 
private: 
     std::string m_questName; 
       std::vector<GameObjects> m_rewards; 
       std::string m_questDescription; 
       NPC m_questGiver; 
     Bool isActive; 
}; 
```

当然，这只是一个简单的演示，而在这种情况下，我们将跳过实现。

这种实现方法的优点是它是用本机代码编写的，意味着它将运行得很快，并且它靠近引擎，这意味着它将更容易地访问底层系统，而无需接口层或其他库的需要。

这种实现方法的缺点包括，因为它是游戏引擎或游戏代码的一部分，这意味着任何更改都需要重新编译。这也使得非编程人员难以添加他们自己的任务想法，或者在发布后处理任务系统的扩展。

虽然这种方法确实有效，但更适用于较小的项目，在这些项目中，一旦任务或系统就位，您将不需要或不想要对其进行更改。

# 引擎/脚本桥

这种方法与我们之前实现`NPC`对话系统的方法相同。在这种设计中，我们创建一个处理脚本加载和数据传递的接口类。由于我们之前已经看到了类似的实现，我将跳过这里的示例代码，而是继续讨论这种方法的优缺点。

这种实现方法的优点包括与仅引擎实现相比的灵活性。如果我们想要进行任何更改，我们只需要在编辑器中加载脚本，进行更改，然后重新加载游戏。这也使得非编码人员更容易创建自己的任务。

这种实现方法的缺点包括它仍然部分地与引擎本身相关。脚本只能访问引擎接口公开的元素和函数。如果您想要为任务添加更多功能，您必须在脚本使用之前将其构建到引擎端。

这种方法更适合于较大的项目，但如前所述，仍然有其缺点。

# 基于脚本的系统

我们可以采取的另一种方法是在我们的脚本语言中构建整个系统，只从引擎中公开通用方法。这些通用方法很可能是模板函数的良好候选者。在这种方法中，任务系统的内部和任务脚本都将用脚本语言编写。在脚本中编写的每个任务都将包括对处理管理的任务系统脚本的引用。这种方法与仅引擎方法非常相似；它只是从引擎中移出，并进入脚本系统。

让我们来看一个简化版本的任务系统脚本。出于简洁起见，有些部分被省略了：

```cpp
local questsys = {} 
questsys.quest = {} 

function questsys.new(questname, objectives, reward, description, location, level, questgiver) 
for keys, value in ipairs(objectives) do 
    value.value = 0 
  end 
  questsys.quest[#questsys.quest+1] = { 
    questname = questname, 
    objectives = objectives, 
    reward = reward, 
    description = description, 
    questgiver = questgiver, 
    accepted = false, 
    completed = false, 
    isAccepted = function(self) return self.accepted end, 
    isCompleted = function(self) return self.completed end 
  } 
end 

function questsys.accept(questname) 
  for key, value in ipairs(questsys.quest) do 
    if value.questname == questname then 
      if not value.accepted then 
        value.accepted = true 
      end 
  end 
end 

... 

function questsys.turnin(questname) 
  rejectMsg = "You have not completed the quest." 
  for key, value in ipairs(questsys.quest) do 
    if value.questname == questname then 
      for i, j in ipairs(questsys.quest[key].objectives) do 
        if j.value == j.maxValue then 
          value.completed = true 
          value.reward() 
        else return rejectMsg end 
      end 
  end 
end 

... 

questsys.get(questname, getinfo) 
  for key, value in ipairs(questsys.quest) do 
    if value.questname == questname then 
      if getinfo == "accepted" then return value:isAccepted() end 
      if getinfo == "completed" then return value:isCompleted() end 
      if getinfo == "questname" then return value.questname end 
      if getInfo == "description" then return value.description end 
      if getInfo == "location" then return value.location end 
      if getInfo == "level" then return value.level end 
      if getInfo == "questgiver" then return value.questgiver end 
    else error("No such quest name!") 
  end 
end 

return questsys 
```

再次，我省略了一些函数以节省空间，但理解系统所需的核心组件都在这里。首先，我们有一个创建新任务的函数，接受名称、目标、描述和任务给予者。然后我们有接受函数，将任务设置为活动状态。请注意，我们使用键/值查找方法来遍历我们的表 - 我们会经常这样做。然后我们有一个完成任务的函数，最后是一个简单的返回所有任务信息的函数。这里没有描绘的函数是用于获取和设置任务各种目标值的。要查看完整的实现，请查看代码存储库的`Chapter08`文件夹中的`Quest_Example`项目。

现在，有了任务系统脚本，我们有几个选择。首先，我们可以通过使用 Lua 内置的`require`系统将此系统添加到其他脚本中，这将允许我们在其他脚本中使用该脚本。这样做的语法如下：

```cpp
local questsys = require('questsys') 
```

或者我们可以简单地在游戏引擎中加载脚本并使用接口，就像我们在上一个示例中所做的那样，并以这种方式与我们的任务系统交互。有了这种灵活性，选择权在于开发人员和情况。

这种实现方法的优点包括极大的灵活性。在这种方法中，不仅可以修改任务，还可以在不需要重新构建游戏或引擎的情况下即时修改任务系统本身。这通常是在产品发布后包含可下载内容（DLC）、游戏修改（mod）和其他额外内容的方法。

这种实现的缺点包括，尽管它非常灵活，但增加了额外的复杂性。它也可能会更慢，因为系统是用解释性的脚本语言编写的，性能可能会受到影响。它还要求开发人员对脚本语言有更多的了解，并可能需要更多的学习时间。

像其他方法一样，这种方法也有其适用的场合和时间。虽然我倾向于在较大的项目中使用这样的系统，但如果团队没有准备好，这种方法可能会增加更多的开销而不是简化使用。

# 总结

在本章中，当涉及到实施高级游戏玩法系统时，我们涵盖了大量内容。我们深入探讨了如何在游戏项目中包含像 Lua 这样的脚本语言。然后我们在这些知识的基础上，探讨了实施对话和任务系统到我们示例引擎中的方法。虽然我们讨论了很多内容，但我们只是触及了这个主题的表面。在下一章中，我们将继续基于这些新知识，为我们的游戏构建一些人工智能。


# 第九章：人工智能

大多数游戏都建立在竞争取胜的概念上。这种形式的竞争可以采取多种形式。自最早的视频游戏以来，玩家们发现自己在与机器竞争。思考、反应和挑战计算机对手的加入使游戏感觉生动并与玩家联系在一起。在本章中，我们将学习如何通过引入人工智能来为我们的游戏增加思考。

本章涵盖以下内容：

+   什么是游戏人工智能？

+   做决定

+   运动和寻路技术

# 什么是游戏人工智能？

往往被误解的游戏人工智能的定义，以及游戏人工智能不是一项非常具有挑战性的任务。在 AI 这样一个广泛的领域中，很容易在这个主题上填满许多卷的书。鉴于我们只有一个章节来讨论这个概念和实施，在本节中，我们将尽力发展一个合理的游戏人工智能的定义以及它不是什么。

# 定义游戏人工智能

如前所述，确切地定义游戏人工智能是一项艰巨的任务，但我将尽力描述我认为是关于电子视频游戏的简明解释。当设计师创建游戏世界时，他们通过塑造愿景和定义一些常见的互动规则来实现。通常，玩家将通过观察世界的元素来体验这个世界。与世界的 NPC、对手和环境的互动，以及通过叙事方面，给玩家一种沉浸在游戏世界中的感觉。这些互动可以采取许多形式。在游戏中，玩家不断通过与无生命的物体互动来体验世界，但与其他人的互动才是真正突出的。这使得游戏感觉更具沉浸感、更具触感和更有生命力。

游戏世界中某物感觉活灵活现通常是通过对游戏世界和物体的观察来实现的，比如 NPC 做出决定。这是寻找游戏人工智能定义的一个重要标志。在更广泛的意义上，人工智能可以被认为是这种感知决策的应用。通常，这种决策的感知以自主的人工智能代理的形式出现，例如常见的 NPC。这些决定可能包括从移动、对话选择，甚至对环境的改变，这些改变可能传达开发者试图创造的体验。这再次是我在定义游戏人工智能时的另一个标志。本质上，这是关于开发者试图创造的体验。因此，游戏人工智能更多地是关于近似实现期望效果，而不一定是完美的科学解释。

当开发者着手创建人工智能体验时，重要的是要牢记玩家的乐趣和沉浸感。没有人想要与完美的对手对战。我们希望在互动的另一端感知到智能，只是不希望它更聪明。这就是游戏人工智能的开发和通用人工智能发展领域开始产生分歧的地方。我们将在下一节深入探讨这种分歧，但现在让我们看看游戏开发中人工智能的一些用途。

# 对话

通过对话进行某种形式的互动的游戏往往通过角色与玩家的连接以及玩家对他们故事的投入来给人一种沉浸在世界中的感觉。然而，这是一个挑战，通常是通过对话树来实现的，正如我们在上一章中所看到的。这种对话树的方法，在某些情况下是可靠的，但很容易变得复杂。

完全脚本化对话的另一个问题是，随着对话随着时间的推移而继续，玩家很快就会摆脱这是一种智能互动的幻觉。这使得互动感觉受限，反过来也使得世界感觉受限。解决这个问题的一种方法是在对话中引入人工智能。您可以使用决策算法来增强脚本化的互动，从而在回应中给人一种更深层次的智能感。在这个概念的极端方面，您可以采用一种解析玩家输入并动态生成回应的方法。这样的方法可能包括所谓的**自然语言处理**（**NLP**）。通过利用类似于聊天机器人的东西，设计师和工程师可以创建由在用户互动时思考的代理人所居住的世界。虽然这听起来可能非常诱人，但自然语言处理领域仍被认为处于起步阶段。借助云计算提供动力的 API，如微软的认知服务 API，创建支持 NLP 的基础设施的过程变得更加容易。然而，适当的实施和语言模型的培训可能非常耗时。

# 竞争对手

许多游戏包括敌人或竞争对手的概念，供玩家进行互动。事实上，我会说这是大多数人会认为是游戏人工智能的一个例子。这些对手如何与玩家、他们的环境和其他由 AI 控制的对手互动，都是他们的人工智能设计的一部分。通常，这种人工智能设计将包括决策制定的概念，如行为树、反馈循环、状态和其他模式。它们通常还会包括其他人工智能组件，如运动算法和路径规划技术，我们稍后将更深入地介绍。创建有趣而具有挑战性的对手并不是一件容易的事。正如我之前所说，没有人想玩一个他们觉得没有赢的机会的游戏。拥有一个比玩家更快更聪明的人工智能不应该是设计对手人工智能的目标；相反，您应该专注于给用户一个有竞争力的人工智能，可能能够适应玩家不断增长的技能。正是在这种情况下，像使用机器学习来构建自适应人工智能这样的高级技术开始引起关注。尽管这些技术仍处于探索阶段，但定制人工智能对手的日子可能很快就会到来。

# 运动和路径规划

可以说，与使用人工智能作为对手一样常见的是利用人工智能进行运动和路径规划的概念。在运动中使用人工智能包括实施算法来处理游戏元素的自主移动。诸如转向、追逐和躲避等概念都可以在人工智能算法中表达。运动人工智能也常常用于处理简单的碰撞回避。路径规划是使用人工智能在将游戏对象从一个位置移动到另一个位置时找到最有效或最有效的路线的概念。自六十年代以来，**Dijkstra**和**A***等算法一直存在，并为路径规划人工智能的发展提供了支柱。我们将在本章后面更深入地探讨运动和路径规划算法和技术。

# 游戏人工智能不是什么

人工智能作为一个研究领域非常广泛，实际上包括的远不止游戏使用的内容。最近，围绕开发者空间中的人工智能的讨论变得更加广泛，越来越多的开发者寻求在其项目中利用人工智能技术的方法。因此，我认为重要的是要提及游戏开发领域之外一些更常见的人工智能用例。

AI 领域中最热门的领域之一是机器学习。**机器学习**（**ML**）可能最好由 Arthur Lee Samuel 描述，当他创造了机器学习这个术语时：*计算机学习如何在没有明确编程的情况下实现结果或预测的能力。*在数据分析领域，机器学习被用作一种方法来设计复杂的模型和算法，帮助预测给定问题的结果。这也被称为预测性分析。这些分析模型允许研究人员和数据科学家创建可靠、可重复的计算和结果，并通过数据中的历史关系和趋势发现其他见解。正如前一节中提到的，定制 AI 从您的游戏风格中学习并适应的想法是非常吸引人的概念。然而，这可能是一个很棘手的问题；如果 AI 变得太聪明，那么游戏的乐趣水平就会迅速下降。机器学习在游戏中的使用的一个很好的例子是 Forza 赛车游戏系列。在这里，赛车 AI 头像通过云计算驱动的机器学习实现来调整您遇到的 AI 赛车手的竞争水平，以适应您当前的能力水平。

AI 在游戏开发领域之外的另一个不断增长的用途是其在数据挖掘场景中的应用。虽然这一领域的 AI 仍处于早期阶段，但其在理解用户和客户数据方面的应用对许多商业部门非常有吸引力。这种 AI 用例的边界及其与游戏开发概念的潜在重叠尚未被定义。然而，一些数据挖掘的核心组件，用于理解玩家如何与游戏及其各个组件进行交互，很容易被视为对游戏开发者有益。准确了解玩家如何与游戏 GUI 等元素进行交互，将使开发者能够为每个用户创造更好的体验。

我想要讨论的 AI 在游戏开发领域之外的最后一个用例可能是当普通人想到 AI 时最为认可的用途之一，那就是在认知处理研究中使用 AI。在 AI 的学术解释中，认知处理是开发科学上可证明的这些过程的模型。这基本上可以概括为在 AI 过程中对人类智能进行建模。虽然这种方法对科学研究非常重要，但目前对游戏开发的用例来说还太过抽象，无法被认为是有用的。也就是说，机器人和自然语言处理的使用开始渗入游戏开发，正如前面提到的。

学术和研究 AI 的具体目标往往与游戏 AI 的目标完全不同。这是因为两者之间的实现和技术的固有差异完全不同。更多时候，游戏 AI 解决方案会倾向于简化方法，以便进行简单的更改和调整，而研究方法很可能会选择最科学完整的实现。在接下来的几节中，我们将看一些这些更简单的游戏开发实现，并讨论它们的用例和理论。

# 做决定

AI 的目标更多地是给人类智能的外观。智能感知的关键方面之一是 AI 代理做出决策的想法。即使是脚本化的，对某些行动有选择权，给玩家一种思考世界的感觉，由思考实体构成。在下一节中，我们将介绍游戏 AI 中一些更为知名的决策制定技术。

# AI 状态机

如果你一直在按章节跟着这本书，你可能已经注意到状态模式的使用不止一次。这种模式是一个非常强大的模式，因此在我们各种组件设计中经常使用。在人工智能领域，状态模式再次成为一颗耀眼的明星。状态机的使用，特别是有限状态机（FSM），允许对代码的执行流程进行详细的表示。它非常适合在游戏中实现 AI，允许设计强大的交互而不需要复杂的代码。

我不打算花太多时间来讨论有限状态机实现的概念和理论，因为我们已经详细覆盖了。相反，我们将看一个在 AI 脚本中实现它的例子。如果你需要对这种模式进行复习，请查看第五章中关于理解状态的部分。

以下是一个描述敌人简单大脑的图表。在这个例子中，每个状态代表一个动作，比如搜索或攻击：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/b5527c00-1545-4e52-bce6-e5ed22d608fa.png)

虽然这是一个简单的例子，但它确实为许多情况提供了有用的 AI。我们可以在 C++中实现这个项目，就像我们在*Screen*示例和其他地方看到的那样。然而，如果你已经阅读了前一章，你会看到我们可以在脚本中实现这样的逻辑。当然，这使我们能够灵活地进行脚本编写，比如不必重新构建项目来调整代码的元素。这对于 AI 来说非常有益，因此在本章中，我将展示使用 Lua 脚本的示例代码，这可以使用前一章中描述的步骤来实现。

在 Lua 脚本中，这种 AI 设计的可能实现可能看起来类似于以下内容：

```cpp
Search = function () 
{ 
    //Do search actions.. 
    if playerFound == true then currentState = Attack end 
} 
Attack = function() 
{ 
    //Do attack actions 
    if playerAttacks == true then currentState = Evade  
    elseif playerOutOfSight == true then currentState = Search end 
} 
Evade = function() 
{ 
    //Do evade actions 
    If healthIsLow == true then currentState = FindHealth 
    Elseif playerRetreats == true then currentState == Attack end 
} 
FindHealth = function() 
{ 
    //Do finding health actions 
    If healthFound == true then currentState = Search end 
} 
currentState = Search 
```

这应该看起来很熟悉，就像上一章中的 NPC 对话示例。在这里，为了完成系统，我们首先会将脚本加载到 AI 代理或 NPC 的实例中，然后在游戏代码的`Update`循环中调用`currentState`变量当前分配的函数。通过这种代码实现，我们有了一种有效的构建基本 AI 交互的方法。这种技术自游戏开发的早期就存在。事实上，这与街机经典游戏《吃豆人》中的幽灵对手 AI 的实现非常相似。

我们还可以扩展这种简单的 FSM 实现，并将基于堆栈的 FSM 添加到解决方案中。这与第五章中看到的实现示例非常相似，因此我不会详细介绍关于基于堆栈的 FSM 理论的所有细节。基于堆栈的 FSM 的基本原则是，我们可以按照先进后出的顺序向堆栈添加和移除对象。向堆栈添加项目的常用术语称为推送，从堆栈中移除对象的操作称为弹出。因此，对于状态示例，在不同的函数期间，堆栈可能看起来类似于以下图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/8f905652-25f7-47ee-b792-c05b26056e84.png)

使用基于堆栈的 FSM 的一个主要优势是，现在可以使用堆栈来控制当前状态。每个状态可以从堆栈中弹出自己，允许执行下一个状态。我们还可以实现“进入”和“退出”的概念，使我们能够在状态内部有更多的状态。我们可以在每个状态中进行设置和清理等操作，使我们的 AI 状态系统更加灵活。

在 Lua 脚本中实现基于堆栈的有限状态机（FSM）的状态可能看起来类似于以下内容：

```cpp
StateA =  
{ 
    Update = function () 
    { 
        //Do state update actions 
} 
OnEnter = function() 
{ 
    //Do actions for first load 
} 
OnExit = function() 
{ 
    //Do action for last call for this state 
} 
} 
```

然后，在我们的 C++代码中，我们将添加其余的架构，以支持基于状态的 FSM。在这里，我们将创建一个向量或数组对象，该对象将保存从 Lua 脚本中加载的状态对象的指针。然后，我们将调用`OnEnter`、`OnExit`和`Update`函数，用于当前占据数组中最后一个元素的状态对象。如前所述，我们可以通过简单创建一个枚举并切换案例来处理状态流。我们也可以创建一个`StateList`类，该类将实现包装 FSM 所需函数。对于我们的示例，这个`StateList`类可能如下所示：

```cpp
class StateList { 
    public: 
        StateList (); 
        ~ StateList (); 

        LuaState * GoToNext(); 
        LuaState * GoToPrevious(); 

        void SetCurrentState(int nextState); 
        void AddState(State * newState); 

        void Destroy(); 

        LuaState* GetCurrent(); 

    protected: 
        std::vector< LuaState*> m_states; 
        int m_currentStateIndex = -1; 
    }; 
} 
```

无论你选择以哪种方式实现基于状态的 FSM，你仍然会获得堆栈控制的额外好处。正如你所看到的，状态模式在 AI 开发中使用时，为我们创建 AI 交互提供了一个伟大而灵活的起点。接下来，我们将看一些其他技术，介绍如何将决策引入到你的 AI 设计中。

# 决策树

决策树是一种类似流程图的结构，由分支和叶子组成。树的每个分支都是一个条件，用于做出决策。每个叶子是在条件中做出的选择的动作。在树的最远端，叶子是控制 AI 代理的实际命令。使用决策树结构可以更容易地设计和理解 AI 实现的流程。在决策树中实现的简单 AI 大脑可能看起来类似于以下图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/f564e89d-5d08-456f-8ce9-0844c823035f.png)

你可能会想到，这看起来和听起来非常像我们在第八章中实现的对话树，*高级游戏系统*。那是因为它们就是！就像在处理对话和选择的情况下一样，使用树结构是脚本化 AI 交互流程的一种绝佳方式。决策树可以非常深，具有调用执行特定功能的子树的分支和节点。这使设计师能够使用大量不同的决策库，这些决策可以链接在一起，提供令人信服的 AI 交互深度。你甚至可以发展出可以根据当前任务的整体可取性排序的分支，然后在所需的分支失败时回退到其他决策。这种弹性和灵活性正是树结构的优势所在。

熟悉 C++数据结构的人可能已经在考虑如何在代码中实现这种树结构。也许列表已经浮现在脑海中。有许多不同的实现决策树的方法。我们可以将树定义为外部格式，比如 XML。我们可以使用 C++和 Lua 等脚本语言的混合来实现它的结构和架构，但由于我真的想要深入理解树设计，我们将把整个实现放在 Lua 中。这可以通过 David Young 在书籍*使用 Lua 学习游戏 AI 编程*中演示的一个很好的例子来完成，所以我们将以 David 更详细的例子为基础，构建我们的简单示例。

首先，让我们看一下树对象的结构。在`DecisionTree.lua`文件中，我们可以有以下代码：

```cpp
DecisionTree = {}; 

function DecisionTree.SetBranch(self, branch)     
self.branch_ = branch; 
end 

function DecisionTree.Update(self, deltaTime)     
-- Skip execution if the tree hasn't been setup yet.     
if (self.branch_ == nil) then 
        return; 
    end 
    -- Search the tree for an Action to run if not currently     
    -- executing an Action. 
    if (self.currentAction_ == nil) then 
        self.currentAction_ = self.branch_:Evaluate(); 
        self.currentAction_:Initialize(); 
    end 
        local status = self.currentAction_:Update(deltaTime); 
end 
function DecisionTree.new() 
    local decisionTree = {}; 
        -- The DecisionTree's data members. 
    decisionTree.branch_ = nil; 
    decisionTree.currentAction_ = nil; 
        -- The DecisionTree's accessor functions. 
    decisionTree.SetBranch = decisionTree.SetBranch; 
    decisionTree.Update = decisionTree.Update; 
        return decisionTree; 
end 
```

在我们的树结构中，我们实现了一个更新循环，该循环评估树中的根分支并处理结果动作。一旦动作被创建、处理和完成，决策树将重新评估自身，从根分支重新开始确定下一个要执行的动作。

接下来是分支对象。在我们的实现中，分支将包括一个条件，该条件将确定接下来执行哪个元素。条件评估的责任是返回一个值，该值范围从分支中的子级的最大数量。这将表示应该执行哪个元素。我们的决策分支 Lua 类对象将具有基本函数，用于添加额外的子级以及在分支计算期间使用的设置条件函数。在`DecisionBranch.lua`文件中，我们可以有一个类似以下的实现：

```cpp
DecisionBranch = {} 
DecisionBranch.Type = " DecisionBranch "; 
function DecisionBranch.new() 
    local branch = {}; 
    -- The DecisionBranch data members. 
    branch.children_ = {}; 
    branch.conditional_ = nil; 
    branch.type_ = DecisionBranch.Type; 
    -- The DecisionBranch accessor functions. 
    branch.AddChild = DecisionBranch.AddChild; 
    branch.Evaluate = DecisionBranch.Evaluate; 
    branch. SetConditional = DecisionBranch. SetConditional; 
    return branch; 
end 
function DecisionBranch.AddChild(self, child, index) 
    -- Add the child at the specified index, or as the last child. 
    index = index or (#self.children_ + 1); 
        table.insert(self.children_, index, child); 
end 
function DecisionBranch.SetConditional (self, conditional) 
    self. conditional _ = conditional; 
end 
```

正如大卫在他的例子中指出的那样，由于叶子只是动作，我们可以将每个叶子动作包含在分支中。这使我们能够在代码中获得所需的功能，而无需额外的结构。通过使用`type_ 变量`，我们可以确定分支的子级是另一个分支还是需要执行的动作。

对于分支本身的评估，我们执行条件，然后使用返回的值来确定树中的下一步。值得注意的是，树中的每个分支最终都必须以一个动作结束。如果树中有任何不以动作结束的叶子，那么树就是畸形的，将无法正确评估。

留在`DecisionBranch.lua`文件中，评估分支的代码看起来类似以下内容：

```cpp
function DecisionBranch.Evaluate(self) 
    -- Execute the branch's evaluator function, this will return a 
    -- numeric value which indicates what child should execute. 
    local conditional = self. conditional _(); 
    local choice = self.children_[conditional]; 
    if (choice.type_ == DecisionBranch.Type) then 
        -- Recursively evaluate children to see if they are decision branches. 
        return choice:Evaluate(); 
    else 
        -- Return the leaf action. 
        return choice; 
    end 
end 
```

现在我们已经有了树数据结构，我们可以继续构建一个供使用的树。为此，我们首先创建决策树的新实例，创建树中所需的每个分支，连接条件分支，最后添加动作叶子。在`AILogic.lua`文件中，我们可以有类似以下的内容：

```cpp
function AILogic_DecisionTree() 
    --Create a new instance of the tree 
    local tree = DecisionTree.new(); 
--Add branches 
local moveBranch = DecisionBranch.new(); 
    local shootBranch = DecisionBranch.new(); 
    --Connect the conditional branches and action leaves 
... 
moveBranch:AddChild(MoveAction()); 
      moveBranch:AddChild(randomBranch); 
      moveRandomBranch:SetConditional( 
        function() 
            if Conditional_HasMovePosition() then 
                return 1; 
            end 
            return 2; 
        end); 
... 
    --Set initial branch 
    tree:SetBranch(moveBranch); 
return tree; 
end 
```

有了决策树，我们现在可以调用此脚本并将树加载到 AI 代理对象中。我们可以随时进行更改，添加更多决策和动作，甚至添加其他 AI 技术来增强决策。虽然决策树允许开发人员和设计师创建易于理解和阅读的 AI 结构，但它也有缺点。最显着的缺点之一是其对复杂逻辑条件的建模，其中您需要考虑条件的每种可能结果。此外，随着更多分支可能性的增加，树也将开始需要平衡。如果不进行平衡，树的部分将需要复制，迅速增加树结构的复杂性，并导致更容易出现错误的代码。

# 反馈循环

我想简要谈一下 AI 决策中的最后一个主题，即反馈循环的概念。反馈循环是指系统的某个输出值被反馈或返回给系统，进而影响系统的状态，影响其后续值。理想情况下，在视频游戏中，特别是在 AI 交互中，每个循环都应该是一个稳定的反馈循环。稳定反馈循环的简单定义是系统的输出用于扭转导致反馈值的情况，使反馈系统移动到稳定状态的收敛。这可以防止您的 AI 反馈引起负面或正面反馈循环的失控效应。

为了帮助您真正理解反馈循环是什么，让我们以视频游戏中最常见的例子来说明，即耐力。耐力在许多场景中都有体现，比如角色奔跑或奔跑的能力，或者角色攀爬的能力。在我们的例子中，我们将看一下拳击比赛的例子。以下是一个显示我们想要实现的反馈循环的图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/3a09fb51-5a12-447c-8e09-6f492d48f86b.png)

如前所述，我们需要确保拳击示例中的耐力反馈循环是稳定的。 这意味着当我们达到预定义的低耐力水平时，我们需要将循环切换到防守，以便我们恢复耐力。 如果达到预定义的恢复水平，我们则相反地切换到进攻以降低耐力水平。 这种切换允许我们保持循环稳定，并被称为振荡反馈循环。

在代码中实现这一点是令人惊讶地简单：

```cpp
void Update(float deltaTime) 
{ 
    if(currentState == attacking) 
    { 
        ReduceStamina(); 
    if(player.stamina <= depleted) 
{ 
        currentState = defending; 
} 
} 
else if (currentState == defending) 
{ 
    IncreaseStamina(); 
    if(stamina >= replenished) 
    { 
        currentState = attacking; 
    } 
} 
} 
```

就是这样，老实说。 编写这种技术的实现并不复杂。 我们确实跳过了一些事情，比如如何处理减少和增加耐力。 考虑到这是一个 AI 系统，我们希望它看起来更真实，因此静态地增加这些值并不是很好。 在这里放置一个好的随机值可以使其更具真实感。 最终，这是一种易于实现的技术，可以提供一种很好的方式来改变结果，并为 AI 组件提供更独特的交互。

# 运动和路径规划技术

AI 代理和其他非玩家角色经常需要在游戏世界中移动。 实现这种移动，使其看起来像是真实的，是一个具有挑战性的过程。 在下一节中，我们将看看如何实现算法和技术，以将 AI 代理的移动和路径规划添加到我们的游戏开发项目中。

# 运动算法和技术

使用运动算法来控制 AI 代理在关卡或游戏世界中的移动是视频游戏中 AI 算法的一个非常常见的用例。 这些算法可以实现行为，给人以思考和反应的 AI 代理的印象，它们还可以执行其他任务，如简单的物体避让。 在下一节中，我们将看一些这些运动技术。

# 转向行为

转向行为是由各种技术组成的运动算法的子集，用于基于外部和内部变量控制 AI 代理的移动。 在我们的示例引擎中，我们已经整合了一个 3D 物理计算库-请参阅第五章，“构建游戏系统”，进行复习-我们已经有了一个 NPC 类的概念，作为我们的 AI 代理。 这意味着我们已经拥有了创建基于牛顿物理的转向系统所需框架的大部分内容，也称为基于转向的运动系统。 基于转向的运动系统由几个不同的分类组成，用于向 AI 代理添加力。 这些包括寻找、逃避、规避、徘徊、追逐等分类。 这些算法的完全详细实现将占据自己的章节，因此我们将专注于每个算法的高级概念和用例。 为了帮助您在实现方面，我在示例引擎中包含了`OpenSteer`库。 `OpenSteer`将处理计算的细节，使我们的引擎和我们的 AI Lua 脚本更容易使用这些算法来控制代理的移动。

以下是运行寻找和逃避算法的`OpenSteer`库程序的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/43b0b05a-2f94-4307-b446-e3279bd3c877.png)

# 寻找

让我们从寻找算法开始。 寻找算法的目标是引导 AI 代理朝向游戏空间中的特定位置。 这种行为施加力，使当前航向和期望的航向朝向目标目的地对齐。 以下图表描述了这个过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/f1d19952-67a0-4381-b46c-cda9dfd4ce6b.png)

**期望航向**实际上是一个从角色到目标的方向向量。**期望航向**的长度可以设置为一个值，比如角色当前的速度。转向向量或**寻找路径**是期望航向与角色当前航向的差。这个方程可以简化为以下形式：

```cpp
    desiredHeading = normalize (position - target) * characterSpeed 
    steeringPath = desiredHeading - velocity 
```

寻找算法的一个有趣的副作用是，如果 AI 代理继续寻找，它最终会穿过目标，然后改变方向再次接近目标。这会产生一种看起来有点像蛾子围绕灯泡飞舞的运动路径。要使用`OpenSteer`来计算转向力，你需要调用`steerForSeek`函数，传递一个 3 点向量来描述目标的位置：

```cpp
Vec3 steerForSeek (const Vec3& target); 
```

# ![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/cc201d75-cfb0-4d7f-be36-63174f2b835b.png)

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/cc201d75-cfb0-4d7f-be36-63174f2b835b.png)

逃避

使用`OpenSteer`来计算逃避 AI 代理的转向力，你需要调用`steerForEvasion`函数，传递一个对象作为我们要逃避的目标，以及一个浮点值来指定在计算要施加的力时要使用的未来最大时间量：

```cpp
 Vec3 steerForFlee (const Vec3& target); 
```

# 追逐

追逐转向行为与寻找行为非常相似，但这里的区别在于目标点实际上是一个移动的对象或玩家。下图说明了这个行为：

逃避

为了创建有效的追逐行为，我们需要对目标的未来位置进行一些预测。我们可以采取的一种方法是使用一个预测方法，在每次更新循环中重新评估。在我们简单的预测器中，我们将假设我们的目标在此更新循环中不会转向。虽然这种假设更容易出错，但预测结果只会在一小部分时间（1/30）内使用。这意味着，如果目标确实改变方向，下一个模拟步骤中将根据目标改变方向进行快速修正。同时，根据这个假设，可以通过将目标的速度乘以 X 并将该偏移添加到其当前位置来计算 X 单位时间内的目标位置。然后，只需将寻找转向行为应用于预测的目标位置，就可以实现追逐行为。

要使用`OpenSteer`来计算追逐 AI 代理的转向力，你需要调用`steerForPursuit`函数，传递一个对象作为我们要追逐的目标：

```cpp
Vec3 steerForPursuit (const TargetObject& target); 
```

# 使用`OpenSteer`来计算逃避 AI 代理的转向力，你需要调用`steerForFlee`函数，传递一个 3 点向量来描述目标的位置：

逃避就像逃离是寻找的反向，逃避是追逐的反向。这意味着，我们不是朝着目标的计算未来位置驾驶 AI 代理，而是从目标的当前位置逃离。下图说明了这个行为：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/d565e6ae-e0fc-4f4e-8276-c69a6bd33bc3.png)

使用逃避转向行为时，AI 代理将远离预测的相遇点。这通常会导致不太自然的行为，因为大多数真正逃离的实体可能会有一个随机的逃避模式。实现更自然效果的一种方法是修改施加的力与另一个行为，比如我们接下来将要介绍的漫游行为。

逃避行为就是寻找行为的反向。这意味着，AI 代理不是朝着特定目标对齐航向，而是朝着目标点的相反方向对齐航向。下图说明了这个过程：

```cpp
Vec3 steerForEvasion (const AbstractVehicle& menace, 
                      const float maxPredictionTime); 
```

# 漫游

正如我之前提到的，有时通过添加另一个行为来修改力来使行为有一些波动会更好。漫游行为是一个很好的修改行为的例子。漫游行为基本上返回一个与代理的前向矢量相关的切线转向力。值得注意的是，由于漫游行为旨在为代理的移动增加一些偏差，它不应该单独用作转向力。

要使用`OpenSteer`来为 AI 代理计算漫游转向力，你可以调用`steerForWander`函数，并传递一个浮点值来指定漫游之间的时间步长。时间步长值允许在帧时间变化时保持漫游速率一致：

```cpp
Vec3 steerForWander (float dt); 
```

虽然这本书中我们只能花这么多时间来研究 AI 转向行为，但我们只是开始了解可用的内容。像群集和简单的物体避让这样的概念不幸地超出了本章的范围，但是`OpenSteer`库完全支持这些概念。如果你有兴趣了解更多关于这些行为的内容，我强烈建议阅读`OpenSteer`文档。

# 搜索算法和路径规划技术

在许多游戏中，我们经常需要找到从一个位置到另一个位置的路径。游戏开发中人工智能的另一个非常常见的需求，也是本章将要涉及的最后一个需求，是使用搜索算法来寻找 AI 代理周围移动的最佳路径。

例如，这里我们将专注于图搜索算法。图搜索算法，顾名思义，使用图作为其数据输入的来源。在我们的地图示例中，图是一组位置和它们之间的连接。它们通常分别被称为节点和边。以下是一个非常基本的图数据可能看起来像的示例：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/d09f3fab-ad19-4a00-ac89-5e885b73a3a2.png)

这些图搜索算法的输出可以用来制定 AI 代理需要采取的路径。这条路径由图的节点和边组成。值得注意的是，这些算法会告诉你的 AI 去哪里移动，但不会提供如何移动。这些算法不像本章前面的转向力算法，它们不会移动 AI 代理。然而，结合转向算法，这些路径规划算法将创建出色的整体 AI 行为。

现在我们对图是如何表示地图以及我们想要找到路径的点有了基本的了解，让我们来看一些最常用的算法。

# 广度优先

广度优先搜索是最简单的搜索算法。它平等地探索所有方向。那么它是如何探索的呢？在所有这些搜索算法中，关键思想是跟踪一个不断扩展的区域，称为前沿。广度优先算法通过从起点向外移动并首先检查其邻居，然后是邻居的邻居，依此类推来扩展这个前沿。以下是一个显示这种扩展在网格上发生的图表。数字表示网格方格被访问的顺序：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/ms-cpp-gm-dev/img/b90ad766-5e37-42ba-b7ff-2f12df3882f0.png)

以下是如何在 C++中实现这一点的一个简单示例。出于篇幅考虑，我省略了一些代码部分。完整的实现可以在源代码库的`Chapter09`示例项目中找到：

```cpp
void SearchGraph::BreadthFirst(int s) 
{ 
    // Mark all the vertices as not visited 
    bool *visited = new bool[V]; 
    for(int i = 0; i < V; i++) 
        visited[i] = false; 

    // Create a queue for BFS 
    list<int> queue; 

    // Mark the current node as visited and enqueue it 
    visited[s] = true; 
    queue.push_back(s); 

    // 'i' will be used to get all adjacent vertices of a vertex 
    list<int>::iterator i; 

    while(!queue.empty()) 
    { 
        // Dequeue a vertex from queue and print it 
        s = queue.front(); 
        cout << s << " "; 
        queue.pop_front(); 

        // Get all adjacent vertices of the dequeued vertex s 
        // If a adjacent has not been visited, then mark it visited 
        // and enqueue it 
        for(i = adj[s].begin(); i != adj[s].end(); ++i) 
        { 
            if(!visited[*i]) 
            { 
                visited[*i] = true; 
                queue.push_back(*i); 
            } 
        } 
    } 
} 
```

从源代码中你可能已经注意到，这个算法的一个技巧是我们需要避免重复处理节点并多次处理一个节点。在这个简单的例子中，我们实现了一个布尔值数组来标记已访问的节点。如果我们不在这个例子中标记已访问的顶点，我们就会创建一个无限循环过程。

这是一个非常有用的算法，不仅适用于常规路径规划，还适用于程序地图生成、流场路径规划、距离图和其他类型的地图分析。

# Dijkstra 算法

在某些情况下，当每一步都可能有不同的成本时，我们需要找到最短的路径。例如，在*文明*游戏系列中，穿越不同的地形类型需要不同数量的回合。在这种情况下，我们可以实现 Dijkstra 算法，也称为**统一成本搜索**。这个算法让我们可以优先考虑要探索的路径。它不是平等地探索所有可能的路径，而是偏向于成本较低的路径。为了实现路径的优先级，我们需要跟踪移动成本。实质上，我们希望在决定如何评估每个位置时考虑移动成本。在这个算法中，我们需要所谓的优先队列或堆。使用堆而不是常规队列会改变前沿的扩展方式。以下是 C++中演示 Dijkstra 算法的示例代码摘录，为了节省空间，我再次省略了一些部分。您可以在源代码库的`Chapter09`文件夹中找到完整的 Dijkstra 示例：

```cpp
// Prints shortest paths from src to all other vertices 
void SearchGraph:: Dijkstra(int src) 
{ 
    // Create a priority queue to store vertices that are being preprocessed 
    priority_queue< iPair, vector <iPair> , greater<iPair> > pq; 

    // Create a vector for distances and initialize all distances as infinite (INF) 
    vector<int> dist(V, INF); 

    // Insert source itself in priority queue and initialize its distance as 0\. 
    pq.push(make_pair(0, src)); 
    dist[src] = 0; 

    /* Looping till priority queue becomes empty (or all 
      distances are not finalized) */ 
    while (!pq.empty()) 
    { 
        int u = pq.top().second; 
        pq.pop(); 

        // 'i' is used to get all adjacent vertices of a vertex 
        list< pair<int, int> >::iterator i; 
        for (i = adj[u].begin(); i != adj[u].end(); ++i) 
        { 
            // Get vertex label and weight of current adjacent of u. 
            int v = (*i).first; 
            int weight = (*i).second; 

            // If there is shorted path to v through u. 
            if (dist[v] > dist[u] + weight) 
            { 
                // Updating distance of v 
                dist[v] = dist[u] + weight; 
                pq.push(make_pair(dist[v], v)); 
            } 
        } 
    } 

    // Print shortest distances stored in dist[] 
    printf("Vertex   Distance from Sourcen"); 
    for (int i = 0; i < V; ++i) 
        printf("%d tt %dn", i, dist[i]); 
}  
```

这个算法在使用不同成本找到最短路径时非常好，但它确实浪费时间在所有方向上探索。接下来，我们将看看另一个算法，它让我们找到通往单一目的地的最短路径。

# A*

在路径规划中，可以说最好和最流行的技术之一是**A***算法。A*是 Dijkstra 算法的一种优化，适用于单一目的地。Dijkstra 算法可以找到到所有位置的路径，而 A*找到到一个位置的路径。它优先考虑似乎更接近目标的路径。实现非常类似于 Dijkstra 实现，但不同之处在于使用启发式搜索函数来增强算法。这种启发式搜索用于估计到目标的距离。这意味着 A*使用 Dijkstra 搜索和启发式搜索的总和来计算到某一点的最快路径。

以下是维基百科提供的 A*算法过程的伪代码示例，非常出色（[`en.wikipedia.org/wiki/A*_search_algorithm`](https://en.wikipedia.org/wiki/A*_search_algorithm)）：

```cpp
function A*(start, goal) 
    // The set of nodes already evaluated 
    closedSet := {} 

    // The set of currently discovered nodes that are not evaluated yet. 
    // Initially, only the start node is known. 
    openSet := {start} 

    // For each node, which node it can most efficiently be reached from. 
    // If a node can be reached from many nodes, cameFrom will eventually contain the 
    // most efficient previous step. 
    cameFrom := the empty map 

    // For each node, the cost of getting from the start node to that node. 
    gScore := map with default value of Infinity 

    // The cost of going from start to start is zero. 
    gScore[start] := 0 

    // For each node, the total cost of getting from the start node to the goal 
    // by passing by that node. That value is partly known, partly heuristic. 
    fScore := map with default value of Infinity 

    // For the first node, that value is completely heuristic. 
    fScore[start] := heuristic_cost_estimate(start, goal) 

    while openSet is not empty 
        current := the node in openSet having the lowest fScore[] value 
        if current = goal 
            return reconstruct_path(cameFrom, current) 

        openSet.Remove(current) 
        closedSet.Add(current) 

        for each neighbor of current 
            if neighbor in closedSet 
                continue        // Ignore the neighbor which is already evaluated. 

            if neighbor not in openSet    // Discover a new node 
                openSet.Add(neighbor) 

            // The distance from start to a neighbor 
            tentative_gScore := gScore[current] + dist_between(current, neighbor) 
            if tentative_gScore >= gScore[neighbor] 
                continue        // This is not a better path. 

            // This path is the best until now. Record it! 
            cameFrom[neighbor] := current 
            gScore[neighbor] := tentative_gScore 
            fScore[neighbor] := gScore[neighbor] + heuristic_cost_estimate(neighbor, goal) 

    return failure 

function reconstruct_path(cameFrom, current) 
    total_path := [current] 
    while current in cameFrom.Keys: 
        current := cameFrom[current] 
        total_path.append(current) 
    return total_path 
```

这就是我们对一些常见路径规划技术的快速介绍。虽然在本节中我们看到了一些实现，但如果您正在寻找生产游戏的绝佳起点，我强烈建议您查看一些开源库。这些是非常有价值的学习资源，并提供了经过验证的实现技术，您可以在此基础上构建。

# 总结

在本章中，我们在短时间内涵盖了一个广泛的研究领域。我们对游戏 AI 的真正定义进行了基本界定，以及它不是什么。在本章中，我们还探讨了如何通过包括 AI 技术来扩展决策功能。我们讨论了如何通过使用转向力和行为来控制 AI 代理的移动。最后，我们通过查看路径规划算法的使用来为我们的 AI 代理创建从一个点到另一个点的路径来结束了本章。虽然我们在本章中涵盖了相当多的内容，但在游戏 AI 的世界中仍有许多未被发掘的内容。我恳请您继续您的旅程。在下一章中，我们将看看如何将多人游戏和其他网络功能添加到我们的示例游戏引擎中。
