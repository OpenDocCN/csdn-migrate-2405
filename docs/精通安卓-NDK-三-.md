# 精通安卓 NDK（三）

> 原文：[`zh.annas-archive.org/md5/F3DC9D6FA4DADE68301DCD4BEC565947`](https://zh.annas-archive.org/md5/F3DC9D6FA4DADE68301DCD4BEC565947)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：OpenGL ES 3.1 与跨平台渲染

在本章中，我们将学习如何实现在 OpenGL 4 和 OpenGL ES 3 之上的抽象层，以便让我们的图形应用程序能在 Android 和桌面计算机上运行。首先，我们从一些基本的向量与线性代数类开始。

# 线性代数与变换

在`Core/VecMath.h`文件中，有一系列针对向量和矩阵的特定类和辅助工具。我们主要使用的类是`LVector2`、`LVector3`、`LVector4`、`LMatrix3`、`LMatrix4`和`LQuaternion`，这些类定义了基本的代数运算。它们有一些快捷方式，以便编写任何数学密集型代码：

```java
using vec2 = LVector2;
using vec3 = LVector3;
using vec4 = LVector4;
using mat3 = LMatrix3;
using mat4 = LMatrix4;
using quat = LQuaternion;
```

这个小型数学库基本上是从 Linderdaum Engine ([`www.linderdaum.com`](http://www.linderdaum.com))压缩的一些代数代码。

此外，在`Math`命名空间中有一组有用的函数，用于处理不同的投影变换计算。在后续章节中，它们将被大量使用。

# 使用 SDL2 进行图形初始化

在我们之前的书籍《*Android NDK Game Development Cookbook*, *Packt Publishing*》中，我们详细学习了如何初始化 Android 上的 OpenGL ES 2 和桌面上的 OpenGL 3 核心配置。现在，我们将使用 SDL2 库来完成这项工作，该库可在[`www.libsdl.org`](https://www.libsdl.org)获取。让我们看看`1_GLES3`示例。这个示例的 Java 代码（除了 SDL2 内部实现之外）简短且简单：

```java
package com.packtpub.ndkmastering;
import android.app.Activity;
import android.os.Bundle;
public class AppActivity extends org.libsdl.app.SDLActivity
{
  static
  {
    System.loadLibrary( "NativeLib" );
  }
  public static AppActivity m_Activity;
  @Override protected void onCreate( Bundle icicle )
  {
    super.onCreate( icicle );
    m_Activity = this;
  }
};
```

其他所有操作都在 C++代码中完成。有一个`main()`函数，它通过 SDL2 使用宏重新定义，使我们的应用程序看起来像是桌面应用程序：

```java
int main(int argc, char* argv[])
{
  clSDL SDLLibrary;
```

首先，使用`clSDLWindow`类创建一个窗口和一个 OpenGL 渲染上下文：

```java
  g_Window = clSDLWindow::CreateSDLWindow( "GLES3", 1024, 768 );
```

然后，我们可以获取 OpenGL 函数的指针。这种抽象比静态链接到 OpenGL 库更优越，因为它使我们的代码更具可移植性。例如，在 Windows 上，如果不使用第三方库，你不能静态链接到核心 OpenGL 函数：

```java
  LGL3 = std::unique_ptr<sLGLAPI>( new sLGLAPI() );
  LGL::GetAPI( LGL3.get() );
```

这是我们在第四章，*组织虚拟文件系统*中处理虚拟文件系统时已经使用的回调。在这个例子中我们不需要任何路径，所以让我们使用一个空字符串：

```java
  OnStart( "" );
```

事件循环是显式完成的，并包含对`OnDrawFrame()`函数的调用：

```java
  while( g_Window && g_Window->HandleInput() )
  {
    OnDrawFrame();
    g_Window->Swap();
  }
  g_Window = nullptr;
  return 0;
}
```

这些包装类（`clSDL`和`clSDLWindow`）分别声明在`SDLLibrary.h`和`SDLWindow.h`文件中。`clSDL`类是基于 SDL 的 RAII 包装器，在构造函数和析构函数中进行库的初始化和反初始化：

```java
clSDL()
{
  SDL_Init( SDL_INIT_VIDEO );
}
virtual ~clSDL()
{
  SDL_Quit();
}
```

`clSDLWindow`类表示一个带有 OpenGL 上下文和系统消息泵的窗口抽象：

```java
class clSDLWindow: public iIntrusiveCounr
{
private:
  SDL_Window* m_Window;
  SDL_GLContext m_Context;
  float m_Width;
  float m_Height;
  std::atomic<bool> m_Pendingit;
public:
  clSDLWindow( const std::string& Title, int Width, int Height );
  virtual ~clSDLWindow();
  void RequestExit()
  {
    m_PendingExit = true;
  }
  void Swap();
```

这个成员函数执行消息循环的一次迭代：

```java
  bool HandleInput()
  {
    SDL_Event Event;
    while ( SDL_PollEvent(&Event) && !m_PendingExit )
    {
      if ( (Event.type == SDL_QUIT) || !this->HandleEvent( Event ) )
      m_PendingExit = true;
    }
    return !m_PendingExit;
  }
```

将整数坐标转换为浮点数标准化坐标 0..1，以便更容易使用不同分辨率的屏幕：

```java
  vec2 GetNormalizedPoint( int x, int y ) const
  {
    return vec2(
      static_cast<float>(x) / m_Width,
      static_cast<float>(y) / m_Height
    );
  }
```

以下方法对于构建当前窗口的投影矩阵很有用：

```java
  float GetAspect() const
  {
    return m_Width / m_Height;
  }
```

一个公共静态辅助方法，用于创建`clSDLWindow`的实例：

```java
public:
  static clPtr<clSDLWindow> CreateSDLWindow(
    const std::string& Title, int Width, int Height )
  {
    return make_intrusive<clSDLWindow>( Title, Width, Height );
  }
```

`HandleEvent()`成员函数负责将 SDL2 事件分派给我们的回调函数：

```java
private:
  bool HandleEvent( const SDL_Event& Event );};
```

`HandleEvent()`的实现如下：

```java
  bool clSDLWindow::HandleEvent( const SDL_Event& Event )
  {
    switch ( Event.type )
    {
      case SDL_WINDOWEVENT:
        if ( Event.window.event == SDL_WINDOWEVENT_SIZE_CHANGED)
        {
          m_Width  = static_cast<float>( Event.window.data1 );
          m_Height = static_cast<float>( Event.window.data2 );
        }
        return true;
        case SDL_KEYDOWN:
        case SDL_KEYUP:         OnKey( Event.key.keysym.sym, Event.type == SDL_KEYDOWN );         break;
        case SDL_MOUSEBUTTONDOWN:
        case SDL_MOUSEBUTTONUP:         break;
        case SDL_MOUSEMOTION          break;
        case SDL_MOUSEWHEEL          break;
    }
    return true;
  }
```

并非所有的案例标签都已实现，也并非所有的 SDL2 事件都被使用。我们将在后续章节根据需要使用这个路由。

在我们的示例中，我们使用一些有用的 OpenGL 包装器渲染一个旋转的盒子，可以隐藏移动版和桌面版 OpenGL 之间的差异。以下是`OnStart()`的代码，它将 OpenGL 的版本打印到系统日志中，并初始化顶点缓冲对象和着色器程序：

```java
  clPtr<clVertexAttribs> g_Box;
  clPtr<clGLVertexArray> g_BoxVA;
  clPtr<clGLSLShaderProgram> g_ShaderProgram;
  void OnStart( const std::string& RootPath )
  {
    LOGI( "Hello Android NDK!" );
    const char* GLVersion  = (const char*)LGL3->glGetString( GL_VERSION  );
    const char* GLVendor   = (const char*)LGL3->glGetString( GL_VENDOR   );
    const char* GLRenderer = (const char*)LGL3->glGetString( GL_RENDERER );
    LOGI( "GLVersion : %s\n", GLVersion );
    LOGI( "GLVendor  : %s\n", GLVendor  );
    LOGI( "GLRenderer: %s\n", GLRenderer );
```

首先，我们创建一个与 API 无关的盒子网格表示：

```java
    g_Box = clGeomServ::CreateAxisAlignedBox( LVector3(-1), LVector3(+1) );
```

然后，我们将其输入到 OpenGL 中，使用顶点缓冲对象创建一个顶点数组：

```java
    g_BoxVA = make_intrusive<clGLVertexArray>();
    g_BoxVA->SetVertexAttribs( g_Box );
```

着色器程序由包含顶点和片段着色器源代码的两个字符串变量构建而成：

```java
    g_ShaderProgram = make_intrusive<clGLSLShaderProgram>( g_vShaderStr, g_fShaderStr );
    LGL3->glClearColor( 0.1f, 0.0f, 0.0f, 1.0f );
    LGL3->glEnable( GL_DEPTH_TEST );
  }
```

下面是使用 GLSL 3.3 核心配置编写的着色器。使用模型-视图-投影矩阵变换顶点：

```java
  static const char g_vShaderStr[] = R"(
    uniform mat4 in_ModelViewProjectionMatrix;
    in vec4 in_Vertex;
    in vec2 in_TexCoord;
    out vec2 Coords;
    void main()
    {
      Coords = in_TexCoord.xy;
      gl_Position = in_ModelViewProjectionMatrix * in_Vertex;
    }
  )";
```

使用纹理坐标作为 RG 颜色分量来绘制盒子：

```java
  static const char g_fShaderStr[] = R"(
    in vec2 Coords;
    out vec4 out_FragColor;
    void main()
    {
      out_FragColor = vec4( Coords, 1.0, 1.0 );
    }
  )";
```

你可能已经注意到着色器的源代码不包含`#version`和`precision`行。这是因为`clGLSLShaderProgram`类对源代码进行了一些操作，以抽象不同版本 GLSL 之间的差异。我们将在后续段落熟悉这个类。在此之前，让我们看看`OnDrawFrame()`：

```java
  void OnDrawFrame()
  {
    static float Angle = 0;
    Angle += 0.02f;
    LGL3->glClear( GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT );
    mat4 Proj = Math::Perspective(
      45.0f, g_Window->GetAspect(), 0.4f, 2000.0f );
```

绕`(1, 1, 1)`轴旋转立方体：

```java
    LMatrix4 MV = LMatrix4::GetRotateMatrixAxis( Angle,
      vec3( 1, 1, 1 ) ) *
      mat4::GetTranslateMatrix( vec3( 0, 0, -5 ) );
    g_ShaderProgram->Bind();
    g_ShaderProgram->SetUniformNameMat4Array(
      "in_ModelViewProjectionMatrix", 1, MV * Proj );
    g_BoxVA->Draw( false );
  }
```

# OpenGL API 绑定

如你所见，前面提到的代码中所有的 OpenGL 调用都是通过`LGL3`前缀完成的。这是一个在`LGLAPI.h`中声明的名为`sLGLAPI`的结构，包含指向实际 OpenGL API 函数的指针：

```java
  struct sLGLAPI
  {
    sLGLAPI()
    {
      memset( this, 0, sizeof( *this ) );
    };
    PFNGLACTIVETEXTUREPROC        glActiveTexture;
    PFNGLATTACHSHADERPROC         glAttachShader;
    PFNGLBINDATTRIBLOCATIONPROC   glBindAttribLocation;
    PFNGLBINDBUFFERPROC           glBindBuffer;
    PFNGLBINDBUFFERBASEPROC       glBindBufferBase;
    PFNGLBINDFRAGDATALOCATIONPROC glBindFragDataLocation;
    ...
  }
```

`sLGLAPI`结构的字段在`LGL::GetAPI()`函数中设置。这个函数有两个不同的实现，一个是 Windows 的`LGL_Windows.h`，另一个是`LGL_Android.h`中为其他所有平台。区别在于 Windows 上的动态链接，如下代码所示：

```java
  void LGL::GetAPI( sLGLAPI* API )
  {
    API->glBlendFunc = ( PFNGLBLENDFUNCPROC )GetGLProc( API, "glBlendFunc" );
    API->glBufferData = ( PFNGLBUFFERDATAPROC )GetGLProc( API, "glBufferData" );
    API->glBufferSubData = ( PFNGLBUFFERSUBDATAPROC )GetGLProc( API, "glBufferSubData");
    ...
  }
```

所有其他平台都使用静态链接系统提供的 OpenGL 库：

```java
  void LGL::GetAPI( sLGLAPI* API )
  {
    API->glActiveTexture = &glActiveTexture;
    API->glAttachShader = &glAttachShader;
    API->glBindAttribLocation = &glBindAttribLocation;
    API->glBindBuffer = &glBindBuffer;
    ...
  }
```

当然，如果你使用特定供应商的 OpenGL 扩展，可以使用动态链接在任何平台上通过`glGetProcAddresss()`访问它们，这时`sLGLAPI`结构就显得非常方便：

这是我们在 OpenGL 之上的抽象层次最低的部分。有人可能会说这个所谓的层次什么也不做。这是不正确的。看看在 Android 上是如何获取`glClearDepth()`的指针的。出于某种原因，不是直接调用函数，而是一个存根：

```java
  API->glClearDepth = &Emulate_glClearDepth;
```

存根定义如下：

```java
  LGL_CALL void Emulate_glClearDepth( double Depth )
  {
    glClearDepthf( static_cast<float>( Depth ) );
  }
```

原因是 OpenGL ES 中没有`glClearDepth()`函数，它接受一个`float`参数，但 OpenGL 3 有这个函数。这种方式可以将移动设备和桌面 OpenGL 之间的 API 差异隐藏在薄薄的抽象层后面。使用这种技术，你可以透明地替换一个 OpenGL 枚举为另一个。可以透明地实现跟踪机制，将 OpenGL 函数参数的值打印到日志中。在将现有应用程序移植到没有图形调试器可用的平台时，这种技术至关重要（是的，我们在说你，黑莓）。我们将这个作为你的练习。

现在让我们深入了解高级抽象是如何实现的。

# 跨平台的 OpenGL 抽象概念

几何对象可以通过它们的表面来表示。在本章中，我们只讨论多边形图形，因此最重要的数据结构是*三角网格*。

就像数字音频一样，我们方便的 API 无关的数据结构在可以渲染之前需要转换成图形 API 的本地格式。让我们从 3D 空间中三角化几何的表示开始。

一个单一三角形可以通过三个顶点来指定。每个顶点至少存储其在 3D 空间中的位置，如下所示：

![跨平台的 OpenGL 抽象概念](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-ndk/img/image00223.jpeg)

在实现可移植渲染器的第一步，我们需要将几何存储分离出来，最简单的情况下，这只是带有属性和顶点的集合以及通过这些顶点构造图形原语的迭代顺序，与任何 API 特定的函数和数据类型分离。这种数据结构在`clVertexAttribs`类中实现：

```java
class clVertexAttribs: public iIntrusiveCounter
{
public:
  clVertexAttribs();
  explicit clVertexAttribs( size_t Vertices );
  void SetActiveVertexCount( size_t Count )
  {FActiveVertexCount = Count; }
  size_t GetActiveVertexCount() const
  { return FActiveVertexCount; }
```

这个方法返回一个包含指向实际顶点属性、位置、纹理坐标、法线和颜色的容器，可以输入到 OpenGL 顶点缓冲对象中：

```java
  const std::vector<const void*>& EnumerateVertexStreams() const;
  {
    FStreams[ L_VS_VERTEX   ] = &FVertices[0];
    FStreams[ L_VS_TEXCOORD ] = &FTexCoords[0];
    FStreams[ L_VS_NORMAL   ] = &FNormals[0];
    FStreams[ L_VS_COLORS   ] = &FColors[0];
    return FStreams;
  }
```

我们声明了一组辅助方法来生成几何数据：

```java
  void Restart( size_t ReserveVertices );
  void EmitVertexV( const vec3& Vec );
  void SetTexCoordV( const vec2& V );
  void SetNormalV( const vec3& Vec );
  void SetColorV( const vec4& Vec );
```

我们声明一组公共字段来存储我们的数据。顶点 3D 位置*x*，*y*，*z*声明如下：

```java
public:
  std::vector<vec3> FVertices;
```

纹理坐标`u`和`v`。这是我们顶点格式的局限性，因为有时纹理坐标可能包含超过两个通道。然而，对于我们的应用程序来说，这种限制是合适且可行的：

```java
  std::vector<vec2> FTexCoords;
```

顶点法线通常在对象空间中：

```java
  std::vector<vec3> FNormals;
```

顶点的 RGBA 颜色。如果你编写了正确的着色器，这个容器可以用于任何你想要的定制数据：

```java
  std::vector<vec4> FColors;
};
```

实现很简单；但是，我们建议在进一步操作之前查看`Geometry.cpp`和`Geometry.h`文件。

为了将有用的数据填充到`clVertexAttribs`的实例中，`clGeomServ`类中声明了一组静态方法：

```java
classlGeomServ
{
public:
  static clPtr<clVertexAttribs> CreateTriangle2D( float vX, float vY, float dX, float dY, float Z );
  static clPtr<clVertexAttribs> CreateRect2D( float X1, float Y1, float X2, float Y2, float Z,
    bool FlipTexCoordsVertical, int Subdivide );
  static void AddAxisAlignedBox( const clPtr<clVertexAttribs>& VA, const LVector3& Min, const LVector3& Max );
  static clPtr<clVertexAttribs> CreateAxisAlignedBox( const LVector3& Min, const LVector3& Max );
  static void AddPlane( const clPtr<clVertexAttribs>& VA, float SizeX, float SizeY, int SegmentsX, int SegmentsY, float Z );
  static clPtr<clVertexAttribs> CreatePlane( float SizeX, float SizeY, int SegmentsX, int SegmentsY, float Z );
};
```

所有`Create*()`方法创建一个新的几何图元并返回包含它的`clVertexAttribs`实例。以`Add`开头的方法将图元添加到现有的`clVertexAttribs`类实例中，假设它有足够的容量来存储新的图元。实现非常简单，可以在`Geometry.cpp`中找到。更复杂的几何生成例程将在后续章节中添加。

# 将几何数据提供给 OpenGL

要渲染`clVertexAttribs`的内容，我们需要将其数据转换为一组特定于 API 的缓冲区和 API 函数调用。这是通过在`clGLVertexArray`类中创建**顶点数组对象**（**VOA**）和**顶点缓冲区对象**（**VBO**）OpenGL 对象，并从`clVertexAttribs`获取内容来完成的：

```java
class clGLVertexArray: public iInusiveCounter
{
public:
  clGLVertexArray();
  virtual ~clGLVertexArray();
```

`Draw()`方法执行实际渲染，它是我们抽象层中可能进行渲染的最低级别：

```java
  void Draw( bool Wireframe ) const;
  void SetVertexAttribs(
    const clPtr<clVertexAttrs>& Attribs );
private:
  void Bind() const;
private:
  Luint FVBOID;
  Luint FVAOID;
```

这些指针实际上是顶点数据在顶点缓冲区内的偏移量：

```java
  std::vector<const void*> FAttribVBOOffset;
```

这些指针指向`clVertexAttribs`中的实际数据：

```java
  std::vector<const void*> FEnumeratedStreams;
  clPtr<clVertexAttribs> FAttribs;
};
```

这个类的实现包括一些簿记工作以及调用 OpenGL 函数。构造函数和析构函数分别初始化和销毁 VOA 和 VBO 的句柄：

```java
clGLVertexArray::clGLVertexArray()
: FVBOID( 0 ),
  FVAOID( 0 ),
  FAttribVBOOffset( L_VS_TOTAL_ATTRIBS ),
  FEnumeratedStreams( L_VS_TOTAL_ATTRIBS ),
  FAttribs( nullptr )
{
```

在 Windows 上，我们使用 OpenGL 4，其中使用顶点数组对象是强制性的：

```java
  #if dined( _WIN32 )
    LGL3->glGenVertexArrays( 1, &FVAOID );
  #endif
}
```

销毁操作以特定于平台的方式进行：

```java
clGLVertexArray::~clGLVertexArray()
{
  LGL3->glDeleteBuffers( 1, &FVBOID );
  #if defined( _WIN32 )
    LGL3->glDeleteVertexArrays( 1, &FVAOID );
  #endif
}
```

私有方法`Bind()`将此顶点数组对象设置为 OpenGL 渲染管线的源顶点流：

```java
void clGLVertexArray::Bind() const
{
  LGL3->glBindBuffer( GL_ARRAY_BUFFER, FVBOID );
  LGL3->glVertexAttribPointer( L_VS_VERTEX, L_VS_VEC_COMPONENTS[ 0 ], GL_FLOAT, GL_FALSE, 0, FAttribVBOOffset[ 0 ] );
  LGL3->glEnableVertexAttribArray( L_VS_VERTEX );
```

绑定并启用顶点位置后，我们启用每个额外的非空属性：

```java
  for ( int i = 1; i < L_VS_TOTAL_ATTRIBS; i++ )
  {
    LGL3->glVertexAttribPointer( i,
      L_VS_VEC_COMPONENTS[ i ],
      GL_FLOAT, GL_FALSE, 0, FAttribVBOOffset[ i ] );
    FAttribVBOOffset[ i ] ?
      LGL3->glEnableVertexAttribArray( i ) :
      LGL3->glDisableVertexAttribArray( i );
  }
}
```

`Draw()`方法绑定 VOA 并调用`glDrawArrays()`来渲染几何图形：

```java
void clGLVertexArray::Draw( bool Wireframe ) const
{
  #if defined( _WIN32 )
    LGL3->glBindVertexArray( FVAOID );
  #else
    Bind();
  #endif
```

第一个参数是图元的类型。如果`Wireframe`参数为`true`，我们告诉 OpenGL 将数据视为一系列线，每个连续的点对一条线。如果参数为`false`，则每个连续的点三元组被用作三角形的三个顶点：

```java
  LGL3->glDrawArrays(
    Wireframe ? GL_LINE_LOOP : GL_TRIANGLES, 0,
    static_cast<GLsizei>( FAttribs->GetActiveVertexCount() ) );
}
```

`SetVertexAttribs()`成员函数将几何数据附加到`GLVertexArray`并重新创建所有必需的 OpenGL 对象：

```java
void clGLVertexArray::SetVertexAttribs(  const clPtr<clVertexAttribs>& Attribs )
{
  FAttribs = Attribs;
```

分配指针后，我们获取一个指向各个顶点属性流的指针数组：

```java
  FEnumeratedStreams = FAttribs->EnumerateVertexStreams();
  LGL3->glDeleteBuffers( 1, &FVBOID );
  size_t VertexCount = FAttribs->FVertices.size();
  size_t DataSize = 0;
```

检查每个流是否包含任何数据，并相应地更新顶点缓冲区的大小：

```java
  for ( int i = 0; i != L_VS_TOTAL_ATTRIBS; i++ )
  {
    FAttribVBOOffset[ i ] = ( void* )DataSize;
    DataSize += FEnumeratedStreams[i] ?
      sizeof( float ) * L_VS_VEC_COMPONENTS[ i ] * VertexCount : 0;
  }
```

之后，我们创建一个新的顶点缓冲区对象，该对象将包含几何数据：

```java
  LGL3->glGenBuffers( 1, &FVBOID );
  LGL3->glBindBuffer( GL_ARRAY_BUFFER, FVBOID );
```

这里最重要的事情是将数据从`clVertexAttribs`对象复制到 GPU 内存中。这是通过使用`nullptr`作为缓冲区指针调用`glBufferData()`来分配存储来完成的：

```java
  LGL3->glBufferData( GL_ARRAY_BUFFER, DataSize, nullptr, GL_STREAM_DRAW );
```

你可以在[`www.khronos.org/opengles/sdk/docs/man3/html/glBufferData.xhtml`](https://www.khronos.org/opengles/sdk/docs/man3/html/glBufferData.xhtml)找到更多关于`glBufferData()`的信息。

这里是对每个非空属性数组的后续`glBufferSubData()`调用，这些属性数组包括顶点位置、纹理坐标、法线和颜色：

```java
  for ( int i = 0; i != L_VS_TOTAL_ATTRIBS; i++ )
  {
    if ( FEnumeratedStreams[i] )
    {
      LGL3->glBufferSubData( GL_ARRAY_BUFFER, ( GLintptr )FAttribVBOOffset[ i ], FAttribs->GetActiveVertexCount() * sizeof( float ) * L_VS_VEC_COMPONENTS[ i ], FEnumeratedStreams[ i ] );
    }
  }
```

绑定对于 VAO 和非 VAO 版本来说有些特定：

```java
  #if defined( _WIN32 )
    LGL3->glBindVertexArray( FVAOID );
    Bind();
    LGL3->glBindVertexArray( 0 );
  #endif
}
```

VAO 版本可以在 OpenGL ES 3 上使用。然而，未经修改的代码也可以在 OpenGL ES 2 上运行。

# 着色器程序

桌面和移动 OpenGL 版本都将着色器程序作为其渲染管道的一部分。仅提供几何图形是不够的。然而，为了创建可移植的渲染子系统，我们应该处理 GLSL 3.00 ES 和 GLSL 3.30 Core 之间的几个重要区别。

让我们从`uniform`值的声明开始：

```java
struct sUniform
{
public:
  explicit sUniform( const std::string& e)
  : FName( e )
  , FLocation( -1 )
  {};
  sUniform( int Location, const std::string& e)  : FName( e )
  , FLocation( Location )
  {};
  std::string FName;
  Lint FLocation;
};
```

这个类存储了在链接着色器程序中统一变量的名称和位置。着色器程序类的结构如下所示：

```java
class clGLSLShaderProgram: public iIntrusiveCounr
{
public:
```

构造函数以顶点和片段着色器的源代码作为参数：

```java
  clGLSLShaderProgram( const std::string& VShader, const std::string& FShader );
  virtual ~clGLSLShaderProgram();
```

`Bind()`方法在使用前绑定着色器程序：

```java
  void Bind();
```

一组处理统一变量的方法：

```java
  Lint CreateUniform( const std::string& Name );
  void SetUniformNameFloat( const std::string& Name, const float Float );
  void SetUniformNameFloatArray( const std::string& Name, int Count, const float& Float );
  void SetUniformNameVec3Array( const std::string& Name, int Count, const LVector3& Vector );
  void SetUniformNameVec4Array( const std::string& Name, int Count, const LVector4& Vector );
  void SetUniformNameMat4Array( const std::string& Name, int Count, const LMatrix4& Matr );
private:
```

使用附加的着色器链接程序：

```java
  bool RelinkShaderProgram();
```

我们需要绑定属性和片段数据的默认位置。这将在以下方法中完成：

```java
  void BindDefaultLocations( Luint ProgramID )
  {
    LGL3->glBindAttribLocation( ProgramID, L_VS_VERTEX, "in_Vertex" );
    LGL3->glBindAttribLocation( ProgramID, L_VS_TEXCOORD, "in_TexCoord" );
    LGL3->glBindAttribLocation( ProgramID, L_VS_NORMAL, "in_Normal" );
    LGL3->glBindAttribLocation( ProgramID, L_VS_COLORS, "in_Color" );
    LGL3->glBindFragDataLocation( ProgramID, 0, "out_FragColor" );
  }
```

它将着色器变量`in_Vertex`、`in_Normal`、`in_TexCoord`和`in_Color`绑定到适当的顶点流。你可以在你的 GLSL 代码中声明并使用这些`in`变量。`out_FragColor`输出变量与片段着色器的单一输出相关联。

编译并将着色器附加到此着色器程序：

```java
  Luint AttachShaderID( Luint Target, const std::string& ShaderCode, Luint OldShaderID );
```

检查编译和链接过程中发生的任何错误并记录：

```java
  bool CheckStatus( Luint ObjectID, Lenum Target, const std::string& Message ) const;
```

此方法从链接的着色器程序检索所有统一变量，并将它们作为`sUniform`结构存储在`FUniforms`容器中：

```java
  void RebindAllUniforms();
private:
  std::string FVertexShader;
  std::string FFragmentShader;
  Luint FVertexShaderID;
  Luint FFragmentShaderID;
```

此着色程序中所有活动的统一变量集合存储如下：

```java
  std::vector<sUniform> FUniforms;
```

OpenGL 着色器程序和着色器标识符存储在以下字段中：

```java
  Luint FProgramID;
  std::vector<Luint> FShaderID;
};
clGLSLShaderProgram::clGLSLShaderProgram(
  const std::string& VShader, const std::string& FShader )
: FVertexShader( VShader )
, FFragmentShader( FShader )
, FUniforms()
, FProgramID( 0 )
, FVertexShaderID( 0 )
, FFragmentShaderID( 0 )
{
  RelinkShaderProgram();
}
```

我们可以如下销毁所有创建的 OpenGL 对象：

```java
clGLSLShaderProgram::~clGLSLShaderProgram()
{
  LGL3->glDeleteProgram( FProgramID );
  LGL3->glDeleteShader( FVertexShaderID );
  LGL3->glDeleteShader( FFragmentShaderID );
}
```

让我们看看如何创建着色器对象并将其附加到着色器程序：

```java
Luint clGLSLShaderProgram::AttachShaderID( Luint Target,
  const std::string& ShaderCode, Luint OldShaderID )
{
```

由于我们使用 OpenGL ES 3 和 OpenGL 4，着色器的版本应相应指定：

```java
  #if defined( USE_OPENGL_4 )
    std::string ShaderStr = "#version 330 core\n";
  #else
    std::string ShaderStr = "#version 300 es\n";
    ShaderStr += "precision highp float;\n";
    ShaderStr += "#define USE_OPENGL_ES_3\n";
  #endif
    ShaderStr += ShaderCode;
```

生成的着色器提交给 OpenGL API 函数：

```java
    Luint Shader = LGL3->glCreateShader( Target );
    const char* Code = ShaderStr.c_str();
    LGL3->glShaderSource( Shader, 1, &Code, nullptr );
    LGL3->glCompileShader( Shader );
```

检查编译状态，并记录编译代码时检测到的任何错误。如果新着色器编译失败，这段代码将回退到之前编译的着色器。你可以使用前几章中的文件系统类来实现动态着色器程序的重新加载：

```java
    if ( !CheckStatus( Shader, GL_COMPILE_STATUS, "Shader wasn''t compiled:" ) )
    {
      LGL3->glDeleteShader( Shader );
      return OldShaderID;
    }
    if ( OldShaderID )
    {
      LGL3->glDeleteShader( OldShaderID );
    }
    return Shader;
  }
```

错误检查和记录实现起来并不复杂，是必须的：

```java
  bool clGLSLShaderProgram::CheckStatus( Luint ObjectID, Lenum Target, const std::string& Message ) const
  {
    Lint   SuccessFlag = 0;
    Lsizei Length      = 0;
    Lsizei MaxLength   = 0;
    if ( LGL3->glIsProgram( ObjectID ) )
    {
      LGL3->glGetProgramiv( ObjectID, Target, &SuccessFlag );
      LGL3->glGetProgramiv( ObjectID, GL_INFO_LOG_LENGTH, &MaxLength );
```

着色器程序错误消息的缓冲区在栈上动态分配：

```java
      char* Log = ( char* )alloca( MaxLength );
      LGL3->glGetProgramInfoLog( ObjectID, MaxLength, &Length, Log );
      if ( *Log ) { LOGI( "Program info:\n%s\n", Log ); }
    }
    else if ( LGL3->glIsShader( ObjectID ) )
    {
      LGL3->glGetShaderiv( ObjectID, Target, &SuccessFlag );
      LGL3->glGetShaderiv( ObjectID, GL_INFO_LOG_LENGTH, &MaxLength );
```

以类似的方式处理着色器对象：

```java
      char* Log = ( char* )alloca( MaxLength );
      LGL3->glGetShaderInfoLog( ObjectID, MaxLength, &Length, Log );
      if ( *Log ) { LOGI( "Shader info:\n%s\n", Log ); }
    }
    return SuccessFlag != 0;
  }
```

当顶点和片段着色器对象都成功编译后，将重新链接着色器程序：

```java
  bool clGLSLShaderProgram::RelinkShaderProgram()
  {
    Luint ProgramID = LGL3->glCreateProgram();
    FVertexShaderID = AttachSaderID( GL_VERTEX_SHADER, FVertexShader, FVertexShaderID );
    if ( FVertexShaderID )
    { LGL3->glAttachShader( ProgramID, FVertexShaderID ); }
    FFragmentShaderID = AttachShaderID( GL_FRAGMENT_SHADER, FFragmentShader, FFragmentShaderID );
    if ( FFragmentShaderID )
    { LGL3->glAttachShader( ProgramID, FFragmentShaderID ); }
```

绑定所有默认顶点属性的定位：

```java
    BindDefaultLocations( ProgramID );
    LGL3->glLinkProgram( ProgramID );
    if ( !CheckStatus( ProgramID, GL_LINK_STATUS, "Program wasn''t linked" ) )
    {
      LOGI( "INTERNAL ERROR: Error while shader relinking" );
      return false;
    }
```

在这一点上，我们知道着色器程序已成功链接，我们可以将其作为渲染管道的一部分使用。用以下代码替换旧程序：

```java
    LGL3->glDeleteProgram( FProgramID );
    FProgramID = ProgramID;
```

从链接的程序中检索活动统一变量的列表并存储它们：

```java
    RebindAllUniforms();
```

将纹理采样器绑定到它们的默认位置。你可以在任何时候添加更多的纹理单元：

```java
    LGL3->glUniform1i( LGL3->glGetUniformLocation(FProgramID, "Texture0"), 0);
    LGL3->glUniform1i( LGL3->glGetUniformLocation(FProgramID, "Texture1"), 1);
    LGL3->glUniform1i( LGL3->glGetUniformLocation(FProgramID, "Texture2"), 2);
    LGL3->glUniform1i( LGL3->glGetUniformLocation(FProgramID, "Texture3"), 3);
    return true;
  }
```

在`RebindAllUniforms()`方法中完成统一变量的排队：

```java
  void clGLSLShaderProgram::RebindAllUniforms()
  {
    Bind();
    FUniforms.clear();
    Lint ActiveUniforms;
    char Buff[256];
    LGL3->glGetProgramiv( FProgramID,
      GL_ACTIVE_UNIFORMS, &ActiveUniforms );
    for ( int i = 0; i != ActiveUniforms; ++i )
    {
      Lsizei Length;
      Lint Size;
      Lenum Type;
      LGL3->glGetActiveUniform( FProgramID, i,
        sizeof( Buff ), &Length, &Size, &Type, Buff );
      std::string Name( Buff, Length );
```

`sUniform`对象被构造并推入容器以供将来访问。作为改进，可以排序向量或用`std::map`替换以允许更快地访问：

```java
      sUniform Uniform( Name );
      Uniform.FLocation = LGL3->glGetUniformLocation( FProgramID, Name.c_str() );
      FUniforms.push_back( Uniform );
    }
  }
```

`SetUniform*()`方法组在 GLSL 着色器程序中设置一个命名统一变量的值。这些方法通过调用`CreateUniform()`获取统一变量的句柄，然后使用`glUniform*()`系列 OpenGL 函数之一来设置新值。字符串名称可以用于着色器的快速原型设计。如果你想要追求性能，可以事先使用`CreateUniform()`成员函数获取统一变量的位置，并使用该值与对应的`SetUniform*()`调用：

```java
  void clGLSLShaderProgram::SetUniformNameFloat( const std::string& Name, const float Float )
  {
    Lint Loc = CreateUniform( Name );
    LGL3->glUniform1f( Loc, Float );
  }
  void clGLSLShaderProgram::SetUniformNamoatArray( const std::string& Name, int Count, const float& Float )
  {
    Lint Loc = CreateUniform( Name );
    LGL3->glUniform1fv( Loc, Count, &Float );
  }
```

向量被转换为指针。注意以下技巧，`ToFloatPtr()`方法返回一个指向向量`x`分量的指针。当这个向量被包装到一个向量数组中时，我们也拥有指向数组开头的指针。因此，`Count`参数非常有意义，我们可以将向量数组传递给这个方法：

```java
  void void clGLSLShaderProgram::SetUniformNameec3Array(     const std::string& Name, int Count, const LVector3& Vector )
  {
    Lint Loc = CreateUniform( Name );
    LGL3->glUniform3fv( Loc, Count, Vector.ToFloatPtr() );
  }
  void clGLSLShaderProgram::SetUniformNameVec4Array( const std::string& Name, int Count, const LVector4& Vector )
  {
    Lint Loc = CreateUniform( Name );
    LGL3->glUniform4fv( Loc, Count, Vector.ToFloatPtr() );
  }
```

矩阵的方法与前面的方法不同，只是参数类型不同：

```java
  void clGLSLShaderProgram::SetUniformNameMat4Array( const std::string& Name, int Count, const LMatrix4& Matrix )
  {
    Lint Loc = CreateUniform( Name );
    LGL3->glUniformMatrix4fv( Loc, Count, false,
    Matrix.ToFloatPtr() );
  }
```

在`SetUniform*()`中使用的`CreateUniform()`方法在`FUniforms`容器中进行搜索，并返回统一变量的 OpenGL 标识符：

```java
  Lint clGLSLShaderProgram::CreateUniform( const std::string& Name )
  {
    for ( size_t i = 0; i != FUniforms.size(); ++i )
    if ( FUniforms[i].FName == Name )
    return FUniforms[i].FLocation;
    return -1;
  }
```

这个方法用于任何名称都是安全的，因为对于在着色器程序中找不到的统一变量返回的`-1`值被 OpenGL 接受并忽略。

`Bind()`方法将着色器程序绑定到当前的 OpenGL 渲染上下文：

```java
  void clGLSLShaderProgram::Bind()
  {
    LGL3->glUseProgram( FProgramID );
  }
```

在更复杂的应用程序中，缓存当前绑定的着色器程序的值是有意义的，并且只有当值发生变化时才调用底层 API。

# 纹理

我们需要包装的最后一个组件是纹理。纹理由`clGLTexture`类的实例表示：

```java
  class clGLTexture: public iIntrusivounter
  {
  public:
    clGLTexture();
    virtual ~clGLTexture();
```

将纹理绑定到一个指定的 OpenGL 纹理单元：

```java
    void Bind( int TextureUnit ) const;
```

从 API 无关的位图中加载纹理像素：

```java
    void LoadFromBitmap( const clPtr<clBitmap>& Bitmap );
```

设置纹理坐标的钳制模式：

```java
    void SetClamping( Lenum Clamping );

```

处理纹理的数据格式和尺寸：

```java
  private:
    void SetFormat( Lenum Target, Lenum InternalFormat, Lenum Format, int Width, int Height );
    Luint FTexID;
    Lenum FInternalFormat;
    Lenum FFormat;
  };
```

该实现相当紧凑。下面就是代码：

```java
  clGLTexturelGLTexture()
  : FTexID( 0 )
  , FIntelFormat( 0 )
  , FFormat( 0 )
  {
  }
  clGLTexture::~clGLTexture()
  {
    if ( FTexID ) { LGL3->glDeleteTextures( 1, &FTexID ); }
  }
  void clGLTexture::Bind( int TextureUnit ) const
  {
    LGL3->glActiveTexture( GL_TEXTURE0 + TextureUnit );
    LGL3->glBindTexture( GL_TEXTURE_2D, FTexID );
  }
```

我们可以设置纹理的格式而不上传任何像素。如果你想要将纹理附加到帧缓冲对象，这非常有用。我们将在第八章，*编写渲染引擎*中使用这个功能来实现渲染到纹理的功能：

```java
  void clGLTexture::SetFormat( Lenum Target, Lenum InternalFormat, Lenum Format, int Width, int Height )
  {
    if ( FTexID )
    {
      LGL3->glDeleteTextures( 1, &FTexID );
    }
    LGL3->glGenTextures( 1, &FTexID );
    LGL3->glBindTexture( GL_TEXTURE_2D, FTexID );
    LGL3->glTexParameterf( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR );
    LGL3->glTexParameterf( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR );
    LGL3->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE );
    LGL3->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE );
    LGL3->glTexImage2D( GL_TEXTURE_2D, 0, InternalFormat, Width, Height, 0, Format, GL_UNSIGNED_BYTE, nullptr );
    LGL3->glBindTexture( GL_TEXTURE_2D, 0 );
  }
  void clGLTexture::SetClamping( Lenum Clamping )
  {
    Bind( 0 );
```

按如下方式更新`S`和`T`的钳制模式：

```java
    LGL3->glTexParameteri( GL_TEXTURE_2D,
      GL_TEXTURE_WRAP_S, Clamping );
    LGL3->glTexParameteri( GL_TEXTURE_2D,
      GL_TEXTURE_WRAP_T, Clamping );
  }
  void clGLTexture::LoadFromBitmap( const clPtr<clBitmap>& Bitmap )
  {
    if ( !Bitmap ) { return; }
    if ( !FTexID )
    {
      LGL3->glGenTextures( 1, &FTexID );
    }
```

根据位图参数选择合适的 OpenGL 纹理格式：

```java
    ChooseInternalFormat( Bitmap->FBitmapParams, &FFormat, &FInternalFormat );
    Bind( 0 );
```

将默认过滤模式设置为`GL_LINEAR`以避免构建 mipmap 链：

```java
    LGL3->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR );
    LGL3->glTexParameteri( GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR );
    int Width = Bitmap->GetWidth();
    int Height = Bitmap->GetHeight();
```

某些 OpenGL ES 实现不允许零尺寸的纹理（是的，我们说的是你，Vivante）：

```java
    if ( !Width || !Height ) { return; }
```

将原始位图数据加载到 OpenGL 中：

```java
    LGL3->glTexImage2D( GL_TEXTURE_2D, 0, FInternalFormat, Width, Height, 0, FFormat, GL_UNSIGNED_BYTE, Bitmap->FBitmapData );
  }
```

到目前为止，我们已经拥有足够的工具来使用 OpenGL 构建可移植的移动应用程序。本章的示例应用程序`1_GLES`在 Windows 和 Android 上渲染了一个彩色的旋转立方体：

![纹理](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-ndk/img/image00224.jpeg)

Windows 版本可以通过执行`>make all -j16 -B`来编译。可以通过调用以下命令来构建 Android 的`.apk`包： 

```java
>ndk-build -j16 -B
>ant debug

```

# 总结

我们学习了如何将原始的 OpenGL 调用封装在一个轻薄的抽象层中，以隐藏 OpenGL ES 3 和 OpenGL 4 之间的许多差异。现在，让我们进入下一章，学习如何使用 OpenGL 和本章展示的类来实现基本的图形用户界面渲染。


# 第七章：跨平台 UI 与输入系统

在前一章中，我们介绍了用于平台独立渲染的类和接口。在这里，我们在通往 3D OpenGL 渲染器的路上稍作绕行，使用 SDL 库渲染用户界面的元素。为了渲染我们的 UI，我们需要线条、矩形、纹理矩形和文本字符串。

我们将从描述`iCanvas`接口开始本章，该接口旨在渲染几何图元。`iCanvas`最复杂的部分是 Unicode 文本渲染，它使用 FreeType 库实现。字体字符缓存对于复杂的 UI 来说也是一个非常重要的主题，这里将讨论这个问题。本章的第二部分描述了一个多页图形用户界面，适用于构建多平台应用程序的界面基石。本章以一个 SDL 应用程序结束，该程序展示了我们 UI 系统在实际中的能力。

# 渲染

目前，我们仅使用 SDL 库，不使用任何 OpenGL，因此我们将声明`iCanvas`接口，以允许立即渲染几何图元，但不一定快速，并避免创建前一章描述的`GLVertexArray`实例。稍后，我们可能会提供不同的`iCanvas`实现，以切换到另一个渲染器：

```java
class iCanvas: public iIntrusiveCounter
{
public:
```

前两种方法设置当前的渲染颜色，指定为 RGB 整数的三元组或包含额外 alpha 透明度的 4 维向量：

```java
  virtual void SetColor( int R, int G, int B ) = 0;
  virtual void SetColor( const ivec4& C ) = 0;
```

`Clear()`方法清除屏幕渲染表面：

```java
  virtual void Clear() = 0;
```

`Rect()`和`Line()`方法分别按照其名称所示渲染矩形和线条：

```java
  virtual void Rect( int X, int Y,
    int W, int H, bool Filled ) = 0;
  virtual void Line( int X1, int Y1, int X2, int Y2 ) = 0;
```

与纹理相关的一组方法管理纹理的创建和更新。`CreateTexture()`方法返回创建的纹理的整数句柄。纹理句柄`Idx`作为参数传递给`UpdateTexture()`成员函数，以将位图数据上传到纹理中。`Pixels`参数持有包含像素数据的位图对象：

```java
  virtual int CreateTexture( const clPtr<clBitmap>& Pixels ) = 0;
  virtual int UpdateTexture( int Idx, const clPtr<clBitmap>& Pixels ) = 0;
  virtual void DeleteTexture( int Idx ) = 0;
```

`TextureRect()`方法使用指定的纹理渲染一个四边形：

```java
  virtual void TextureRect( int X, int Y, int W, int H, int SX, int SY, int SW, int SH, int Idx ) = 0;
```

文本渲染通过单个`TextStr()`调用完成，该调用指定了文本应适应（或夹紧）的矩形区域、要渲染的字符串、字体大小的点数、文本颜色以及来自`TextRenderer`类的字体 ID，我们将在后面进行描述：

```java
  virtual void TextStr( int X1, int Y1, int X2, int Y2, const std::string& Str, int Size, const LVector4i& Color, int FontID );
```

最后一个公共成员函数是`Present()`，它确保所有图元都显示在屏幕上：

```java
  virtual void Present() = 0;
};
```

我们提供了两个`iCanvas`接口的实现。一个使用 SDL 库，另一个基于纯 OpenGL 调用。`clSDLCanvas`类包含指向 SDL 渲染器对象`m_Renderer`的指针。`clSDLCanvas`的构造函数接受指向前一章描述的`clSDLWindow`类实例的指针，以创建与窗口关联的渲染器：

```java
class clSDLCanvas: public iCanvas
{
private:
  SDL_Renderer* m_Renderer;
public:
  explicit clSDLCanvas( const clPtr<clSDLWindow>& Window )
  {
    m_Renderer = SDL_CreateRenderer( Window->GetSDLWindow(), -1, SDL_RENDERER_ACCELERATED );
  }
  virtual ~clSDLCanvas();
```

`clSDLCanvas`类直接调用相应的 SDL 例程来渲染矩形：

```java
  virtual void Rect( int X, int Y, int W, int H, bool Filled ) override
  {
    SDL_Rect R = { X, Y, W, H };
    Filled ?
      SDL_RenderFillRect( m_Renderer, &R ) :
      SDL_RenderDrawRect( m_Renderer, &R );
  }
```

`SetColor()`，`Clear()`，和`Present()`成员函数也调用相应的 SDL 例程：

```java
  virtual void SetColor( int R, int G, int B ) override;
  {
    SDL_SetRenderDrawColor( m_Renderer, R, G, B, 0xFF );
  }
  virtual void SetColor( const ivec4& C ) override;
  {
    SDL_SetRenderDrawColor( m_Renderer, C.x, C.y, C.z, C.w );
  }
  virtual void Clear() override;
  {
    SDL_RenderClear( m_Renderer );
  }
  virtual void Present() override
  {
    SDL_RenderPresent( m_Renderer );
  }
```

我们必须做一些记录以同步我们的`clBitmap`对象与`SDL_Texture`。内部结构如下：

```java
  std::vector<SDL_Texture*> m_Textures;
```

`CreateTexture()`方法分配一个新的 SDL 纹理：

```java
  int CreateTexture( const clPtr<clBitmap>& Pixels )
  {
    if ( !Pixels ) return -1;
    SDL_Texture* Tex = SDL_CreateTexture( m_Renderer,
      SDL_PIXELFORMAT_RGBA8888, SDL_TEXTUREACCESS_STREAMING, Pixels->GetWidth(), Pixels->GetHeight() );
    SDL_Rect Rect = { 0, 0, Pixels->GetWidth(), Pixels->GetHeight() };
```

我们将使用`Pixels`对象中的像素数据来更新 SDL 纹理：

```java
    void* TexturePixels = nullptr;
    int Pitch = 0;
    int Result = SDL_LockTexture( Tex, &Rect, &TexturePixels, &Pitch );
```

在这里，我们假设纹理的间距总是等于我们原始像素数据的间距。这在一般情况下不成立。然而，这个假设对于 2 的幂次纹理总是成立的。我们建议你实现尊重间距的纹理更新作为一个练习：

```java
    memcpy( TexturePixels, Pixels->FBitmapData, Pitch * Pixels->GetHeight() );
    SDL_UnlockTexture(Tex);
```

创建纹理后，我们将其存储在`m_Texture`容器中：

```java
    int Idx = (int)m_Textures.size();
    m_Textures.push_back( Tex );
    return Idx;
  }
```

`UpdateTexture()`方法类似，不同之处在于它不创建新纹理，而是重用前一个纹理的大小，因此，更新速度更快：

```java
  int UpdateTexture( int Idx, const clPtr<clBitmap>& Pixels )
  {
    if ( !Pixels ) return;
    if ( !Pixels || Idx < 0 || Idx >= (int)m_Textures.size() )
    {
      return -1;
    }
```

为了更新纹理，我们将调用`SDL_LockTexture()`以获取指向纹理数据的指针，并使用`memcpy()`来复制位图像素：

```java
    Uint32 Fmt;
    int Access;
    int W, H;
    SDL_QueryTexture( m_Textures[Idx], &Fmt, &Access, &W, &H );
    SDL_Rect Rect = { 0, 0, W, H };
    void* TexturePixels = nullptr;
    int Pitch = 0;
    int res = SDL_LockTexture( m_Textures[Idx], &Rect, &TexturePixels, &Pitch );
```

同样，这也只适用于与所提供位图相同间距的纹理：

```java
    memcpy( TexturePixels, Pixels->FBitmapData, Pitch * H );
    SDL_UnlockTexture( m_Textures[Idx] );
  }
```

当不再需要纹理时，可以使用`DeleteTexture()`成员函数来删除它：

```java
  void DeleteTexture( int Idx )
  {
    if ( Idx < 0 || Idx >= (int)m_Textures.size() )
    {
      return;
    }
    SDL_DestroyTexture( m_Textures[Idx] );
    m_Textures[Idx] = 0;
  }
```

`TextureRect()`方法调用`SDL_RenderCopy()`函数来绘制纹理映射的矩形：

```java
  void TextureRect( int X, int Y, int W, int H,
    int SX, int SY, int SW, int SH, int Idx )
  {
    SDL_Rect DstRect = { X, Y, X + W, Y + H };
    SDL_Rect SrcRect = { SX, SY, SX + SW, SY + SH };
    SDL_RenderCopy( m_Renderer, m_Textures[Idx], &SrcRect, &DstRect);
  }
```

`TextStr()`方法将 UTF-8 编码的字符串渲染到一个矩形区域内。它使用 FreeType 库，需要一些高级机制才能工作。我们将在以下章节讨论其实现。先来看看下面这个：

```java
  virtual void TextStr(
    int X1, int Y1, int X2, int Y2,
    const std::string& Str, int Size,
    const LVector4i& Color, int FontID );
};
```

基本上，`iCanvas`接口是围绕 SDL 设计的，其目的是将 SDL 的依赖隐藏在一个轻量级的接口之后，这样相对容易地使用另一种实现。在这里，我们使用 OpenGL 以及前一章中引入的类来实现`iCanvas`接口。看看`clGLCanvas`类。

首先，我们需要定义一些 GLSL 着色器，以渲染填充和纹理矩形。我们可以自然地使用 C++11 原始字符串字面量来做这件事。顶点着色器重新映射我们画布中使用的窗口标准化坐标到 OpenGL 标准化设备坐标，并且被所有片段程序共享：

```java
static const char RectvShaderStr[] = R"(
  uniform vec4 u_RectSize;
  in vec4 in_Vertex;
  in vec2 in_TexCoord;
  out vec2 Coords;
  void main()
  {
    Coords = in_TexCoord;
    float X1 = u_RectSize.x;
    float Y1 = u_RectSize.y;
    float X2 = u_RectSize.z;
    float Y2 = u_RectSize.w;
    float Width = X2 - X1;
    float Height = Y2 - Y1;
```

我们取 0,0…1,1 的矩形并将其重新映射到所需的矩形*X1,Y1-X2,Y2*。这样，我们可以使用单个顶点数组对象来渲染任何矩形：

```java
    vec4 VertexPos = vec4( X1 + in_Vertex.x * Width, Y1 + in_Vertex.y * Height,in_Vertex.z, in_Vertex.w ) * vec4( 2.0, -2.0, 1.0, 1.0 ) + vec4( -1.0, 1.0, 0.0, 0.0 );
    gl_Position = VertexPos;
  }
)";
```

这个片段着色器用于渲染一个单色矩形：

```java
static const char RectfShaderStr[] = R"(
  uniform vec4 u_Color;
  out vec4 out_FragColor;
  in vec2 Coords;
  void main()
  {
    out_FragColor = u_Color;
  }
)";
```

纹理映射的版本稍微复杂一些。我们将常数颜色与纹理进行调制：

```java
static const char TexRectfShaderStr[] = R"(
  uniform vec4 u_Color;
  out vec4 out_FragColor;
  in vec2 Coords;
  uniform sampler2D Texture0;
  void main()
  {
    out_FragColor = u_Color * texture( Texture0, Coords );
  }
)";
```

在`clGLCanvas`的构造函数中，我们将创建渲染所需的所有持久 OpenGL 对象：

```java
clGLCanvas::clGLCanvas( const clPtr<clSDLWindow>& Window )
: m_Window( Window )
{
```

初始化我们的 OpenGL 包装器：

```java
  LGL3 = std::unique_ptr<sLGLAPI>( new sLGLAPI() );
  LGL::GetAPI( LGL3.get() );
```

这个矩形的几何形状被重用来渲染任何尺寸的矩形：

```java
  m_Rect = clGeomServ::CreateRect2D( 0.0f, 0.0f, 1.0f, 1.0f, 0.0f, false, 1 );
  m_RectVA = new clGLVertexArray();
  m_RectVA->SetVertexAttribs( m_Rect );
```

从源代码中链接两个着色器程序：

```java
  m_RectSP = new clGLSLShaderProgram( RectvShaderStr, RectfShaderStr );
  m_TexRectSP = new clGLSLShaderProgram( RectvShaderStr, TexRectfShaderStr );
}
```

一个私有辅助函数用于将整数窗口坐标转换为我们在着色器中使用的标准化窗口坐标：

```java
vec4 clGLCanvas::ConvertScreenToNDC( int X, int Y, int W, int H ) const
{
  float WinW = static_cast<float>( m_Window->GetWidth() );
  float WinH = static_cast<float>( m_Window->GetHeight() );
  vec4 Pos( static_cast<float>( X ) / WinW,
    static_cast<float>( Y ) / WinH,
    static_cast<float>( X + W ) / WinW,
    static_cast<float>( Y + H ) / WinH );
  return Pos;
}
```

现在，实际的渲染代码非常直接。首先让我们渲染一个填充的矩形：

```java
void clGLCanvas::Rect( int X, int Y, int W, int H, bool Filled )
{
  vec4 Pos = ConvertScreenToNDC( X, Y, W, H );
  LGL3->glDisable( GL_DEPTH_TEST );
  m_RectSP->Bind();
  m_RectSP->SetUniformNameVec4Array( "u_Color", 1, m_Color );
  m_RectSP->SetUniformNameVec4Array( "u_RectSize", 1, Pos );
```

由于 alpha 混合是一个非常耗时的操作，只有当颜色的 alpha 通道实际暗示透明时才启用它：

```java
  if ( m_Color.w < 1.0f )
  {
    LGL3->glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    LGL3->glEnable( GL_BLEND );
  }
  m_RectVA->Draw( false );
```

再次禁用混合：

```java
  if ( m_Color.w < 1.0f )
  {
    LGL3->glDisable( GL_BLEND );
  }
}
```

我们的实现非常简单，并不进行任何状态更改跟踪，一旦你进行大量`Rect()`调用时，这会非常耗时。我们建议你向`iCanvas`接口添加一个方法，该方法可以一次渲染一系列矩形，并在渲染之前将它们分类为透明和非透明桶。这样，多个矩形的渲染速度可以相对较快。顺便一提，SDL 以类似的方式提供`SDL_FillRects()`函数。

由于我们可以使用我们的`clGLTexture`类，纹理管理功能现在变得简单了：

```java
int clGLCanvas::CreateTexture( const clPtr<clBitmap>& Pixels )
{
  if ( !Pixels ) return -1;
  m_Textures.emplace_back( new clGLTexture() );
  m_Textures.back()->LoadFromBitmap( Pixels );
  return m_Textures.size()-1;
}
```

`UpdateTexture()`和`DeleteTextures()`函数几乎是一行代码，除了参数有效性检查：

```java
void clGLCanvas::UpdateTexture( int Idx, const clPtr<clBitmap>& Pixels )
{
  if ( m_Textures[ Idx ] ) m_Textures[ Idx ]->LoadFromBitmap( Pixels );
}
void clGLCanvas::DeleteTexture( int Idx )
{
  m_Textures[ Idx ] = nullptr;
}
```

让我们使用这些纹理绘制一个纹理矩形。大部分工作与`Rect()`类似，除了纹理绑定：

```java
void clGLCanvas::TextureRect( int X, int Y, int W, int H, int SX, int SY, int SW, int SH, int Idx )
{
  if ( Idx < 0 || Idx >= (int)m_Textures.size() )
  {
    return;
  }
  vec4 Pos = ConvertScreenToNDC( X, Y, W, H );
  LGL3->glDisable( GL_DEPTH_TEST );
```

将所需的纹理绑定到纹理单元`0`：

```java
  m_Textures[ Idx ]->Bind( 0 );
```

使用`m_TexRectSP`着色器程序：

```java
  m_TexRectSP->Bind();
  m_TexRectSP->SetUniformNameVec4Array( "u_Color", 1, m_Color );
  m_TexRectSP->SetUniformNameVec4Array( "u_RectSize", 1, Pos );
```

对于带有透明 texel 的纹理矩形，总是使用混合：

```java
  LGL3->glBlendFunc( GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA );
  LGL3->glEnable( GL_BLEND );
  m_RectVA->Draw( false );
  LGL3->glDisable( GL_BLEND );
}
```

在 OpenGL 状态更改上可以实现类似的优化。我们留给你实现这种缓存机制。现在，让我们继续文本渲染，以便稍后可以返回到`clGLCanvas::TextStr()`。

# 文本渲染

在本节中，我们将描述`clTextRenderer`类中实现的文本渲染过程的所有重要细节。以下是我们的文本渲染器的部分：

+   UTF-8 字符串解码（[`en.wikipedia.org/wiki/UTF-8`](http://en.wikipedia.org/wiki/UTF-8)）

+   文本大小计算、字距调整和前进计算

+   单个字形的渲染，就像第二章中的 FreeType 示例，*本地库*

+   字体和字形加载与缓存

+   字符串渲染

我们假设所有字符串都是 UTF-8 编码，因为这样所有 ASCII 码在 0 到 127 之间的拉丁字符正好占一个字节，各种国家符号最多占四个字节。UTF-8 唯一的问题是 FreeType 接受固定宽度的 2 字节 UCS-2 编码，因此我们必须包含解码例程以从 UTF-8 转换为 UCS-2。

### 注意

有一个关于每个软件开发者都必须了解的 Unicode 和字符集的绝对基础知识的优秀文章。查看[`www.joelonsoftware.com/articles/Unicode.html`](http://www.joelonsoftware.com/articles/Unicode.html)。

我们将渲染字符串的每个字符存储在`clTextRenderer`的`FString`字段中：

```java
class clTextRenderer
{
  std::vector<sFTChar> FString;
```

每个字符的描述存储在以下结构中，其中`FChar`字段包含 UCS-2 字符代码，内部字符索引为`FIndex`：

```java
  struct sFTChar
  {
    FT_UInt FChar;
    FT_UInt FIndex;
```

`FGlyph`字段保存了带有渲染字形的 FreeType `FT_Glyph`结构：

```java
    FT_Glyph FGlyph;
```

解码字符编码后，我们计算每个字形的像素宽度和前进值，并将这些值存储在`FWidth`和`FAdvance`中：

```java
    FT_F26Dot6 FWidth;
    FT_F26Dot6 FAdvance;
```

`FCacheNode`字段由 FreeType 字体缓存子系统内部使用，以下是其简要描述：

```java
    FTC_Node FCacheNode;
```

默认构造函数为每个字段设置空值：

```java
    sFTChar()
    : FChar( 0 ), FIndex( ( FT_UInt )( -1 ) )
    , FGlyph( nullptr ), FAdvance( 0 )
    , FWidth( 0 ), FCacheNode( nullptr )
    { }
  };
```

现在我们有一个结构来保存我们的字符，下面将展示如何处理字符串并计算每个字符的位置。本章的后续段落描述了`clTextRenderer`的内部细节，因此当我们声明新字段时，意味着它们属于`clTextRenderer`类。我们从可以渲染字符串的高级例程开始。之后，我们讨论 UTF-8 解码，最后展示如何实现字体管理和缓存。

## 计算字形位置和字符串大小的像素值

`LoadStringWithFont()`成员函数接收一个文本字符串、内部字体标识符和所需的字体高度（以像素为单位）。它计算`FString`数组中每个元素的参数。此例程用于渲染和文本大小计算：

```java
bool TextRenderer::LoadStringWithFont( const std::string& S, int ID, int Height )
{
  if ( ID < 0 ) { return false; }
```

首先，我们获取字体句柄并确定是否需要字距调整。`FFace`是`clTextRenderer`中的`FT_Face`类型的字段。`GetSizedFace()`方法检索与所需高度匹配的字体。它使用内部字体缓存，以避免为单个分辨率多次渲染游戏字形，这一部分将在本章后面详细讨论。请看以下代码：

```java
  FFace = GetSizedFace( ID, Height );
  if ( !FFace ) { return false; }
  bool UseKerning = FT_HAS_KERNING( FFace );
```

然后，我们将 UTF-8 字符串解码为 UCS-2，并填充`FString`数组：

```java
  DecodeUTF8( S.c_str() );
```

填充`FString`后，我们渲染每个字符并计算位置：

```java
  for ( size_t i = 0, count = FString.size(); i != count; i++ )
  {
    sFTChar& Char = FString[i];
    FT_UInt ch = Char.FChar;
```

首先，我们获取字体的字符索引，并跳过行尾和回车字符：

```java
    Char.FIndex = ( ch != '\r' && ch != '\n' ) ?
      GetCharIndex( ID, ch ) : -1;
```

当我们知道字符的索引时，我们可以调用`FT_RenderGlyph()`方法，但每次遇到时都渲染单个字形是相当低效的。`GetGlyph()`例程负责从缓存中提取字形：

```java
    Char.FGlyph = ( Char.FIndex != -1 ) ?
      GetGlyph( ID, Height, ch, FT_LOAD_RENDER, &Char.FCacheNode ) : nullptr;
```

如果字形加载成功，我们会调用`SetAdvance()`方法：

```java
    if ( !Char.FGlyph || Char.FIndex == -1 ) continue;
    SetAdvance( Char );
```

可选地，我们可以调用`Kern()`方法来调整当前字符的前进值：

```java
    if ( i > 0 && UseKerning )
    {
      Kern( FString[i - 1], Char );
    }
  }
  return true;
}
```

辅助`SetAdvance()`方法计算字形的边界框，并将其宽度和前进值存储在`sFTChar`结构中：

```java
void TextRenderer::SetAdvance( sFTChar& Char )
{
  Char.FAdvance = Char.FWidth = 0;
  if ( !Char.FGlyph ) return;
```

前进值以`22:10`固定点值存储，我们使用位运算移位将其转换为整数值：

```java
  Char.FAdvance = Char.FGlyph->advance.x >> 10;
```

`FT_Glyph_Get_CBox()`函数返回一个边界框；我们使用它的`xMax`字段：

```java
  FT_BBox bbox;
  FT_Glyph_Get_CBoxPTR( Char.FGlyph,
    FT_GLYPH_BBOX_GRIDFIT, &bbox );
  Char.FWidth = bbox.xMax;
```

对于某些字形，如空格，宽度为零，我们使用`FAdvance`字段：

```java
  if ( Char.FWidth == 0 && Char.FAdvance != 0 )
  {
    Char.FWidth = Char.FAdvance;
  }
}
```

`Kern()`例程取两个相邻字符并计算前进校正。我们的文本渲染器不支持自动连字替换，如果需要这种替换，这里可能是执行它的地方：

```java
void TextRenderer::Kern( sFTChar& Left, const sFTChar& Right )
{
```

字符串的开头和结尾不需要进行字距调整：

```java
  if ( Left.FIndex == -1 || Right.FIndex == -1 ) return;
  FT_Vector Delta;
```

`FT_GetKerning()`调用计算当前字符的相对偏移校正：

```java
  FT_Get_KerningPTR( FFace, Left.FIndex, Right.FIndex, FT_KERNING_DEFAULT, &Delta );
```

结果被加到前进值中：

```java
  Left.FAdvance += Delta.x;
}
```

使用`FString`数组，我们可以通过简单相加各个字符的大小来轻松计算渲染字符串的大小。稍后，这个大小值用于为字符串分配输出位图：

```java
void TextRenderer::CalculateLineParameters( int* Width, int* MinY, int* MaxY, int* BaseLine ) const
{
```

变量`StrMinY`和`StrMaxY`保存了字符串中字符的最小和最大像素坐标：

```java
  int StrMinY = -1000, StrMaxY = -1000;
  if ( FString.empty() ) StrMinY = StrMaxY = 0;
```

`SizeX`变量保存字符串位图中的水平像素数。我们迭代`FString`数组，并将每个字符的前进值加到`SizeX`上：

```java
  int SizeX = 0;
  for ( size_t i = 0 ; i != FString.size(); i++ )
  {
    if ( FString[i].FGlyph == nullptr ) continue;
```

对于每个字符，我们获取字形的位图并更新`SizeX`变量：

```java
    FT_BitmapGlyph BmpGlyph = ( FT_BitmapGlyph )FString[i].FGlyph;
    SizeX += FString[i].FAdvance;
    int Y = BmpGlyph->top;
    int H = BmpGlyph->bitmap.rows;
```

读取字形尺寸后，我们更新字符串的最小和最大尺寸：

```java
    if ( Y > StrMinY ) StrMinY = Y;
    if ( H - Y > StrMaxY ) StrMaxY = H - Y;
  }
```

最后，我们通过将`26:6`固定点值`SizeX`转换为像素来计算字符串的整数值`Width`：

```java
  if ( Width ) { *Width = ( SizeX >> 6 ); }
  if ( BaseLine ) { *BaseLine = StrMaxY; }
  if ( MinY ) { *MinY = StrMinY; }
  if ( MaxY ) { *MaxY = StrMaxY; }
}
```

在进行字形渲染之前，我们还需要检查另一个重要事项。让我们概述 UTF-8 字符解码的过程。

## 解码 UTF-8

前一节提到的`DecodeUTF8()`例程，在`LoadStringWithFont()`中使用，迭代传入的字节数组，并使用`DecodeNextUTF8Char()`获取 UCS-2 编码中的字符代码：

```java
bool TextRenderer::DecodeUTF8( const char* InStr )
{
```

首先，我们存储一个指向缓冲区的指针，并将当前位置设置为 0：

```java
  FIndex = 0;
  FBuffer = InStr;
```

`FLength`字段包含`InStr`中的字节数。`DecodeNextUTF8Char()`方法使用`FLength`在到达字符串末尾时停止解码过程：

```java
  FLength = ( int )strlen( InStr );
  FString.clear();
  int R = DecodeNextUTF8Char();
```

然后，我们将遍历`FBuffer`中的字节数组，直到遇到零字节：

```java
  while ( ( R != UTF8_LINE_END ) && ( R != UTF8_DECODE_ERROR ) )
  {
    sFTChar Ch;
```

UCS-2 字符代码是我们在新的`sFTChar`实例中唯一更改的东西：

```java
    Ch.FChar = R;
    FString.push_back( Ch );
    R = DecodeNextUTF8Char();
  }
  return ( R != UTF8_DECODE_ERROR );
}
```

`DecodeNextUTF8Char()`中的 UTF-8 解码器基于来自[`www.json.org/JSON_checker/utf8_decode.c`](http://www.json.org/JSON_checker/utf8_decode.c)的 JSON 检查器的源代码。为了节省空间，我们省略了相当直接的位操作。低级实现细节可以在伴随的源代码中找到，只需查看`TextRenderer.h`和`TextRenderer.cpp`。

## 字形渲染

`RenderLineOnBitmap()`方法接收一个分配好的位图作为输出表面，并使用指定的字体标识符渲染给定的文本字符串。`LeftToRight`参数告诉我们文本是从左到右还是从右到左书写：

```java
void TextRenderer:

{
  LoadStringWithFont( TextString, FontID, FontHeight );
```

加载后，通过再次迭代`FString`容器，并为每个字符调用`DrawGlyphOnBitmap()`方法来完成文本渲染：

```java
  int x = StartX << 6;
  for ( size_t j = 0 ; j != FString.size(); j++ )
  {
    if ( FString[j].FGlyph != 0 )
    {
      FT_BitmapGlyph BmpGlyph = ( FT_BitmapGlyph ) FString[j].FGlyph;
```

我们通过累加每个字符的前进值来跟踪当前的水平位置变量`x`。对于每个非空字形，我们计算一个*实际*的屏幕位置，考虑到由`LeftToRight`参数指定的实际文本方向：

```java
      int in_x = ( x >> 6 ) +
        ( LeftToRight ? 1 : -1 ) * BmpGlyph->left;
```

如果方向是从右到左，我们将相应地校正位置：

```java
      if ( !LeftToRight )
      {
        in_x += BmpGlyph->bitmap.width;
        in_x = StartX + ( StartX - in_x );
      }
      DrawGlyphOnBitmap( Out, &BmpGlyph->bitmap,
        in_x, Y - BmpGlyph->top, Color );
    }
```

在每次迭代的末尾，我们使用前进值来移动水平计数器：

```java
    x += FString[j].FAdvance;
  }
}
```

包装例程`RenderTextWithFont()`预先计算输出位图的大小，并返回一个可直接使用的图像：

```java
clPtr<clBitmap> TextRenderer::RenderTextWithFont( const std::string& TextString, int FontID, int FontHeight, const ivec4& Color, bool LeftToRight )
{
  if ( !LoadStringWithFont( TextString, FontID, FontHeight ) )
  { return nullptr; }
  int W, Y;
  int MinY, MaxY;
  CalculateLineParameters( &W, &MinY, &MaxY, &Y );
  int H2 = MaxY + MinY;
```

在计算了文本大小之后，我们会分配一个输出位图，清除它，并调用`RenderLineOnBitmap()`方法：

```java
  clPtr<clBitmap> Result = make_intrusive<clBitmap>( W, H2, L_BITMAP_BGRA8 );
  Result->Clear();
```

`RenderLineOnBitmap()`调用为从右到左的文本固定了起始位置：

```java
  RenderLineOnBitmap( TextString, FontID, FontHeight, LeftToRight ? 0 : W - 1, MinY, Color, LeftToRight, Result );
  return Result;
}
```

`DrawGlyphOnBitmap()`方法与我们在第二章*本地库*中使用的代码类似。我们遍历字形的位图中的所有像素，并使用 FreeType 返回的数据设置它们：

```java
void TextRenderer::DrawGlyphOnBitmap( const clPtr<clBitmap>& Out, FT_Bitmap* Bitmap, int X0, int Y0, const ivec4& Color ) const
{
  int W = Out->GetWidth();
  int Width = W - X0;
  if ( Width > Bitmap->width ) { Width = Bitmap->width; }
  for ( int Y = Y0 ; Y < Y0 + Bitmap->rows ; ++Y )
  {
    unsigned char* Src = Bitmap->buffer +
      ( Y - Y0 ) * Bitmap->pitch;
```

在掩模创建模式下，我们可以直接将字形复制到输出位图中，忽略`Color`参数，即只渲染灰度掩模：

```java
    if ( FMaskMode )
    {
      for ( int X = X0 + 0 ; X < X0 + Width ; X++ )
      {
        int Int = *Src++;
        int OutMaskCol = ( Int & 0xFF );
        Out->SetPixel(X, Y,
          ivec4i(OutMaskCol,
            OutMaskCol, OutMaskCol, 255) );
      }
    }
    else
```

对于彩色渲染，我们会获取源像素，并根据掩模将其与指定颜色混合：

```java
    {
      for ( int X = X0 + 0 ; X < X0 + Width ; X++ )
      {
        unsigned int Int = *Src++;
        ivec4 Col = BlendColors(Color, Out->GetPixel(X, Y), (Int & 0xFF));
        if ( Int > 0 )
        {
          Col.w = Int;
          Out->SetPixel(X, Y, Col);
        }
      }
    }
  }
}
```

`BlendColors()`例程在颜色`C1`和`C2`之间执行线性插值。这里的右移位代替了除以 256。为了避免浮点运算和转换，混合因子从 0 变化到 255，因此在公式中使用值 255 而不是`1.0f`：

```java
inline LVector4i BlendColors( const LVector4i& C1, const LVector4i& C2, unsigned int F )
{
  int r = ((C1.x) * F >> 8) + ((C2.x) * (255 - F) >> 8);
  int g = ((C1.y) * F >> 8) + ((C2.y) * (255 - F) >> 8);
  int b = ((C1.z) * F >> 8) + ((C2.z) * (255 - F) >> 8);
  return LVector4i(r, g, b, 255);
}
```

现在，我们知道如何渲染字形。让我们找出如何加载、管理和缓存不同的字体。

## 字体初始化和缓存

到目前为止，我们还没有描述字体管理、字形渲染和重用字符位图的细节。

首先，我们将声明一个 FreeType 库句柄，供每次调用 FreeType API 时使用：

```java
FT_Library FLibrary;
```

对于我们使用的每种字体，都需要一个渲染字形缓存和一个字符映射缓存。这些缓存由一个`FTC_Manager`实例维护：

```java
FTC_Manager FManager;
```

接下来，我们需要字形和字符映射缓存：

```java
FTC_ImageCache FImageCache;
FTC_CMapCache FCMapCache;
```

我们在`FAllocatedFonts`字段中跟踪已加载字体文件的字节缓冲区。`std::map`的键是字体文件的名称：

```java
std::map<std::string, void*> FAllocatedFonts;
```

`FFontFaceHandles`映射是另一个初始化的 FreeType 字体句柄的容器：

```java
std::map<std::string, FT_Face> FFontFaceHandles;
```

私有的`LoadFontFile()`方法使用我们的虚拟文件系统机制读取字体文件，并将初始化的字体添加到前面代码中声明的容器中：

```java
FT_Error clTextRenderer::LoadFontFile( const std::string& FileName )
{
  if ( !FInitialized ) { return -1; }
```

我们防止已加载字体的重新加载：

```java
  if ( FAllocatedFonts.count( FileName ) > 0 ) { return 0; }
```

新字体被读取到`clBlob`对象中，并将其数据复制到一个单独的`Data`缓冲区：

```java
  clPtr<clBlob> DataBlob = LoadFileAsBlob(g_FS, FileName);
  int DataSize = DataBlob->GetSize();
  char* Data = new char[DataSize];
  memcpy( Data, DataBlob->GetData(), DataSize );
```

`FT_New_Memory_Face()`函数用于创建一个新的`FT_Face`对象，并将其存储在`FFontFaceHandles`数组中：

```java
  FT_Face TheFace;
  FT_Error Result = FT_New_Memory_FacePTR( FLibrary, ( FT_Byte* )Data, ( FT_Long )DataSize, 0, &TheFace );
  if ( Result == 0 )
  {
    FFontFaceHandles[ FileName ] = TheFace;
```

`Data`缓冲区被添加到`FAllocatedFonts`中，字体名称被添加到`FFontFaces`容器中：

```java
    FAllocatedFonts[ FileName ] = ( void* )Data;
    FFontFaces.push_back( FileName );
  }
  return Result;
}
```

我们正在开发的`clTextRenderer`类在`InitFreeType()`方法中包含了初始化代码：

```java
void clTextRenderer::InitFreeType()
{
```

这里我们省略了`LoadFT()`方法的描述，因为在 Windows 上，它只是简单地加载一个 FreeType 动态库文件并解析函数指针。对于 Android，此方法为空，并返回`true`：

```java
  FInitialized = LoadFT();
  if ( FInitialized )
  {
    FInitialized = false;
```

实际的初始化代码创建了一个 FreeType 库实例并分配了缓存：

```java
    if ( FT_Init_FreeTypePTR( &FLibrary ) != 0 ) { return; }
```

在 FreeType 之后初始化缓存管理器。`FreeType_Face_Requester`是一个指向我们下面代码中描述的方法的函数指针。它解析字体文件名并实际加载字体数据：

```java
    if ( FTC_Manager_NewPTR( FLibrary, 0, 0, 0, FreeType_Face_Requester, this, &FManager ) != 0 )
    { return; }
```

最后，初始化两个缓存，类似于管理器：

```java
    if ( FTC_ImageCache_NewPTR( FManager,
      &FImageCache ) != 0)
    {
      return;
    }
    if ( FTC_CMapCache_NewPTR( FManager, &FCMapCache ) != 0 )
    {
      return;
    }
    FInitialized = true;
  }
}
```

FreeType 的逆序完成初始化：

```java
void TextRenderer::StopFreeType()
{
```

首先，我们通过调用`FreeString`来清除`FString`容器：

```java
  FreeString();
```

然后，我们将释放`FAllocatedFonts`映射中包含字体数据的内存块：

```java
  for ( auto p = FAllocatedFonts.begin();
    p != FAllocatedFonts.end() ; p++ )
  {
    delete[] ( char* )( p->second );
  }
```

最后，我们清除字体面容器，并销毁缓存管理器和库实例：

```java
  FFontFaces.clear();
  if ( FManager ) { FTC_Manager_DonePTR( FManager ); }
  if ( FLibrary ) { FT_Done_FreeTypePTR( FLibrary ); }
}
```

`FreeString`方法为`FString`向量的每个元素销毁缓存的字形：

```java
void TextRenderer::FreeString()
{
  for ( size_t i = 0 ; i < FString.size() ; i++ )
    if ( FString[i].FCacheNode != nullptr )
      FTC_Node_UnrefPTR( FString[i].FCacheNode,
        FManager );
  FString.clear();
}
```

当 FreeType 发现缓存中没有所需的字体时，它会调用我们的`FreeType_Face_Requester()`回调来初始化新的字体面：

```java
FT_Error TextRenderer::FreeType_Face_Requester(
  FTC_FaceID FaceID,
  FT_Library Library,
  FT_Pointer RequestData,
  FT_Face* TheFace )
{
```

这是一个真正需要将 C 风格字体指针转换为整型标识符的尴尬地方。我们使用低 32 位作为标识符：

```java
  #if defined(_WIN64) || defined(__x86_64__)
    long long int Idx = ( long long int )FaceID;
    int FaceIdx = ( int )( Idx & 0x7FFFFFFFF );
  #else
    int FaceIdx = reinterpret_cast< int >( FaceID );
  #endif
```

如果`FaceIdx`小于零，它是一个有效指针，并且字体已经被加载：

```java
  if ( FaceIdx < 0 ) { return 1; }
```

我们正在描述的方法是 C 语言库的回调，因此我们使用`RequestData`模拟`this`指针。在`InitFreeType()`方法中，我们提供了`this`作为参数给`FTC_Manager_New`：

```java
  clTextRenderer* This = ( clTextRenderer* )RequestData;
```

我们从`FFontFaces`数组中提取文件名：

```java
  std::string FileName = This->FFontFaces[FaceIdx];
```

调用`LoadFontFile()`可能会返回零，如果我们已经加载了文件：

```java
  FT_Error LoadResult = This->LoadFontFile( FileName );
```

如果我们还没有加载文件，我们会在`FFontFaceHandles`数组中查找字体：

```java
  *TheFace = ( LoadResult == 0 ) ?
    This->FFontFaceHandles[FileName] : nullptr;
  return LoadResult;
}
```

我们正在接近`clTextRenderer`的完整视图，只剩下与字体和字形相关的少数几个方法。第一个是`GetSizedFace()`，我们在`LoadStringWithFont()`中使用过它：

```java
FT_Face clTextRenderer::GetSizedFace( int FontID, int Height )
{
```

要开始在给定字体高度渲染字形，我们填充`FTC_ScalerRec`结构以设置渲染参数。`IntToID()`例程将整数标识符转换为 void 指针，与`FreeType_Face_Requester()`中的代码相反：

```java
  FTC_ScalerRec Scaler;
  Scaler.face_id = IntToID( FontID );
  Scaler.height = Height;
  Scaler.width = 0;
  Scaler.pixel = 1;
  FT_Size SizedFont;
```

`FTC_Manager_LookupSize()`函数在缓存中查找`FT_Size`结构，我们将其提供给`FT_ActivateSize()`。在此之后，我们的字形以`Height`参数等于的大小进行渲染：

```java
  if ( FTC_Manager_LookupSizePTR( FManager, &Scaler,
    &SizedFont ) != 0 ) return nullptr;
  if ( FT_Activate_SizePTR( SizedFont ) != 0 ) return nullptr;
  return SizedFont->face;
}
```

第二个辅助方法是`GetGlyph()`，它渲染单个字形：

```java
FT_Glyph TextRenderer::GetGlyph( int FontID, int Height, FT_UInt Char, FT_UInt LoadFlags, FTC_Node* CNode )
{
```

在这里，我们将 UCS-2 代码转换为字符索引：

```java
  FT_UInt Index = GetCharIndex( FontID, Char );
```

`ImageType`结构被填充了字形渲染参数：

```java
  FTC_ImageTypeRec ImageType;
  ImageType.face_id = IntToID( FontID );
  ImageType.height = Height;
  ImageType.width = 0;
  ImageType.flags = LoadFlags;
```

然后，`FTC_ImageCache_Lookup()`函数查找先前渲染的字形，如果尚未渲染，则渲染一个：

```java
  FT_Glyph Glyph;
  if ( FTC_ImageCache_LookupPTR( FImageCache,
    &ImageType, Index, &Glyph, CNode ) != 0 )
  { return nullptr; }
  return Glyph;
}
```

第三个方法`GetCharIndex()`使用 FreeType 字符映射缓存快速将 UCS-2 字符代码转换为字形索引：

```java
FT_UInt clTextRenderer::GetCharIndex( int FontID, FT_UInt Char )
{
  return FTC_CMapCache_LookupPTR( FCMapCache,
    IntToID( FontID ), -1, Char );
}
```

`IntToID()`例程与`FreeType_Face_Requester()`中的强制转换代码类似。它所做的就是将整数字体面标识符转换为 C void 指针：

```java
inline void* IntToID( int FontID )
{
  #if defined(_WIN64) || defined (__x86_64__)
    long long int Idx = FontID;
  #else
    int Idx = FontID;
  #endif
    FTC_FaceID ID = reinterpret_cast<void*>( Idx );
  return ID;
}
```

最后，我们需要`GetFontHandle()`方法，它加载字体文件并返回新的有效字体面标识符：

```java
int clTextRenderer::GetFontHandle( const std::string& FileName )
{
```

首先，我们将尝试加载文件。如果文件已经加载，可能会返回零：

```java
  if ( LoadFontFile( FileName ) != 0 )
  return -1;
```

我们在 FFontFaces 容器中查找此字体并返回其索引：

```java
  for ( int i = 0 ; i != ( int )FFontFaces.size() ; i++ ) { }
  if ( FFontFaces[i] == FileName )
    return i;
  return -1;
}
```

我们拥有在位图上渲染 Unicode 字符所需的所有组件。让我们看看如何使用这个功能来扩展`clCanvas`的文本渲染能力。

## 将文本渲染器集成到画布中

现在我们有了`clTextRenderer`类，我们可以实现`clGLCanvas::TextStr()`：

```java
void clGLCanvas::TextStr( int X1, int Y1, int X2, int Y2, const std::string& Str, int Size, const ivec4& Color, int FontID )
{
```

首先，我们将字符串渲染成位图：

```java
  auto B = TextRenderer::Instance()->RenderTextWithFont( Str, FontID, Size, Color, true );
```

静态纹理在所有对`TextStr()`的调用之间共享。虽然性能不是特别高，也不是多线程的，但是非常简单：

```java
  static int Texture = this->CreateTexture();
```

然后，我们从这个位图中更新静态纹理：

```java
  UpdateTexture( Texture, B );
```

计算完输出大小后，我们将调用`TextureRect()`方法，使用我们的文本字符串渲染位图：

```java
  int SW = X2 - X1 + 1, SH = Y2 - Y1 + 1;
  this->TextureRect( X1, Y1, X2 - X1 + 1, Y2 - Y1 + 1, 0, 0, SW, SH, Texture );
}
```

使用单例模式实现全局访问`clTextRenderer`的单个实例：

```java
clTextRenderer* clTextRenderer::Instance()
{
  static clTextRenderer Instance;
  return &Instance;
}
```

我们现在可以使用`iCanvas`接口来渲染文本。让我们绘制一个图形用户界面，我们可以在其中放置文本。

# 组织 UI 系统

创建了立即模式渲染的`iCanvas`接口后，我们可以转向用户界面实现。为了创建有意义的应用程序，仅能渲染静态甚至动画图形信息并不总是足够的。应用程序必须对用户输入做出反应，对于移动设备来说，这通常意味着响应触摸屏事件。在这里，我们创建了一个由三种基本元素（称为视图）组成的简约图形用户界面：

+   `clUIView`：这是一个逻辑容器，也是其他视图的基类

+   `clUIStatic`：这是一个带有文本的静态标签

+   `clUIButton`：这是一个一旦被触摸就会触发事件的物体

每个视图都是一个矩形区域，能够渲染自身并对外部事件（如定时和用户触摸）做出反应。由于我们在使用 NDK，同时我们也想在桌面机上调试我们的软件，因此我们必须将特定于操作系统的队列中的事件重定向到 C++事件处理代码。

## 基础的 UI 视图

我们为每个 UI 元素定义了`clUIView`接口。这个接口包括 UI 视图的几何属性：

```java
class clUIView: public iIntrusiveCounter
{
protected:
```

这个类包含了 UI 元素的几何属性。`m_X`和`m_Y`字段包含在父坐标框架中的相对坐标。`m_ScreenX`和`m_ScreenY`字段包含在屏幕参考框架中的绝对坐标。`m_Width`和`m_Height`字段分别存储元素的宽度和高度：

```java
  int m_X, m_Y;
  int m_ScreenX, m_ScreenY;
  int m_Width, m_Height;
```

类的私有部分包含子视图布局的标志和设置。这些设置稍后会在`LayoutChildViews()`方法中使用。`m_ParentFractionX`和`m_ParentFractionY`值用于覆盖作为父视图大小的百分比的`m_Width`和`m_Height`。如果这些值大于 1，它们将被忽略。它们在`LayoutChildViews`中的显式使用如下所示。`m_AlignV`和`m_AlignH`包含坐标的不同对齐模式：

```java
private:
  float m_ParentFractionX, m_ParentFractionY;
  eAlignV m_AlignV;
  eAlignH m_AlignH;
  int m_FillMode;
```

最后一个字段是`m_ChildViews`向量，其中包含指向子视图的指针，顾名思义：

```java
  std::vector< clPtr<clUIView> > m_ChildViews;
```

默认构造函数为每个字段设置初始值：

```java
public:
  clUIView():
  m_X( 0 ), m_Y( 0 ), m_Width( 0 ), m_Height( 0 ),
  m_ScreenX( 0 ), m_ScreenY( 0 ), m_ParentFractionX( 1.0f ),
  m_ParentFractionY( 1.0f ), m_AlignV( eAlignV_DontCare ),
  m_AlignH( eAlignH_DontCare ), m_ChildViews( 0 )
  {}
```

类接口包含访问属性的`Get*`和`Set*`单行函数

```java
  virtual void SetPosition( int X, int Y ) { m_X = X; m_Y = Y; }
  virtual void SetSize( int W, int H )
  { m_Width = W; m_Height = H; }
  virtual void SetWidth( int W ) { m_Width = W; }
  virtual void SetHeight( int H ) { m_Height = H; }
  virtual int GetWidth() const { return m_Width; }
  virtual int GetHeight() const { return m_Height; }
  virtual int GetX() const { return m_X; }
  virtual int GetY() const { return m_Y; }
```

然后，是布局参数的获取器和设置器：

```java
  virtual void SetAlignmentV( eAlignV V ) { m_AlignV = V; }
  virtual void SetAlignmentH( eAlignH H ) { m_AlignH = H; }
  virtual eAlignV GetAlignmentV() const { return m_AlignV; }
  virtual eAlignH GetAlignmentH() const { return m_AlignH; }
  virtual void SetParentFractionX( float X )
  { m_ParentFractionX = X; }
  virtual void SetParentFractionY( float Y )
  { m_ParentFractionY = Y; }
```

`Add()`和`Remove()`方法提供了对`m_ChildViews`容器的访问：

```java
  virtual void Add( const clPtr<clUIView>& V )
  {
    m_ChildViews.push_back( V );
  }
  virtual void Remove( const clPtr<clUIView>& V )
  {
    m_ChildViews.erase( std::remove( m_ChildViews.begin(), m_ChildViews.end(), V ), m_ChildViews.end() );
  }
```

`GetChildViews()`方法直接提供了对`m_ChildViews`的只读访问：

```java
  virtual const std::vector< clPtr<clUIView> >&
    GetChildViews() const { return m_ChildViews; }
```

`Draw()`方法调用`PreDrawView()`来渲染该 UI 元素的背景层，然后它为每个子视图调用`Draw()`，最后，调用`PostDrawView()`完成该 UI 元素的渲染过程：

```java
  virtual void Draw( const clPtr<iCanvas>& C )
  {
    this->PreDrawView( C );
    for ( auto& i : m_ChildViews )
    {
      i->Draw( C );
    }
    this->PostDrawView( C );
  }
```

`UpdateScreenPositions()`方法重新计算子视图的绝对屏幕位置：

```java
  virtual void UpdateScreenPositions( int ParentX = 0, int ParentY = 0 )
  {
    m_ScreenX = ParentX + m_X;
    m_ScreenY = ParentY + m_Y;
    for ( auto& i : m_ChildViews )
    {
      i->UpdateScreenPositions( m_ScreenX, m_ScreenY );
    }
  }
```

事件处理部分包括`Update()`和`OnTouch()`方法。`Update()`方法通知所有子视图已经过了一段时间：

```java
  virtual void Update( double Delta )
  {
    for( auto& i: m_ChildViews )
    i->Update( Delta );
  }
```

`OnTouch()`方法接受屏幕坐标和触摸标志：

```java
  virtual bool OnTouch( int x, int y, bool Pressed )
  {
    if ( IsPointOver( x, y ) )
    {
```

检查触摸事件是否被任何子视图处理：

```java
      for( auto& i: m_ChildViews )
      {
        if( i->OnTouch( x, y, Pressed ) )
        return true;
      }
    }
    return false;
  }
```

`IsPointOver()`方法检查点是否在视图内：

```java
  virtual bool IsPointOver( int x, int y ) const
  {
    return ( x >= m_ScreenX ) &&
      ( x <= m_ScreenX + m_Width  ) &&
      ( y >= m_ScreenY ) &&
      ( y <= m_ScreenY + m_Height );
  }
```

受保护的部分包含两个虚拟方法，用于渲染实际`clUIView`的内容。`PreDrawView()`方法在渲染子视图之前调用，因此此调用的可见结果可能会被子视图擦除，例如背景层。`PostDrawView()`方法在所有子视图渲染后调用，就像渲染图像顶部的装饰：

```java
protected:
  virtual void PreDrawView( const clPtr<iCanvas>& C ) {};
  virtual void PostDrawView( const clPtr<iCanvas>& C ) {};
};
```

这个机制使得 UI 渲染和自定义成为可能。在我们 UI 可以生动呈现之前，我们还需要一个事件分派机制。让我们来实现它。

## 事件

在最低级别，所有来自 Android 或桌面操作系统的的事件都由 SDL 库处理，我们只需编写这些事件的处理程序：

```java
bool clSDLWindow::HandleEvent( const SDL_Event& Event );
```

我们为`HandleEvent()`函数增加了两个案例标签，以便我们可以分派触摸事件：

```java
case SDL_MOUSEBUTTONDOWN:
  OnTouch( Event.button.x, Event.button.y, true );
  break;
case SDL_MOUSEBUTTONUP:
  OnTouch( Event.button.x, Event.button.y, false );
  break;
```

在 C++11 之前，将类似 C 的函数指针和类成员函数指针包装在单个对象中并不是一件容易的事，需要一些重量级的模板库，如`boost::bind`。现在，SDL 库中的`std::function`对象正好符合我们的需求。

我们在这里实现的唯一交互式对象是`clUIButton`。当用户点击这样的对象时，会执行自定义操作。该操作的代码可以位于独立函数、成员函数或 lambda 表达式中。例如，我们创建一个`Exit`按钮，代码可能如下所示：

```java
ExitBtn->SetTouchHandler(
  [](int x, int y )
  {
    LOGI( "Exiting" );
    g_Window->RequestExit();
    return true;
  }
);
```

`clUIButton`类必须包含`std::function`字段，`OnTouch()`方法在发生点击时可选地调用此函数。

## 实现 UI 类

`clUIStatic`视图是`clUIView`的派生类，重写了`PreDrawView()`方法：

```java
class clUIStatic: public clUIView
{
public:
  clUIStatic() : m_BackgroundColor( 255, 255, 255, 255 ) {}
  virtual void SetBackgroundColor( const ivec4& C )
  { m_BackgroundColor = C;};
protected:
  virtual void PreDrawView( const clPtr<iCanvas>& C ) override
  {
    C->SetColor( m_BackgroundColor );
    C->Rect(m_ScreenX, m_ScreenY, m_Width, m_Height, true);
    clUIView::PreDrawView( C );
  }
private:
  ivec4 m_BackgroundColor;
};
```

`clUIButton`类在`clUIStatic`渲染之上添加了自定义触摸事件处理：

```java
typedef std::function<bool(int x, int y)> sTouchHandler;
  class clUIButton: public clUIStatic
{
public:
  clUIButton(): m_OnTouchHandler(nullptr) {}
  virtual bool OnTouch( int x, int y, bool Pressed ) override
  {
    if( IsPointOver( x, y ) )
    {
      if(!Pressed && m_OnTouchHandler )
      return m_OnTouchHandler(x, y);
    }
    return false;
  }
  virtual void SetTouchHandler(const sTouchHandler&& H)
  { m_OnTouchHandler = H; }
private:
  sTouchHandler m_OnTouchHandler;
};
```

现在，我们的迷你用户界面可以在应用程序中使用。

## 在应用程序中使用视图

下面是一个简短的代码片段，它创建了一个按钮，并在点击该按钮时退出应用程序：

```java
auto MsgBox = make_intrusive<clUIButton>();
MsgBox->SetParentFractionX( 0.5f );
MsgBox->SetParentFractionY( 0.5f );
MsgBox->SetAlignmentV( eAlignV_Center );
MsgBox->SetAlignmentH( eAlignH_Center );
MsgBox->SetBackgroundColor( ivec4( 255, 255, 255, 255) );
MsgBox->SetTitle("Exit");
MsgBox->SetTouchHandler( [](int x, int y )
  {
    LOGI( "Exiting" );
    g_Window->RequestExit();
    return true;
  }
);
```

完整的源代码可以在`1_SDL2UI`示例中找到。除了本章讨论的细节之外，源代码还包含了一个基本的布局机制，以便视图可以拥有相对坐标和大小。想要了解这个附加功能，请查看`LayoutController.cpp`和`LayoutController.h`。

# 总结

在本章中，我们学习了如何用 C++实现并渲染基本用户界面，使用 FreeType 库渲染 UTF-8 文本，并以平台无关的方式处理用户输入。我们将在最后一章使用这些功能来实现一个跨平台游戏应用。现在，让我们回到在第六章，*OpenGL ES 3.1 and Cross-platform Rendering*开始讨论的 3D 渲染话题，并在这些抽象之上实现一个渲染引擎。
