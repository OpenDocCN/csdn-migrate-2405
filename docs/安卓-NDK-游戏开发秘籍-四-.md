# 安卓 NDK 游戏开发秘籍（四）

> 原文：[`zh.annas-archive.org/md5/713F9F8B01BD9DC2E44DADEE702661F7`](https://zh.annas-archive.org/md5/713F9F8B01BD9DC2E44DADEE702661F7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：跨平台 UI 和输入系统

在本章中，我们将涵盖：

+   在安卓上处理多触摸事件

+   在 Windows 上设置多触摸模拟

+   在 Windows 上处理多触摸事件

+   识别手势

+   实现屏幕上的游戏手柄

+   使用 FreeType 进行文本渲染

+   游戏内字符串的本地化

# 引言

移动用户界面基于（除了图形渲染）多触摸输入。本章将向您展示如何在安卓操作系统上处理触摸事件，以及如何在 Windows 上调试它们。还包含了一个关于在 Windows 上使用多个鼠标模拟多触摸能力的专门教程。本章的其余部分致力于高质量文本渲染和支持多种语言。

# 在安卓上处理多触摸事件

迄今为止，我们还没有处理除了安卓上的**返回**按钮之外的任何用户交互。在本教程中，我们将展示如何处理安卓上的多触摸事件。

## 准备就绪

你应该熟悉多触摸输入处理的概念。在 Java 中，安卓多触摸事件是在`MotionEvent`类内部传递的，该类的实例作为参数传递给你的`Activity`类的`onTouchEvent()`方法。`MotionEvent`类包含了所有当前活动中和已释放的触摸信息。为了将此信息传递给我们的本地代码，我们将携带多个触摸的单个事件转换为一系列仅包含单个触摸数据的事件。这简化了 JNI 的交互操作，并使我们的代码易于移植。

## 如何操作...

每个安卓活动都支持多触摸事件处理。我们所要做的就是重写`Activity`类的`onTouchEvent()`方法：

1.  首先，我们声明一些与单个触摸点相关的事件的内部常量：

    ```kt
    private static final int MOTION_MOVE = 0;
    private static final int MOTION_UP   = 1;
    private static final int MOTION_DOWN = 2;
    private static final int MOTION_START = -1;
    private static final int MOTION_END   = -2;
    ```

1.  事件处理器使用`MotionEvent`结构，并提取有关单个触摸的信息。在本地代码中声明的`SendMotion()`函数包含了我们通过 JNI 从`onTouchEvent()`中调用的手势解码：

    ```kt
    @Override public boolean onTouchEvent( MotionEvent event )
    {
    ```

1.  告诉我们的本地代码我们将要发送一系列事件：

    ```kt
      SendMotion( MOTION_START, 0, 0, false, MOTION_MOVE );
    ```

1.  确定事件代码和第一个触摸点的`ID`：

    ```kt
      int E = event.getAction() & MotionEvent.ACTION_MASK;
      int nPointerID = event.getPointerId((event.getAction() &MotionEvent.ACTION_POINTER_INDEX_MASK) >>MotionEvent.ACTION_POINTER_INDEX_SHIFT );
      try
      {
    ```

1.  获取主触摸点的坐标：

    ```kt
        int x = (int)event.getX(), y = (int)event.getY();
        int cnt = event.getPointerCount();
    ```

1.  处理触摸开始：

    ```kt
        if ( E == MotionEvent.ACTION_DOWN )
        {
          for ( int i = 0; i != cnt; i++ )
            SendMotion( event.getPointerId(i),(int)event.getX(i),(int)event.getY(i),true, MOTION_DOWN );
        }
    ```

1.  当所有触摸点释放时，处理整个手势的结束：

    ```kt
        if ( E == MotionEvent.ACTION_UP ||E == MotionEvent.ACTION_CANCEL )
        {
          SendMotion( MOTION_END, 0, 0, false, MOTION_UP );
          return E <= MotionEvent.ACTION_MOVE;
        }
    ```

1.  处理次要触摸点：

    ```kt
        int maskedEvent = event.getActionMasked();
        if ( maskedEvent== MotionEvent.ACTION_POINTER_DOWN )
        {
          for ( int i = 0; i != cnt; i++ )
            SendMotion( event.getPointerId(i),(int)event.getX(i),(int)event.getY(i),true, MOTION_DOWN );
        }
        if ( maskedEvent == MotionEvent.ACTION_POINTER_UP )
        {
          for ( int i = 0; i != cnt ; i++ )
            SendMotion( event.getPointerId(i),(int)event.getX(i),(int)event.getY(i),i != nPointerID, MOTION_UP );
          SendMotion( nPointerID,(int)event.getX(nPointerID),(int)event.getY(nPointerID),false, MOTION_MOVE );
        }
    ```

1.  最后，我们更新每个触摸点的坐标：

    ```kt
        if ( E == MotionEvent.ACTION_MOVE )
        {
          for ( int i = 0; i != cnt; i++ )
            SendMotion(event.getPointerId(i),(int)event.getX(i),(int)event.getY(i),true, MOTION_MOVE );
        }
      }
    ```

1.  当所有操作完成后，我们通知本地手势解码器事件序列的结束：

    ```kt
      SendMotion( MOTION_END, 0, 0, false, MOTION_MOVE );
      return E <= MotionEvent.ACTION_MOVE;
    }
    ```

1.  本地`SendMotion()`函数接受触摸点`ID`、屏幕像素坐标、运动标志和一个表示触摸点是否激活的布尔参数：

    ```kt
    public native static void SendMotion( int PointerID, int x, int y,
      boolean Pressed, int Flag );
    ```

## 工作原理...

安卓操作系统将触摸点的通知发送到我们的应用程序，`onTouchEvent()`函数将包含在`MotionEvent`对象中的触摸事件集合转换为一连串的 JNI `SendMotion()`调用。

## 另请参阅

+   *在 Windows 上处理多触摸事件*

+   *识别手势*

# 在 Windows 上设置多点触控仿真

没有硬件的情况下测试基于触摸的界面是很困难的，但即使有可用的 Android 硬件，我们也没有逐步调试器的奢侈。幸运的是，Windows 支持触摸屏硬件，可以为我们的应用程序提供`WM_TOUCH`事件。这个方法展示了一个技巧，利用多只鼠标来模拟触摸事件。

## 准备就绪

本方法依赖于第三方 Windows 驱动程序，即 MultiTouchVista，它是一个用户输入管理层，处理来自各种设备的输入。可以从[`multitouchvista.codeplex.com/`](http://multitouchvista.codeplex.com/)下载。

## 如何操作...

1.  首先，我们需要安装系统驱动。我们解压`MultiTouchVista_-_second_release_-_refresh_2.zip`文件，这是在撰写本文时最新的版本，然后用管理员权限打开命令行。如果未以管理员权限运行控制台，驱动程序安装将会失败。解压后的文件夹包含一个名为`Driver`的子文件夹，你应根据操作系统的类型选择`x64`或`x32`文件夹。在那个文件夹中，我们执行以下命令：

    ```kt
    >Install driver.cmd
    ```

1.  会弹出一个对话框，询问你是否想要安装这个设备软件，你应该点击**安装**按钮。安装完成后，你将在命令行上看到一条消息。

1.  接下来我们要做的是在**设备管理器**中激活驱动。我们打开**控制面板**，然后打开**设备管理器**窗口。在那里，我们在列表中找到**人体学输入设备**项。我们右键点击刚刚安装了驱动程序的**通用软件 HID 设备**。从上下文菜单中选择**禁用**以禁用该设备。在禁用设备前的确认中，我们只需回答**是**。之后，我们再次通过右键点击这个节点并选择**启用**来重新启用这个设备。

1.  现在，由于我们使用鼠标模拟多点触控，我们应该在屏幕上以某种方式显示触摸点，因为否则不可能知道鼠标指针的位置。在**控制面板** | **硬件和声音**中，我们打开**笔和触摸**窗口。**触摸**选项卡包含**当我与屏幕上的项目互动时显示触摸指针**复选框，应该启用它。

1.  当所有鼠标都连接后，我们可以启动驱动程序。我们打开两个命令行窗口，在第一个窗口中运行来自`MultiTouchVista`软件包的`Multitouch.Service.Console.exe`。在第二个控制台窗口中，我们运行`Multitouch.Driver.Console.exe`，同时不要关闭**MultiTouch.Server.Console**窗口。退出这两个应用程序，以返回到正常的非多点触控 Windows 环境。

## 它是如何工作的...

为了检查驱动程序和服务是否如预期般工作，我们可以尝试使用标准微软画图应用程序，并使用两只或多只鼠标同时绘制一些内容。

## 另请参阅

+   *在 Windows 上处理多点触控事件*

# 在 Windows 上处理多点触控事件

安装了`MultiTouchVista`驱动后，或者如果我们恰好有一个支持多点触控的屏幕，我们可以在应用程序中初始化一个事件循环并处理`WM_TOUCH`消息。

## 准备就绪

第一个食谱包含了关于多点触控处理的所有相关信息。在这个食谱中，我们仅扩展了针对 Microsoft Windows 的代码。

### 注意

本书没有讨论关于 Mac 的多点触控输入模拟。

## 如何操作...

1.  `MinGW`工具链不包括最新的 Windows SDK 头文件，因此需要定义许多常量以使用`WM_TOUCH`消息：

    ```kt
    #if !defined(_MSC_VER)
    #define SM_DIGITIZER            94
    #define SM_MAXIMUMTOUCHES       95
    #define TOUCHEVENTF_DOWN        0x0001
    #define TOUCHEVENTF_MOVE        0x0002
    #define TOUCHEVENTF_UP          0x0004
    #define TOUCHEVENTF_PRIMARY     0x0010
    #define WM_TOUCH                0x0240
    ```

1.  `TOUCHINPUT`结构使用`WinAPI`数据类型封装了一个单独的触摸，并且也应该为`MinGW`手动声明：

    ```kt
    typedef struct _TOUCHINPUT {
      LONG x, y;
      HANDLE hSource;
      DWORD dwID, dwFlags, wMask, dwTime;
      ULONG_PTR dwExtraInfo;
      DWORD cxContact, cyContact;
    } TOUCHINPUT,*PTOUCHINPUT;
    #endif
    ```

1.  接下来的四个函数为我们的应用程序提供了触摸界面处理。我们声明函数原型和静态函数指针，以便从`user32.dll`加载它们：

    ```kt
    typedef BOOL (WINAPI *CloseTouchInputHandle_func)(HANDLE);
    typedef BOOL (WINAPI *Get_func)(HANDLE, UINT, PTOUCHINPUT, int);
    typedef BOOL (WINAPI *RegisterTouch_func)(HWND, ULONG);
    typedef BOOL (WINAPI *UnregisterTouch_func)(HWND);
    static CloseTouch_func CloseTouchInputHandle_Ptr = NULL;
    static Get_func GetTouchInputInfo_Ptr = NULL;
    static RegisterTouch_func RegisterTouchWindow_Ptr = NULL;
    static UnregisterTouch_func UnregisterTouchWindow_Ptr =NULL;
    ```

1.  由于`MinGW`不支持自动导出与`WM_TOUCH`相关的方法，我们必须使用`GetProcAddress()`手动从`user32.dll`加载它们。这一操作在`1_MultitouchInput`中的`Wrapper_Windows.cpp`文件中定义的`LoadTouchFuncs()`函数中完成：

    ```kt
    static bool LoadTouchFuncs()
    {
      if ( !CloseTouchInputHandle_Ptr )
      {
        HMODULE hUser = LoadLibraryA( "user32.dll" );
        CloseTouchInputHandle_Ptr =(CloseTouchInputHandle_func)GetProcAddress( hUser, "CloseTouchInputHandle" );
        GetTouchInputInfo_Ptr = ( GetTouchInputInfo_func )GetProcAddress( hUser, "GetTouchInputInfo" );
        RegisterTouchWindow_Ptr = (RegisterTouchWindow_func)GetProcAddress( hUser, "RegisterTouchWindow" );
        UnregisterTouchWindow_Ptr =(UnregisterTouchWindow_func)GetProcAddress( hUser, "UnregisterTouchWindow" );
      }
      return ( RegisterTouchWindow_Ptr != NULL );
    }
    ```

1.  最后，我们需要声明`GetTouchPoint()`例程，它将`TOUCHPOINT`坐标转换为屏幕像素，为了简单起见，这里使用了硬编码的窗口大小 100 x 100 像素：

    ```kt
    static POINT GetTouchPoint(HWND hWnd, const TOUCHINPUT& ti)
    {
      POINT pt;
      pt.x = ti.x / 100;
      pt.y = ti.y / 100;
      ScreenToClient( hWnd, &pt );
      return pt;
    }
    ```

1.  现在，我们准备在 Windows 上实现多点触控消息处理。在我们的窗口函数中，我们为`WM_TOUCH`消息添加一个新的消息处理程序，其中包含了打包在一起的不同触摸点的数据。我们将参数解包到一个数组中，其中每个条目代表单个触摸点的消息：

    ```kt
    case WM_TOUCH:
    {
      unsigned int NumInputs = (unsigned int)wParam;
      if ( NumInputs < 1 ) { break; }
      TOUCHINPUT* ti = new TOUCHINPUT[NumInputs];
      DWORD Res = GetTouchInputInfo_Ptr((HANDLE)lParam, NumInputs, ti, sizeof(TOUCHINPUT));
      double EventTime = Env_GetSeconds();
      if ( !Res ) { break; }
    ```

1.  对于每个触摸点，我们在全局数组`g_TouchPoints`中更新其状态。这是与 Android 代码的主要区别，因为在 Java 代码中我们会解码`MotionEvent`结构体，并将点列表传递给本地代码：

    ```kt
      for (unsigned int i = 0; i < NumInputs ; ++i)
      {
        POINT touch_pt = GetTouchPoint(Window, ti[i]);
        vec2 Coord(touch_pt.x / ImageWidth,touch_pt.y / ImageHeight);
        sTouchPoint pt(ti[i].dwID, Coord,MOTION_MOVE, EventTime);
        if (ti[i].dwFlags & TOUCHEVENTF_DOWN)pt.FFlag = MOTION_DOWN;
        if (ti[i].dwFlags & TOUCHEVENTF_UP)
          pt.FFlag = MOTION_UP;
        Viewport_UpdateTouchPoint(pt);
      }
    ```

1.  然后，我们清理临时数组：

    ```kt
      CloseTouchInputHandle_Ptr((HANDLE)lParam);
      delete[] ti;
    ```

1.  我们移除所有释放的点：

    ```kt
      Viewport_ClearReleasedPoints();
    ```

1.  最后，我们处理所有活动的触摸点：

    ```kt
      Viewport_UpdateCurrentGesture();
      break;
    }
    ```

1.  事件处理程序使用一个全局触摸点列表：

    ```kt
    std::list<sTouchPoint> g_TouchPoints;
    ```

1.  `sTouchPoint`结构体封装了一个触摸点的坐标、触摸点`ID`、运动标志和关联的事件时间戳：

    ```kt
    struct sTouchPoint
    {
      int FID;
      vec2 FPoint;
      int FFlag;
      double FTimeStamp;
      sTouchPoint(int ID, const vec2& C, int flag, doubletstamp):
        FID(ID), FPoint(c), FFlag(flag), FTimeStamp(tstamp) {}
    ```

1.  检查这个触摸点是否处于激活状态：

    ```kt
      inline bool IsPressed() const
      {
        return (FFlag == MOTION_MOVE) || (FFlag ==MOTION_DOWN);
      }
    };
    ```

1.  `Viewport_UpdateTouchPoint()`函数会根据运动标志将点添加到列表中，或者只是更新状态：

    ```kt
    void Viewport_UpdateTouchPoint(const sTouchPoint& pt)
    {
      std::list<sTouchPoint>::iterator foundIt =FTouchPoints.end();
      for ( auto it = FTouchPoints.begin(); it != foundIt;++it )
      {
        if ( it->FID == pt.FID )
        {
          foundIt = it;
          break;
        }
      }
      switch ( pt.FFlag )
      {
        case MOTION_DOWN:
          if ( foundIt == FTouchPoints.end() )
            FTouchPoints.push_back( pt );
        case MOTION_UP:
        case MOTION_MOVE:
          if ( foundIt != FTouchPoints.end() )
            *foundIt = pt;
          break;
      }
    }
    ```

1.  `Viewport_ClearReleasedPoints()`函数移除所有运动标志设置为`MOTION_UP`的点：

    ```kt
    void Viewport_ClearReleasedPoints()
    {
      auto first = FTouchPoints.begin();
      auto result = first;
      for ( ; first != FTouchPoints.end() ; ++first )
        if ( first->FFlag != MOTION_UP ) *result++ = *first;
      FTouchPoints.erase( result, FTouchPoints.end() );
    }
    ```

1.  最后一个函数，`Viewport_UpdateCurrentGesture()`，将点列表发送到手势处理器：

    ```kt
    void Viewport_UpdateCurrentGesture()
    {
      Viewport_ProcessMotion( MOTION_START,vec2(), false, MOTION_MOVE );
      auto j = FTouchPoints.begin();
      for ( ; j != FTouchPoints.end(); ++j )
        Viewport_ProcessMotion( j->FID, j->FPoint,j->IsPressed(), j->FFlag );
      Viewport_ProcessMotion( MOTION_END, vec2(), false,MOTION_MOVE );
    }
    ```

## 工作原理...

在`WM_CREATE`事件处理程序中，我们将我们的窗口注册为触摸事件响应者：

```kt
case WM_CREATE:
...
g_TouchEnabled = false;
BYTE DigitizerStatus = (BYTE)GetSystemMetrics( SM_DIGITIZER );
if ( (DigitizerStatus & (0x80 + 0x40)) != 0 )
{
  BYTE nInputs = (BYTE)GetSystemMetrics( SM_MAXIMUMTOUCHES );
  if ( LoadTouchFuncs() )
  {
    if ( !RegisterTouchWindow_Ptr(h, 0) )
    {
      LOGI( "Enabled, num points: %d\n", (int)nInputs );
      g_TouchEnabled = true;
      break;
    }
  }
}
```

然后，我们在`Viewport_ProcessMotion()`函数中获取一系列触摸事件。

## 还有更多...

Windows 8 引入了`WM_POINTER`消息，这确保了代码更加整洁，类似于 Android 和其他基于触摸的环境。感兴趣的读者可以阅读相应的 MSDN 文章（[`msdn.microsoft.com/en-us/library/hh454928(v=vs.85).aspx`](http://msdn.microsoft.com/en-us/library/hh454928(v=vs.85).aspx)），并在窗口函数中编写类似的处理程序。

## 另请参阅

`1_MultitouchInput`示例中包含了`WM_TOUCH`消息处理代码。下一个食谱将展示如何解码一系列的多点触控事件并识别一些基本的手势。

# 识别手势

在这个食谱中，我们实现了一个检测捏合缩放旋转和 fling/swipe 手势的函数。它可以作为识别您自定义手势的起点。

## 准备工作

本食谱依赖于本章中的*在 Android 上处理多点触控事件*食谱来处理多点触控输入。

## 如何操作...

1.  我们将运动解码任务分解为各个层次。低级代码处理操作系统生成的触摸事件。收集到的触摸点数据由中级代码中的一组例程处理，我们将在本食谱中介绍这些内容。最后，所有解码的手势都通过简单的`iGestureResponder`接口报告给用户的高级代码：

    ```kt
    class iGestureResponder
    {
    public:
    ```

1.  `Event_UpdateGesture()`方法提供了直接访问接触点当前状态的功能。在讨论了`iGestureResponder`之后，紧接着介绍了`sMotionData`结构。`1_MultitouchInput`示例重写了这个方法来渲染触摸点：

    ```kt
      virtual void Event_UpdateGesture( const sMotionData& Data ) {}
    ```

1.  `Event_PointerChanged()`和`Event_PointerMoved()`方法被调用，以指示单个触摸的变化：

    ```kt
      virtual void Event_PointerChanged(int PtrID,const vec2& Pnt, bool Pressed) {}
      virtual void Event_PointerMoved(int PtrID, const vec2&const vec2& Pnt){}
    ```

1.  解码的手势信息被发送到`iGestureResponder`实例。当 fling/swipe 事件结束时，会调用`Event_Fling()`方法：

    ```kt
      virtual void Event_Fling( const sTouchPoint& Down,const sTouchPoint& Up ) {}
    ```

1.  使用`Up`和`Down`点的时间戳，响应者可以估计手指移动的速度并决定手势是否成功。当手指在屏幕上拖动时，会调用`Event_Drag()`方法：

    ```kt
      virtual void Event_Drag( const sTouchPoint& Down,const sTouchPoint& Current ) {}
    ```

1.  捏合缩放事件通过三种方法处理。当手势开始时调用`Event_PinchStart()`方法，手势结束时调用`Event_PinchStop()`，每次更新两个触摸点时调用`Event_Pinch()`方法：

    ```kt
      virtual void Event_PinchStart( const sTouchPoint& Initial1,const sTouchPoint& Initial2 ) {}
      virtual void Event_Pinch( const sTouchPoint& Initial1,const sTouchPoint& Initial2,const sTouchPoint& Current1,const sTouchPoint& Current2 ) {}
      virtual void Event_PinchStop( const sTouchPoint& Initial1,const sTouchPoint& Initial2,const sTouchPoint& Current1,const sTouchPoint& Current2 ) {};
    };
    ```

1.  让我们转到中级例程来解码手势。首先，声明一个`iGestureResponder`的实例，稍后使用：

    ```kt
      iGestureResponder* g_Responder;
    ```

1.  我们引入了`sMotionData`结构，它描述了当前的手势状态。使用`Get*`函数访问单个触摸点的特征。`AddTouchPoint()`函数确保不会添加具有重复 ID 的点：

    ```kt
    struct sMotionData
    {
      sMotionData(): FTouchPoints() {};
      void Clear() { FTouchPoints.clear(); };
      size_t GetNumTouchPoints() const { returnFTouchPoints.size(); }
      const sTouchPoint& GetTouchPoint( size_t Idx )    const {return FTouchPoints[Idx]; }
      vec2 GetTouchPointPos(size_t i) const { returnFTouchPoints[i].FPoint; }
      int GetTouchPointID(size_t i)  const { returnFTouchPoints[i].FID; }
      void AddTouchPoint( const sTouchPoint& TouchPoint )
      {
        for ( size_t i = 0; i != FTouchPoints.size(); i++ )
          if ( FTouchPoints[i].FID == TouchPoint.FID )
          {
            FTouchPoints[i] = TouchPoint;
            return;
          }
        FTouchPoints.push_back( TouchPoint );
      }
    private:
      std::vector<sTouchPoint> FTouchPoints;
    };
    ```

1.  手势由其触摸点的当前状态和先前触摸点状态的环形缓冲区描述。为了检测手势，我们创建了一个临时的状态机。两个布尔变量指示我们是否真的有手势以及手势是否正在进行中。对于每种类型的手势，也存储有效性标志：

    ```kt
    sMotionData                 FMotionData;
    RingBuffer<sMotionData>     FPrevMotionData(5);
    bool FMotionDataValid = false;
    bool FMoving = false;
    bool FFlingWasValid = false;
    bool FPinchZoomValid = false;
    bool FPinchZoomWasValid = false;
    ```

1.  单指手势，如抛掷、拖拽或轻触，由当前点和初始点描述。捏合缩放是双指手势，其状态由两个初始点和两个当前点确定。中心点坐标是初始点和当前点坐标的平均值：

    ```kt
    sTouchPoint FInitialPoint( 0, LVector2(), MOTION_MOVE, 0.0 );
    sTouchPoint FCurrentPoint( 0, LVector2(), MOTION_MOVE, 0.0 );
    sTouchPoint FInitialPoint1, FInitialPoint2;
    sTouchPoint FCurrentPoint1, FCurrentPoint2;
    float FZoomFactor = 1.0f;
    float FInitialDistance = 1.0f;
    LVector2 FInitialCenter, FCurrentCenter;
    ```

1.  为了忽略意外的屏幕触摸，我们引入了一个灵敏度阈值，这是手指必须移动的最小屏幕空间百分比，以便检测到抛掷手势：

    ```kt
      float FlingStartSensitivity = 0.2f;
    ```

1.  如果手指最终位置相对于初始位置移动小于以下值，那么抛掷手势将被完全忽略：

    ```kt
      float FlingThresholdSensitivity = 0.1f;
    ```

1.  `RingBuffer`数据结构是使用一个简单的动态数组实现的。完整的源代码在`RingBuffer.h`文件中：

    ```kt
    template <typename T> class RingBuffer
    {
    public:
      explicit RingBuffer(size_t Num): FBuffer(Num) { clear(); }
      inline void clear() { FCount = FHead  = 0; }
      inline void push_back( const T& Value )
      {
        if ( FCount < FBuffer.size() ) FCount++;
        FBuffer[ FHead++ ] = Value;
        if ( FHead == FBuffer.size() ) FHead = 0;
      }
    ```

1.  唯一的特殊方法是相对于`FHead`的先前状态的访问器：

    ```kt
      inline T* prev(size_t i)
      { return (i >= FCount) ? NULL: &FBuffer[AdjustIndex(i)]; }
    private:
      std::vector<T> FBuffer;
    ```

1.  当前元素和项目总数：

    ```kt
      size_t FHead;
      size_t FCount;
    ```

1.  负值时的带环绕的除法余数：

    ```kt
      inline int ModInt( int a, int b )
      { int r = a % b; return ( r < 0 ) ? r+b : r; }
    ```

1.  最后一个例程计算前一个元素索引：

    ```kt
      inline size_t AdjustIndex( size_t i ) const
      {
        return (size_t)ModInt( (int)FHead - (int)i - 1,(int)FBuffer.size() );
      }
    };
    ```

1.  为了解码手势，我们仔细处理每一个触摸事件。在开始时我们重置触摸点集合，在触摸结束时我们检查手势是否完成：

    ```kt
    void GestureHandler_SendMotion( int ContactID, eMotionFlagFlag,LVector2 Pos, bool Pressed )
    {
      if ( ContactID == MOTION_START )
      {
        FMotionDataValid = false;
        FMotionData.Clear();
        return;
      }
      if ( ContactID == MOTION_END )
      {
        FMotionDataValid = true;
        UpdateGesture();
        g_Responder->Event_UpdateGesture( FMotionData );
        if ( sMotionData* P = FPrevMotionData.prev(0) )
        {
          if ( P->GetNumTouchPoints() !=FMotionData.GetNumTouchPoints() )FPrevMotionData.push_back( FMotionData );
        }
        else
        {
          FPrevMotionData.push_back( FMotionData );
        }
        return;
      }
    ```

1.  如果我们仍在移动，那么修改当前点的信息：

    ```kt
      if ( Pressed )
        FMotionData.AddTouchPoint( sTouchPoint( ContactID, Pos,MOTION_DOWN, Env_GetSeconds() ) );
    ```

1.  根据运动标志，我们通知响应者关于个别触摸的信息：

    ```kt
      switch ( Flag )
      {
        case MOTION_MOVE:
          g_Responder->Event_PointerMoved( ContactID, Pos );
          break;
        case MOTION_UP:
        case MOTION_DOWN:
          g_Responder->Event_PointerChanged( ContactID, Pos,Flag == MOTION_DOWN );
          break;
      }
    }
    ```

1.  `UpdateGesture()`函数负责所有的检测工作。它会检查当前的手势状态，并在有手势进行中的时候调用`g_Responder`对象的方法：

    ```kt
    void UpdateGesture()
    {
      const sTouchPoint& Pt1 = FInitialPoint;
      const sTouchPoint& Pt2 = FCurrentPoint;
      g_Responder->Event_UpdateGesture( FMotionData );
    ```

1.  拖拽和捏合手势通过`IsDraggingValid()`和`IsPinchZoomValid()`方法进行检查，这些方法稍后会进行描述。如果手指移动超过特定距离，我们会响应单点拖拽：

    ```kt
      if ( IsDraggingValid() )
      {
        if ( GetPositionDelta().Length() >FlingThresholdSensitivity )
        {
          g_Responder->Event_Drag( Pt1, Pt2 );
          FFlingWasValid = true;
        }
      }
    else if ( FFlingWasValid )
      {
        if ( GetPositionDelta().Length() >FlingStartSensitivity )
          g_Responder->Event_Fling( Pt1, Pt2 );
        else
          g_Responder->Event_Drag( Pt1, Pt2 );
        FFlingWasValid = false;
      }
      if ( IsPinchZoomValid() )
      {
        if ( FPinchZoomWasValid )
          g_Responder->Event_Pinch( FInitialPoint1,FInitialPoint2, FCurrentPoint1,FCurrentPoint2 );
        else
          g_Responder->Event_PinchStart( FInitialPoint1,FInitialPoint2 );
        FPinchZoomWasValid = true;
      }
      else if ( FPinchZoomWasValid )
      {
        FPinchZoomWasValid = false;
        g_Responder->Event_PinchStop( FInitialPoint1,FInitialPoint2, FCurrentPoint1, FCurrentPoint2 );
      }
    }
    ```

1.  之前描述的`UpdateGesture()`函数使用了以下辅助函数：

    ```kt
    static vec2 GetPositionDelta()
    { return FCurrentPoint.FPoint - FInitialPoint.FPoint; }
    ```

1.  拖拽或抛掷动作应该用一根手指完成。为了区分拖拽和抛掷，我们使用`IsDraggingValid()`函数：

    ```kt
    static bool IsDraggingValid()
    {
      if ( FMotionDataValid && FMotionData.GetNumTouchPoints() == 1&& FMotionData.GetTouchPointID( 0 ) == 0 )
      {
        if ( !FMoving )
        {
          FMoving       = true;
          FInitialPoint = FMotionData.GetTouchPoint( 0 );
          return false;
        }
        FCurrentPoint = FMotionData.GetTouchPoint( 0 );
      }
      else
      {
      FMoving = false;
      }
      return FMoving;
    }
    ```

1.  为了检查用户是否正在执行捏合缩放手势，我们调用`IsPinchZoomValid()`函数。我们获取触摸点并计算它们之间的距离。如果我们已经在执行捏合缩放手势，我们更新当前点。否则，我们存储初始点并计算中心：

    ```kt
    static bool IsPinchZoomValid()
    {
      if (FMotionDataValid && FMotionData.GetNumTouchPoints() == 2 )
      {
        const sTouchPoint& Pt1 = FMotionData.GetTouchPoint(0);
        const sTouchPoint& Pt2 = FMotionData.GetTouchPoint(1);
        const LVector2& Pos1(FMotionData.GetTouchPointPos(0));
        const LVector2& Pos2(FMotionData.GetTouchPointPos(1));
        float NewDistance = (Pos1 - Pos2).Length();
        if ( FPinchZoomValid )
        {
          FZoomFactor    = NewDistance / FInitialDistance;
          FCurrentPoint1 = Pt1;
          FCurrentPoint2 = Pt2;
          FCurrentCenter = ( Pos1 + Pos2 ) * 0.5f;
        }
        else
        {
          FInitialDistance = NewDistance;
          FPinchZoomValid  = true;
          FZoomFactor      = 1.0f;
          FInitialPoint1   = Pt1;
          FInitialPoint2   = Pt2;
          FInitialCenter = ( Pos1 + Pos2 ) * 0.5f;
          return false;
        }
      }
      else
      {
        FPinchZoomValid = false;
        FZoomFactor     = 1.0f;
      }
      return FPinchZoomValid;
    }
    ```

## 它的工作原理...

`g_Responder`实例接收所有关于解码手势的数据。

# 实现屏幕上的游戏手柄

是时候利用多点触控功能，在 Android 设备触摸屏上模拟类似游戏控制台界面了。

## 准备就绪

在继续这个食谱之前，先学习如何处理来自*在 Android 上处理多点触控事件*和*在 Windows 上处理多点触控事件*的食谱的多点触控输入。

## 如何操作...

我们实现了一个自定义的多点触控事件处理器，它跟踪所有的触控点。游戏手柄被渲染成左侧的全屏位图。当用户触摸屏幕时，我们使用触摸坐标从图右侧的遮罩中获取像素颜色。然后，我们找到与颜色对应的内部按钮并改变其`Pressed`状态。下图展示了游戏手柄的可视表示和颜色遮罩：

![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-gm-dev-cb/img/7785_07_1.jpg)

1.  我们虚拟游戏手柄的单个按钮由其在遮罩中的颜色和在按钮表中的索引确定：

    ```kt
    struct sBitmapButton
    {
      vec4 FColour;
      int FIndex;
    };
    ```

1.  虚拟模拟杆支持两个方向，由其半径、遮罩颜色和位置确定：

    ```kt
    struct sBitmapAxis
    {
      float FRadius;
      vec2 FPosition;
      int FAxis1, FAxis2;
      vec4 Fcolour;
    };
    ```

1.  `ScreenJoystick`类包含了所有按钮和轴的描述：

    ```kt
    class ScreenJoystick
    {
      std::vector<sBitmapButton> FButtonDesc;
      std::vector<sBitmapAxis> FAxisDesc;
    ```

1.  每个轴的值和每个按钮的`Pressed`标志存储在两个数组中：

    ```kt
      std::vector<float> FAxisValue;
      std::vector<bool> FKeyValue;
    ```

1.  这个类还需要遮罩位图数据指针：

    ```kt
      unsigned char* FMaskBitmap;
    ```

1.  `FPushed*`数组告诉我们当前哪些按钮和轴被激活了：

    ```kt
      sBitmapButton* FPushedButtons[MAX_TOUCH_CONTACTS];
      sBitmapAxis*   FPushedAxis[MAX_TOUCH_CONTACTS];
    ```

1.  构造函数和析构函数本质上是空的：

    ```kt
      ScreenJoystick(): FMaskBitmap( NULL ) {}
      virtual ~ScreenJoystick() {}
    ```

1.  `InitKeys()`方法在游戏手柄构造完成后分配状态数组：

    ```kt
      void InitKeys()
      {
        FKeyValue.resize( FButtonDesc.size() );
        if ( FKeyValue.size() > 0 )
        {
          for (size_t j = 0 ; j < FKeyValue.size() ; j++ )
            FKeyValue[j] = false;
    }
        FAxisValue.resize( FAxisDesc.size() * 2 );
        if ( FAxisValue.size() > 0 )
        {
          memset( &FAxisValue[0], 0, FAxisValue.size() *sizeof( float ) );
        }
        Restart();
      }
    ```

1.  `Restart()`方法清除被按下按钮的状态：

    ```kt
      void Restart()
      {
        memset( &FPushedAxis[0], 0, sizeof(sBitmapAxis*) *MAX_TOUCH_CONTACTS );
        memset( &FPushedButtons[0], 0, sizeof(sBitmapButton*) *MAX_TOUCH_CONTACTS );
      }
    ```

1.  内部状态由私有的`SetAxisValue()`和`SetKeyState()`方法改变：

    ```kt
      void SetKeyState( int KeyIdx, bool Pressed )
      {
        if ( KeyIdx < 0 || KeyIdx >= ( int )FKeyValue.size() )
      { return; }
        FKeyValue[KeyIdx] = Pressed;
      }
      void SetAxisValue( int AxisIdx, float Val )
      {
        if ( ( AxisIdx < 0 ) ||AxisIdx >= (int)FAxisValue.size() )
      { return; }
        FAxisValue[AxisIdx] = Val;
      }
    ```

1.  `IsPressed()`和`GetAxisValue()`方法可以读取一个键或轴的状态：

    ```kt
      bool IsPressed( int KeyIdx ) const
      {
        return ( KeyIdx < 0 ||KeyIdx >= ( int )FKeyValue.size() ) ?false : FKeyValue[KeyIdx];
      }
      float GetAxisValue( int AxisIdx ) const
      {
        return ( ( AxisIdx < 0 ) ||AxisIdx >= ( int )FAxisValue.size() ) ?0.0f : FAxisValue[AxisIdx];
      }
    ```

1.  下面的内部方法通过给定的颜色查找按钮和轴：

    ```kt
      sBitmapButton* GetButtonForColour( const vec4& Colour )const
      {
        for ( size_t k = 0 ; k < FButtonDesc.size(); k++ )
        {
          float Distance = (FButtonDesc[k]->FColour –Colour).Length();
          if ( Distance < 0.1f ) return FButtonDesc[k];
        }
        return NULL;
      }

      sBitmapAxis* GetAxisForColour( const vec4& Colour ) const
      {
        for ( size_t k = 0 ; k < FAxisDesc.size(); k++ )
        {
          float Distance = (FButtonDesc[k]->FColour –Colour).Length();
          if ( Distance < 0.1f ) return FAxisDesc[k];
        }
        return NULL;
      }
    ```

1.  每个轴的两个值作为从中心点的位移读取：

    ```kt
      void ReadAxis( sBitmapAxis* Axis, const vec2& Pos )
      {
        if ( !Axis ) { return; }
    ```

1.  根据中心点和触摸点读取轴值：

    ```kt
        float v1 = ( (Axis->FPosition - Pos).x/Axis->FRadius);
        float v2 = (-(Axis->FPosition - Pos).y/Axis->FRadius);
        this->SetAxisValue( Axis->FAxis1, v1 );
        this->SetAxisValue( Axis->FAxis2, v2 );
      }
      vec4 GetColourAtPoint( const vec2& Pt ) const
      {
        if ( !FMaskBitmap ) { return vec4( -1 ); }
        int x = (int)(Pt.x * 512.0f);
        int y = (int)(Pt.y * 512.0f);
        int Ofs = (y * 512 + x) * 3;
        float r = (float)FMaskBitmap[Ofs + 0] / 255.0f;
        float g = (float)FMaskBitmap[Ofs + 1] / 255.0f;
        float b = (float)FMaskBitmap[Ofs + 2] / 255.0f;
        return vec4( b, g, r, 0.0f );
      }
    ```

1.  主例程是`HandleTouch()`方法：

    ```kt
    void HandleTouch( int ContactID, const vec2& Pos, bool Pressed,
      eMotionFlag Flag )
    {
    ```

1.  如果触摸刚刚开始，我们重置每个按钮和轴的值：

    ```kt
      if ( ContactID == MOTION_START )
      {
        for ( size_t i = 0; i != MAX_TOUCH_CONTACTS; i++ )
        {
          if ( FPushedButtons[i] )
          {
            this->SetKeyState(
              FPushedButtons[i]->FIndex, false );
            FPushedButtons[i] = NULL;
          }
          if ( FPushedAxis[i] )
          {
            this->SetAxisValue(
              FPushedAxis[i]->FAxis1, 0.0f );
            this->SetAxisValue(
              FPushedAxis[i]->FAxis2, 0.0f );
            FPushedAxis[i] = NULL;
          }
        }
        return;
      }
      if ( ContactID == MOTION_END ) { return; }
      if ( ContactID < 0 || ContactID >= MAX_TOUCH_CONTACTS )
      { return; }
    ```

1.  如果指针正在移动，我们查找相应的按钮或轴：

    ```kt
      if ( Flag == MOTION_DOWN || Flag == MOTION_MOVE )
      {
        vec4 Colour = GetColourAtPoint( Pos );
        sBitmapButton* Button = GetButtonForColour( Colour );
        sBitmapAxis*     Axis = GetAxisForColour( Colour );
    ```

1.  对于我们找到的每个按钮，将按下状态设置为真：

    ```kt
        if ( Button && Pressed )
        {
          int Idx = Button->FIndex;
          this->SetKeyState( Idx, true );
          FPushedButtons[ContactID] = Button;
        }
    ```

1.  对于找到的每个轴，我们读取其值：

    ```kt
        if ( Axis && Pressed )
        {
          this->ReadAxis( Axis,  Pos );
          FPushedAxis[ContactID] = Axis;
        }
      }
    }
    ```

## 工作原理...

我们声明了一个全局变量，它保存了游戏手柄的状态：

```kt
ScreenJoystick g_Joystick;
```

在`OnStart()`方法中，我们添加两个轴和一个按钮：

```kt
  float A_Y = 414.0f / 512.0f;

  sBitmapAxis B_Left;
  B_Left.FAxis1 = 0;
  B_Left.FAxis2 = 1;
  B_Left.FPosition = vec2( 55.0f / 512.f, A_Y );
  B_Left.FRadius = 40.0f / 512.0f;
  B_Left.FColor = vec4( 0.75f, 0.75f, 0.75f, 0.0f );

  sBitmapButton B_Fire;
  B_Fire.FIndex = ID_BUTTON_THRUST;
  B_Fire.FColor = vec4( 0 );
  g_Joystick.FAxisDesc.push_back( B_Left );
  g_Joystick.FButtonDesc.push_back( B_Fire );
```

然后，我们初始化游戏手柄并重置其状态：

```kt
  g_Joystick.InitKeys();
  g_Joystick.Restart();
```

在代码稍后部分，我们可以使用`g_Joystick.GetAxisValue`的结果来获取当前的轴值，以及使用`g_Joystick.IsPressed`来查看按键是否被按下。

# 使用 FreeType 进行文本渲染

界面可能避免渲染文本信息。然而，大多数应用程序必须在屏幕上显示一些文本。现在是详细考虑带字符间距和字形缓存的**FreeType**文本渲染的时候了。这是本书最长的食谱，但我们确实不希望错过 FreeType 使用中的细节和微妙之处。

## 准备就绪

现在是时候将本书第二章《移植通用库》中关于 FreeType 编译的实际应用提上日程了。我们从第一章*建立构建环境*中描述的空应用程序模板开始。以下代码支持多种字体、自动字距调整和字形缓存。

> *在排版中，字距调整（较少见的是嵌槽）是调整比例字体中字符间间距的过程，通常是为了达到视觉上令人满意的效果。*

致谢：[`en.wikipedia.org/wiki/Kerning`](http://en.wikipedia.org/wiki/Kerning)

字形缓存是 FreeType 库的一个特性，它通过使用字形图像和字符图来减少内存使用。你可以阅读关于它的内容在[`www.freetype.org/freetype2/docs/reference/ft2-cache_subsystem.html`](http://www.freetype.org/freetype2/docs/reference/ft2-cache_subsystem.html)。

## 如何操作...

在这里我们开发了`TextRenderer`类，它保存了 FreeType 库的所有状态。我们将文本渲染封装在一个类中以支持此类多个实例，并确保线程安全。

1.  所需的 FreeType 库初始化包括库实例、字形缓存、字符图缓存和图像缓存。我们首先声明内部的 FreeType 对象：

    ```kt
    class TextRenderer
    {
      // Local instance of the library (for thread-safeexecution)
      FT_Library FLibrary;
      // Cache manager
      FTC_Manager FManager;
      // Glyph cache
      FTC_ImageCache FImageCache;
      // Character map cache
      FTC_CMapCache FCMapCache;
    ```

1.  然后声明已加载字体的列表：

    ```kt
      // List of available font faces
      std::vector<std::string> FFontFaces;
      // Handle for the current font face
      FT_Face FFace;
      // List of loaded font files to prevent multiple filereads
      std::map<std::string, void*> FAllocatedFonts;
      // List of initialized font face handles
      std::map<std::string, FT_Face> FFontFaceHandles;
    ```

1.  `FMaskMode`开关用于选择不透明渲染和 alpha 遮罩创建。它稍后在字形渲染代码中提到：

    ```kt
      bool FMaskMode;
    ```

1.  初始化例程创建 FreeType 库实例并初始化字形和图像缓存：

    ```kt
    void InitFreeType()
    {
      LoadFT();
      FT_Init_FreeTypePTR( &FLibrary );
      FTC_Manager_NewPTR(FLibrary,0,0,0,
        FreeType_Face_Requester, this, &FManager);
      FTC_ImageCache_NewPTR( FManager, &FImageCache );
      FTC_CMapCache_NewPTR( FManager, &FCMapCache );
    }
    ```

    与往常一样，我们提供了尽可能简短的代码。完整的代码应该检查`FTC_*`函数返回的非零代码。`LoadFT()`函数初始化 FreeType 库的函数指针。在本书的代码中，为了允许在 Windows 上动态加载库，我们为所有 FreeType 函数使用了`PTR`后缀。如果你只关心 Android 开发，可以省略`PTR`后缀。

1.  反初始化例程清除所有内部数据并销毁 FreeType 对象：

    ```kt
    void StopFreeType()
    {
      FreeString();
      auto p = FAllocatedFonts.begin();
      for ( ; p!= FAllocatedFonts.end() ; p++ )
        delete[] ( char* )( p->second );
      FFontFaces.clear();
      FTC_Manager_DonePTR( FManager );
      FT_Done_FreeTypePTR( FLibrary );
    }
    ```

1.  `FreeString()`例程清除内部 FreeType 字形缓存：

    ```kt
    void FreeString()
    {
      for ( size_t i = 0 ; i < FString.size() ; i++ )
        if ( FString[i].FCacheNode != NULL )
          FTC_Node_UnrefPTR(FString[i].FCacheNode,FManager);
      FString.clear();
    }
    ```

1.  `FString`包含正在渲染的字符串的所有字符。初始化和反初始化函数分别在构造函数和析构函数中调用：

    ```kt
    TextRenderer(): FLibrary( NULL ), FManager( NULL ),FImageCache( NULL ), FCMapCache( NULL )
    {
      InitFreeType();
      FMaskMode = false;
    }
    virtual ~clTextRenderer() { StopFreeType(); }
    ```

1.  为了利用**TrueType**字体并渲染字形，我们需要创建一组简单的管理例程来加载字体文件。第一个是`LoadFontFile()`函数，它加载字体文件，将其内容存储在列表中，并返回错误代码：

    ```kt
    FT_ErrorLoadFontFile( const std::string& File )
    {
      if ( FAllocatedFonts.count( File ) > 0 ) { return 0; }
      char* Data = NULL;
      int DataSize;
      ReadFileData( File.c_str(), &Data, DataSize );
      FT_Face TheFace;
    ```

1.  我们总是使用第 0 个面，这是加载文件中的第一个：

    ```kt
      FT_Error Result = FT_New_Memory_FacePTR(FLibrary,(FT_Byte*)Data, (FT_Long)DataSize, 0, &TheFace );
    ```

1.  检查是否成功并将字体存储在已加载字体面的数组中：

    ```kt
      if ( Result == 0 )
      {
        FFontFaceHandles[File] = TheFace;
        FAllocatedFonts[File] = ( void* )Data;
        FFontFaces.push_back( File );
      }
      return Result;
    }
    ```

    `ReadFileData()`函数加载`File`的内容。鼓励您实现此功能或查看随附的源代码，其中通过我们的虚拟文件系统完成此操作。

1.  静态函数`FreeType_Face_Requester()`缓存对字体面的访问，并允许我们重用已加载的字体。它在 FreeType 库头文件中定义：

    ```kt
    FT_Error FreeType_Face_Requester( FTC_FaceID FaceID,FT_Library Library, FT_Pointer RequestData, FT_Face* Face )
    {
    #ifdef _WIN64
      long long int Idx = (long long int)FaceID;
      int FaceIdx = (int)(Idx & 0xFF);
    #else
      int FaceIdx = reinterpret_cast< int >(FaceID);
    #endif
      if ( FaceIdx < 0 ) { return 1; }
      TextRenderer* Renderer = ( TextRenderer* )RequestData;
      std::string File = Renderer ->FFontFaces[FaceIdx];
      FT_Error Result = Renderer ->LoadFontFile( File );
      *Face = (Result == 0) ?
      Renderer->FFontFaceHandles[File] : NULL;
      return Result;
    }
    ```

    FreeType 库允许`RequestData`参数，我们通过指针传递`TextRenderer`的实例。在`FreeType_Face_Requester()`代码中的`#ifdef`是必要的，以便在 64 位 Windows 版本上运行。Android OS 是 32 位的，允许将`void*`隐式地转换为`int`。

1.  `GetSizedFace`函数为已加载的面设置字体大小：

    ```kt
    FT_Face GetSizedFace( int FontID, int Height )
    {
      FTC_ScalerRec Scaler;
      Scaler.face_id = IntToID(FontID);
      Scaler.height = Height;
      Scaler.width = 0;
      Scaler.pixel = 1;
      FT_Size SizedFont;
      if ( !FTC_Manager_LookupSizePTR(FManager, &Scaler,&SizedFont) ) return NULL;
      if ( FT_Activate_SizePTR( SizedFont ) != 0 ) { returnNULL; }
      return SizedFont->face;
    }
    ```

1.  然后，我们定义内部的`sFTChar`结构体，它保存有关单个字符的信息：

    ```kt
    struct sFTChar
    {
      // UCS2 character, suitable for FreeType
      FT_UInt FChar;
      // Internal character index
      FT_UInt FIndex;
      // Handle for the rendered glyph
      FT_Glyph FGlyph;
      // Fixed-point character advance and character size
      FT_F26Dot6 FAdvance, FWidth;
      // Cache node for this glyph
      FTC_Node FCacheNode;
      // Default parameters
      sFTChar(): FChar(0), FIndex((FT_UInt)(-1)), FGlyph(NULL),FAdvance(0), FWidth(0), FCacheNode( NULL ) { }
    };
    ```

1.  我们渲染的文本采用 UTF-8 编码，必须将其转换为 UCS-2 多字节表示。最简单的 UTF-8 解码器读取输入字符串并将其字符输出到`FString`向量中：

    ```kt
    bool DecodeUTF8( const char* InStr )
    {
      FIndex = 0;
      FBuffer = InStr;
      FLength = ( int )strlen( InStr );
      FString.clear();
      int R = DecodeNextUTF8Char();
      while ( ( R != UTF8_LINE_END ) && ( R != UTF8_DECODE_ERROR ) )
      {
        sFTChar Ch;
        Ch.FChar    = R;
        FString.push_back( Ch );
        R = DecodeNextUTF8Char();
      }
      return ( R != UTF8_DECODE_ERROR );
    }
    ```

1.  解码器使用以下函数来读取单个字符编码：

    ```kt
    int DecodeNextUTF8Char()
    {
      // the first byte of the character and the result
      int c, r;
      if ( FIndex >= FLength )
        return FIndex == FLength ?UTF8_LINE_END : UTF8_DECODE_ERROR;
      c = NextUTF8();
      if ( ( c & 0x80 ) == 0 ) { return c; }
      if ( ( c & 0xE0 ) == 0xC0 )
      {
        int c1 = ContUTF8();
        if ( c1 < 0 ) { return UTF8_DECODE_ERROR; }
        r = ( ( c & 0x1F ) << 6 ) | c1;
        return r >= 128 ? r : UTF8_DECODE_ERROR;
      }
      if ( ( c & 0xF0 ) == 0xE0 )
      {
        int c1 = ContUTF8(), c2 = ContUTF8();
        if ( c1 < 0 || c2 < 0 ) { return UTF8_DECODE_ERROR; }
        r = ( ( c & 0x0F ) << 12 ) | ( c1 << 6 ) | c2;
        return r>=2048&&(r<55296||r>57343)?r:UTF8_DECODE_ERROR;
      }
      if ( ( c & 0xF8 ) == 0xF0 )
      {
        int c1 = ContUTF8(), c2 = ContUTF8(), c3 = ContUTF8();
        if (c1 < 0||c2 < 0||c3< 0) { return UTF8_DECODE_ERROR; }
        r = (( c & 0x0F ) << 18) | (c1 << 12) | (c2 << 6) | c3;
        return r>=65536 && r<=1114111 ? r: UTF8_DECODE_ERROR;
      }
      return UTF8_DECODE_ERROR;
    }
    ```

    ### 注意

    `DecodeNextUTF8Char()`的源代码取自 Linderdaum Engine，位于[`www.linderdaum.com`](http://www.linderdaum.com)。

1.  `NextUTF8()`和`ContUTF8()`内联函数在解码缓冲区旁边声明：

    ```kt
      static const int UTF8_LINE_END = 0;
      static const int UTF8_DECODE_ERROR = -1;
    ```

1.  包含当前字符串的缓冲区：

    ```kt
      std::vector<sFTChar> FString;
    ```

1.  当前字符索引和源缓冲区长度：

    ```kt
      int FIndex, FLength;
    ```

1.  源缓冲区的原始指针和当前字节：

    ```kt
      const char* FBuffer;
      int  FByte;
    ```

1.  如果没有剩余的字节，则获取下一个字节或`UTF8_LINE_END`：

    ```kt
      inline int NextUTF8()
      {
        return ( FIndex >= FLength ) ?
          UTF8_LINE_END : ( FBuffer[FIndex++] & 0xFF );
      }
    ```

1.  获取下一个延续字节的低六位，如果它不是延续字节，则返回`UTF8_DECODE_ERROR`：

    ```kt
      inline int ContUTF8()
      {
        int c = NextUTF8();
        return ( ( c & 0xC0 ) == 0x80 ) ?
          ( c & 0x3F ) : UTF8_DECODE_ERROR;
      }
    ```

1.  到目前为止，我们已经有了字体加载函数和一个 UTF-8 解码器。现在是处理实际渲染的时候了。我们首先想要做的是计算屏幕像素中的字符串大小，这由`CalculateLineParameters`函数执行：

    ```kt
    void CalculateLineParameters(int* Width, int* MinY, int* MaxY, int* BaseLine ) const
    {
    ```

1.  我们使用两个变量来查找最小和最大垂直位置：

    ```kt
      int StrMinY = -1000, StrMaxY = -1000;
      if ( FString.empty() )
        StrMinY = StrMaxY = 0;
    ```

1.  另一个变量存储字符串的水平大小：

    ```kt
      int SizeX = 0;
    ```

1.  我们遍历`FString`数组，并使用`sFTChar::FGlyph`字段来获取字符的垂直大小。同时，我们将`FAdvance`字段加到`SizeX`上，以考虑字距调整和水平字符大小：

    ```kt
      for ( size_t i = 0 ; i != FString.size(); i++ )
      {
        if ( FString[i].FGlyph == NULL ) { continue; }
        auto Glyph = ( FT_BitmapGlyph )FString[i].FGlyph;
        SizeX += FString[i].FAdvance;
        int Y = Glyph->top;
        int H = Glyph->bitmap.rows;
        if ( Y     > StrMinY ) { StrMinY = Y; }
        if ( H - Y > StrMaxY ) { StrMaxY = H - Y; }
      }
      if ( Width    ) { *Width = ( SizeX >> 6 ); }
      if ( BaseLine ) { *BaseLine = StrMaxY; }
      if ( MinY     ) { *MinY = StrMinY; }
      if ( MaxY     ) { *MaxY = StrMaxY; }
    }
    ```

1.  我们使用前面的代码将 UTF-8 字符串渲染到新分配的位图中：

    ```kt
    clPtr<Bitmap> RenderTextWithFont( const std::string& Str,
    	int FontID, int FontHeight,
    	unsigned int Color, bool LeftToRight )
    {
    ```

1.  解码 UTF-8 输入字符串并计算每个字符的位置：

    ```kt
      if ( !LoadTextStringWithFont(Str, FontID, FontHeight) )
      { return NULL; }
    ```

1.  计算水平和垂直字符串尺寸并为输出位图分配空间：

    ```kt
      int W, Y, MinY, MaxY;
      CalculateLineParameters( &W, &MinY, &MaxY, &Y );
      clPtr<Bitmap> Result = new Bitmap( W, MaxY + MinY);
    ```

1.  将所有字形渲染到位图中。如果文本是从右到左的，则从位图的另一侧开始：

    ```kt
      RenderLineOnBitmap( TextString, FontID, FontHeight,
        LeftToRight ? 0 : W - 1, 	MinY, Color, LeftToRight,Result );
      return Result;
    }
    ```

1.  `LoadStringWithFont()`例程负责计算字符串`S`中每个字符的水平位置：

    ```kt
    bool LoadStringWithFont(const std::string& S, int ID, intHeight )
    {
      if ( ID < 0 ) { return false; }
    ```

1.  获取所需的字体面：

    ```kt
      FFace = GetSizedFace( ID, Height );
      if ( FFace == NULL ) { return false; }
      bool UseKerning = FT_HAS_KERNING( Face );
    ```

1.  解码输入的 UTF-8 字符串并计算字符大小，检查`FString`中的每个元素：

    ```kt
      DecodeUTF8( S.c_str() );
      for ( size_t i = 0, count = FString.size(); i != count;i++ )
      {
        sFTChar& Char = FString[i];
        FT_UInt ch = Char.FChar;
        Char.FIndex = ( ch != '\r' && ch != '\n' ) ?GetCharIndex(ID, ch) : -1;
    ```

1.  加载与字符对应的字形：

    ```kt
        Char.FGlyph = ( Char.FIndex != -1 ) ?GetGlyph( ID, Height, ch,FT_LOAD_RENDER, &Char.FCacheNode ) : NULL;
        if ( !Char.FGlyph || Char.FIndex == -1 ) continue;
    ```

1.  计算此字形的水平偏移量：

    ```kt
        SetAdvance( Char );
    ```

1.  计算除第一个字符外的每个字符的间距：

    ```kt
        if (i > 0 && UseKerning) Kern(FString[i - 1], Char);
      }
      return true;
    }
    ```

1.  `LoadStringWithFont()`函数使用辅助例程`Kern()`和`SetAdvance()`来计算两个连续字符之间的偏移量：

    ```kt
    void SetAdvance( sFTChar& Char )
    {
      Char.FAdvance = Char.FWidth = 0;
      if ( !Char.FGlyph ) { return; }
    ```

1.  将值从 26.6 固定小数格式转换：

    ```kt
      Char.FAdvance = Char.FGlyph->advance.x >> 10;
      FT_BBox bbox;
      FT_Glyph_Get_CBoxPTR( Char.FGlyph,FT_GLYPH_BBOX_GRIDFIT, &bbox );
      Char.FWidth = bbox.xMax;
      if ( Char.FWidth == 0 && Char.FAdvance != 0 )
        { Char.FWidth = Char.FAdvance; }
      }
    void Kern( sFTChar& Left, const sFTChar& Right )
    {
      if ( Left.FIndex == -1 || Right.FIndex == -1 )
        { return; }
      FT_Vector Delta;
      FT_Get_KerningPTR( FFace, Left.FIndex, Right.FIndex,FT_KERNING_DEFAULT, &Delta );
      Left.FAdvance += Delta.x;
    }
    ```

1.  最后，一旦我们有了每个字符的位置，我们将各个字形渲染到位图上：

    ```kt
    void RenderLineOnBitmap( const std::string& S,int FontID, int FontHeight, int StartX, int Y,unsigned int C, bool LeftToRight, const clPtr<Bitmap>&Out )
    {
      LoadStringWithFont( S, FontID, FontHeight );
      int x = StartX << 6;
      for ( size_t j = 0 ; j != FString.size(); j++ )
      {
        if ( FString[j].FGlyph != 0 )
        {
          auto Glyph = (FT_BitmapGlyph) FString[j].FGlyph;
          int in_x = (x>>6);
          in_x  += (LeftToRight ? 1 : -1) * BmpGlyph->left;
          if ( !LeftToRight )
          {
            in_x += BmpGlyph->bitmap.width;
            in_x = StartX + ( StartX - in_x );
          }
          DrawGlyph( Out, &BmpGlyph->bitmap, in_x, Y -BmpGlyph->top, Color );
        }
        x += FString[j].FAdvance;
      }
    }
    ```

    `RenderLineOnBitmap()`中的代码相当直接。唯一微妙之处在于位运算移位操作，它将内部的 FreeType 26.6 位固定小数格式转换为标准整数。首先，我们将`StartX`左移以获得 FreeType 的坐标，对于每个像素，我们将`x`右移以获得屏幕位置。

    ### 注意事项

    FreeType 在内部使用 26.6 固定小数格式来定义分数像素坐标。

1.  `DrawGlyph()`例程根据渲染模式，从字形复制原始像素，或者将源像素与字形的像素相乘：

    ```kt
    void DrawGlyph (const clPtr<Bitmap>& Out, FT_Bitmap* Bmp,int X0, int Y0, unsigned int Color )
    {
      unsigned char* Data = Out->FBitmapData;
      int W = Out->FWidth;
      int Width = W - X0;
      if ( Width > Bmp->width ) { Width = Bmp->width; }
      for ( int Y = Y0 ; Y < Y0 + Bmp->rows ; ++Y )
      {
        unsigned char* Src = Bmp->buffer + (Y-Y0)*Bmp->pitch;
        if ( FMaskMode )
        {
          for ( int X = X0 + 0 ; X < X0 + Width ; X++ )
          {
            int Int = *Src++;
            unsigned char Col = (Int & 0xFF);
            for(int j = 0 ; j < 4 ; j++)
              Data[(Y * W + X) * 4 + j]=  Col;
          }
        }
        else
        {
          for ( int X = X0 + 0 ; X < X0 + Width ; X++ )
          {
            unsigned int Col = MultColor(Color, *Src++);
            if ( Int > 0 )
              { ((unsigned int*)Data)[Y * W + X] = Col; }
          }
        }
      }
    }
    ```

1.  辅助`MultColor()`函数将整数编码颜色的每个分量与`Mult`因子相乘：

    ```kt
    unsigned int MultColor( unsigned int C, unsigned int Mult )
    { return (Mult << 24) | C; }
    ```

## 工作原理...

渲染 UTF-8 字符串所需的最小代码涵盖了创建`TextRenderer`实例、字体加载以及使用加载的字体进行实际文本渲染：

```kt
TextRenderer txt;
int fnt = txt.GetFontHandle("some_font.ttf");
```

以葡萄牙语单词*direção*（意为*方向*）为例进行渲染：

```kt
char text[] = { 'D','i','r','e',0xC3,0xA7,0xC3,0xA3,'o',0 };
auto bmp = 
  txt.RenderTextWithFont(text, fnt, 24, 0xFFFFFFFF, true);
```

结果是`bmp`变量，其中包含渲染的文本，如下面的屏幕截图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-gm-dev-cb/img/7785_07_2.jpg)

## 还有更多…

这是迄今为止最长的食谱，但仍然省略了一些重要细节。如果你每帧渲染的文本量足够大，预渲染一些字符串并避免重新创建图像是有意义的。

# 游戏内字符串的本地化

移动应用程序在各种设备上使用，而且这些设备经常配置为使用非英语的语言。本食谱展示了如何在应用程序 UI 中显示文本消息时实现国际化。

## 准备就绪

回顾第四章，*组织虚拟文件系统*，关于使用我们实现的虚拟文件系统抽象进行只读文件访问。

## 如何操作...

1.  对于我们想要支持的每种语言，我们需要准备一组翻译后的字符串。我们将这些字符串存储在一个文件中。对于英文-俄文语言对，一个例子就是`Localizer-ru.txt`文件：

    ```kt
    Hello~Привет
    Good Bye~Пока
    ```

1.  `~`字符用作原始短语与其翻译之间的分隔符。原始短语可以用作键，并与它的翻译一起存储在一个全局的`std::map`容器中：

    ```kt
    std::map<std::string, std::string> g_Translations;
    …
    g_Translations["Original phrase"] = "Translation"
    ```

1.  假设我们有一个全局变量中的地区名称：

    ```kt
    std::string g_LocaleName;
    ```

1.  我们只需要实现使用`g_Translations`映射的`LocalizeString()`函数：

    ```kt
    std::string LocalizeString( const std::string& Str ) const
    {
      auto i = g_Translations.find( Str );
      return (i != g_Translations.end()) ? i->second : Str;
    }
    ```

1.  `LoadLocale()`例程使用全局`g_LocaleName`变量，并加载所需的翻译表，跳过不含`~`字符的行：

    ```kt
    void LoadLocale()
    {
      g_Translations.clear();
      const std::string FileName( g_LocalePath + "/Localizer-"+ g_LocaleName + ".txt" );
      if ( !g_FS->FileExists( FileName ) ) { return; }
      auto Stream = g_FS->CreateReader( FileName );
      while ( !Stream->Eof() )
      {
        std::string L = Stream->ReadLine();
        size_t Pos = L.find( "~" );
        if ( Pos == std::string::npos ) { continue; }g_Translations[ L.substr(0, Pos) ] = L.substr(Pos + 1);
      }
    }
    ```

1.  为了简单起见，我们定义了存储本地化字符串文件的目录，在另一个全局变量中：

    ```kt
    const std::string g_LocalePath = "Localizer";
    ```

## 它是如何工作的...

`LocalizeString()`函数接受基础语言的字符串并返回其翻译。每当我们想要渲染一些文本时，我们不会直接使用字符串字面量，因为这会严重降低我们本地化游戏的能力。相反，我们将这些字面量包装到`LocalizeString()`调用中：

```kt
  PrintString( LocalizeString( "Some text") );
```

## 还有很多...

要以适当的语言渲染文本，我们可以使用操作系统函数来检测其当前地区设置。在 Android 上，我们在`Activity`中使用以下 Java 代码。`SetLocale()`是从`Activity`构造函数中调用的：

```kt
import java.util.Locale;
…
private static void SetLocale()
{
```

检测地区名称并将其传递给我们的本地代码：

```kt
  String Lang    = Locale.getDefault().getLanguage();
  SetLocaleName( Lang );
}
```

在本地代码中，我们只是捕获了地区名称：

```kt
JNIEXPORT void JNICALL
Java_ com_packtpub_ndkcookbook_app14_App14Activity_SetLocaleName(
  JNIEnv* env, jobject obj, jstring LocaleName )
{
g_LocaleName = ConvertJString( env, LocaleName );
}
```

在 Windows 上，事情甚至更简单。我们调用`GetLocaleInfo() WinAPI`函数，并以 ISO639 格式提取当前语言名称（[`en.wikipedia.org/wiki/ISO_639`](http://en.wikipedia.org/wiki/ISO_639)）：

```kt
  char Buf[9];
  GetLocaleInfo( LOCALE_USER_DEFAULT, LOCALE_SISO639LANGNAME,Buf, sizeof(Buf) );
  g_LocaleName = std::string( Buf );
```


# 第八章：编写匹配-3 游戏

在本章中，我们将涵盖：

+   处理异步多点触控输入

+   改进音频播放机制

+   关闭应用程序

+   实现主循环

+   创建多平台游戏引擎

+   编写匹配-3 游戏

+   管理形状

+   管理游戏场地逻辑

+   在游戏循环中实现用户交互

# 简介

在本章中，我们开始将前面章节的食谱整合在一起。以下的大部分食谱旨在改进和整合前面章节中散布的材料。

### 注意

本章节的示例项目实际上是 Google Play 上发布的 MultiBricks 游戏的简化版：[`play.google.com/store/apps/details?id=com.linderdaum.engine.multibricks`](http://play.google.com/store/apps/details?id=com.linderdaum.engine.multibricks)。

# 处理异步多点触控输入

在上一章中，我们学习了如何在 Android 上处理多点触控事件。然而，我们简单的示例有一个严重的问题。Android 的触摸事件是异步发送的，可能会干扰游戏逻辑。因此，我们需要创建一个队列，以可控的方式处理事件。

## 准备就绪

在继续之前，请查看第七章中的“在 Android 上处理多点触控事件”的食谱，*跨平台 UI 和输入系统*。

## 如何操作…

1.  在上一章中，我们直接从异步 JNI 回调中调用触摸处理器：

    ```kt
    Java_com_packtpub_ndkcookbook_game1_Game1Activity_SendMotion(
      JNIEnv * env, jobject obj, int PointerID, int x, int y,
      bool Pressed, int Flag)
      {                        
      LVector2 Pos = LVector2( (float)x / (float)g_Width,
      (float)y / (float)g_Height );
      GestureHandler_SendMotion( PointerID, (eMotionFlag)Flag,
        Pos,Pressed );
    }
    ```

1.  这次，我们需要将所有事件存储在队列中，而不是立即处理它们。队列将持有传递给`GestureHandler_SendMotion()`的结构体中的参数：

    ```kt
    struct sSendMotionData
    {
      int ContactID;
      eMotionFlag Flag;
      LVector2 Pos;
      bool Pressed;
    };
    ```

1.  队列实现依赖于`std::vector`，持有触摸事件和`Mutex`，提供队列访问同步：

    ```kt
    Mutex g_MotionEventsQueueMutex;
    std::vector<sSendMotionData> g_MotionEventsQueue;
    ```

1.  我们新的`SendMotion()` JNI 回调需要做的工作就是将触摸事件参数打包进队列：

    ```kt
    Java_com_packtpub_ndkcookbook_game1_Game1Activity_SendMotion(
      JNIEnv * env, jobject obj, int PointerID, int x, int y,
      bool Pressed, int Flag)
    {                        
      sSendMotionData M;
      M.ContactID = PointerID;
      M.Flag = (eMotionFlag)Flag;
      M.Pos = LVector2( (float)x / (float)g_Width,
        (float)y / (float)g_Height );
      M.Pressed = Pressed;
      LMutex Lock( &g_MotionEventsQueueMutex );
      g_MotionEventsQueue.push_back( M );
    }
    ```

我们现在可以随时处理触摸事件。

## 工作原理…

为了处理队列中的触摸事件，我们扩展了`DrawFrame()` JNI 回调的实现：

```kt
Java_com_packtpub_ndkcookbook_game1_Game1Activity_DrawFrame(
  JNIEnv* env, jobject obj )
{
```

注意在额外的`{}`内的`Lock`变量的作用域。我们需要它，因为必须在继续游戏逻辑之前解锁互斥变量，以防止死锁：

```kt
  {
    LMutex Lock(&g_MotionEventsQueueMutex );
    for( auto m : g_MotionEventsQueue )
    {
      GestureHandler_SendMotion( m.ContactID, m.Flag,
        m.Pos, m.Pressed );
    }
    g_MotionEventsQueue.clear();
  }
  GenerateTicks();
}
```

### 注意

请查看示例`1_Game`中的`jni/Wrappers.cpp`文件，以获取完整的实现，可以从[www.packtpub.com/support](http://www.packtpub.com/support)获取。

## 还有更多…

我们的新方法更加健壮。然而，在`GestureHandler_SendMotion()`内部生成的触摸事件时间戳稍微有些健壮，不再对应于触摸的实际时间。这引入了一个大约等于单帧渲染时间的延迟，在多人游戏中可能成为一个问题。我们将添加真实时间戳的练习留给读者。这可以通过扩展`sSendMotionData`结构体，添加一个时间戳字段来完成，该字段在 JNI 回调`SendMotion()`内部赋值。

## 另请参阅

+   第七章，*跨平台 UI 和输入系统*中的*在 Android 上处理多触摸事件*配方

# 改进音频播放机制

在前面的章节中，我们学习了如何在 Android 上使用 OpenAL 播放音频。我们在第五章，*跨平台音频流*中实现的基本音频子系统缺乏对音频源的自动管理；我们不得不在单独的线程上手动控制它们。现在，我们将把所有这些代码放入一个新的音频子系统中，以便在实际游戏中使用。

## 准备就绪

此配方的完整源代码已集成到示例`1_Game`中，可以在文件`sound/Audio.h`和`sound/Audio.cpp`中找到。`sound`文件夹中的其他文件提供了对不同音频格式的解码能力——可以查看它们。

## 如何操作…

1.  我们需要我们的`clAudioThread`类来处理活动音频源。让我们通过负责注册的方法来扩展它：

    ```kt
    class clAudioThread: public iThread
    {
    public:
    …
      void RegisterSource( clAudioSource* Src );
      void UnRegisterSource( clAudioSource* Src );
    ```

1.  我们还需要一个用于活动源的容器以及控制对其访问的互斥锁：

    ```kt
    private:
    …
      std::vector< clAudioSource* > FActiveSources;
      Mutex FMutex;
    };
    ```

1.  `clAudioThread::Run()`方法变得更加复杂。除了初始化 OpenAL 之外，它还必须更新活动音频源，以便它们可以从提供者那里获取音频数据：

    ```kt
    void clAudioThread::Run()
    {
      if ( !LoadAL() ) { return; }
      FDevice = alcOpenDevice( NULL );
      FContext = alcCreateContext( FDevice, NULL );
      alcMakeContextCurrent( FContext );
      FInitialized = true;
      FPendingExit = false;
      double Seconds = GetSeconds();
    ```

1.  内部循环根据经过的时间更新活动音频源：

    ```kt
      while ( !IsPendingExit() )
      {
        float DeltaSeconds = static_cast<float>(
        GetSeconds() - Seconds );
    ```

1.  注意以下互斥锁的作用域：

    ```kt
        {
          LMutex Lock(&FMutex );
          for( auto i = FActiveSources.begin();
          i != FActiveSources.end(); i++ )
          {
            ( *i )->Update( DeltaSeconds );
          }
        }
        Seconds = GetSeconds();
    ```

1.  音频源每 100 毫秒更新一次。这个值纯粹是经验性的，适用于非实时音频播放，作为音频子系统滞后与 Android 设备功耗之间的折中：

    ```kt
        Env_Sleep( 100 );
      }
      alcDestroyContext( FContext );
      alcCloseDevice( FDevice );
      UnloadAL();
    }
    ```

1.  需要注册方法来维护`FActiveSources`容器。它们的实现可以在以下代码中找到：

    ```kt
    void clAudioThread::RegisterSource( clAudioSource* Src )
    {
      LMutex Lock(&FMutex );
    ```

1.  不要多次添加同一个音频源：

    ```kt
      auto i = std::find( FActiveSources.begin(),
      FActiveSources.end(), Src );
      if ( i != FActiveSources.end() ) return;
      FActiveSources.push_back( Src );
    }
    void clAudioThread::UnRegisterSource( clAudioSource* Src )
    {
      LMutex Lock(&FMutex );
    ```

1.  只需找到源并删除它：

    ```kt
      auto i = std::find( FActiveSources.begin(),
    FActiveSources.end(), Src );
      if ( i != FActiveSources.end() ) FActiveSources.erase( i );
    }
    ```

这个新的`clAudioThread`类的完整实现在示例`1_Game`中的`sound/Audio.cpp`和`sound/Audio.h`文件中可以找到。

## 工作原理…

为了利用新的`AudioThread`类，音频源必须注册自己。我们扩展了`clAudioSource`类的构造函数和析构函数，以执行 RAII 注册（[`en.wikipedia.org/wiki/Resource_Acquisition_Is_Initialization`](http://en.wikipedia.org/wiki/Resource_Acquisition_Is_Initialization)）：

```kt
clAudioSource::clAudioSource()
{
…
  g_Audio.RegisterSource( this );
}

clAudioSource::~clAudioSource()
{
…
  g_Audio.UnRegisterSource( this );
}
```

现在音频播放非常简单。声明一个全局音频线程：

```kt
clAudioThread g_Audio;
```

从主线程开始，等待初始化完成：

```kt
g_Audio.Start( iThread::Priority_Normal );
g_Audio.Wait();
```

### 注意

我们可以在`g_Audio.Start()`和`g_Audio.Wait()`调用之间调用其他有用的初始化例程，以利用异步初始化。

创建并配置一个新的音频源并播放它：

```kt
Music = new clAudioSource();
Music->BindWaveform(new
clModPlugProvider( LoadFileAsBlob("test.xm")) );
Music->LoopSound( true );
Music->Play();
```

所有的音频管理现在都在另一个线程上完成。

## 还有更多…

我们的音频线程能够播放不同类型的音频文件，如`.ogg`，`.xm`，`.it`和`.s3m`文件。你可以通过向`AudioSource`添加另一个方法来隐藏适当 wavedata 提供者的创建。只需根据文件扩展名切换选择以创建`ModPlugProvider`或`OggProvider`实例。我们把这个作为一个练习留给你。

## 另请参阅

+   在第五章，*跨平台音频流*中的*初始化 OpenAL 和播放.wav 文件*，*解码 Ogg Vorbis 文件*，*使用 ModPlug 解码跟踪器音乐*，以及*流式声音*食谱

# 关闭应用程序

智能手机的电池非常有限，这使得移动设备对任何后台活动都非常敏感。我们之前的应用示例在用户切换到另一个活动后仍然保持运行。这意味着我们没有尊重 Android 活动生命周期（[`developer.android.com/training/basics/activity-lifecycle`](http://developer.android.com/training/basics/activity-lifecycle)），在后台继续浪费宝贵的系统资源，而是应该在`onPause()`回调中暂停我们的应用程序。

## 准备就绪

如果你不太熟悉 Android 活动生命周期，请参考开发者手册：[`developer.android.com/training/basics/activity-lifecycle/index.html`](http://developer.android.com/training/basics/activity-lifecycle/index.html)。

## 如何实现…

1.  一个 Android 应用程序不必实现所有的生命周期方法。我们的生命周期管理策略将非常简单；一旦调用`onPause()`方法，保存游戏状态并终止应用程序。我们需要编写一些 Java 代码来实现这个功能。将这段代码添加到你的`Activity`类中，在我们的例子中是`Game1Activity.java`文件中的`Game1Activity`类：

    ```kt
      @Override protected void onPause()
      {
        super.onPause();
        ExitNative();
      }
      public static native void ExitNative();
    ```

1.  按照以下方式实现`ExitNative()` JNI 方法：

    ```kt
    JNIEXPORT void JNICALL Java_com_packtpub_ndkcookbook_game1_Game1Activity_ExitNative(
      JNIEnv* env, jobject obj )
    {
    OnStop();
      exit( 0 );
    }
    ```

1.  现在我们可以在我们的游戏中实现本地`OnStop()`回调。

## 它是如何工作的…

`OnStop()`回调的典型实现将保存游戏状态，以便稍后游戏恢复时可以恢复状态。由于我们的第一个游戏不需要任何保存，我们只提供一个空的实现：

```kt
void OnStop()
{
}
```

你可能想要稍后作为一个练习来实现游戏保存。

## 还有更多…

要使`OnStop()`方法在 Windows 上工作，只需在`Wrapper_Windows.cpp`中的主循环退出后调用它：

```kt
while ( !PendingExit )
{
  …
}
OnStop();
```

现在这个解决方案是可移植的，所有的逻辑都可以在 Windows 上进行调试。

## 另请参阅

+   *实现主循环*

# 实现主循环

在前面的章节中，我们的代码示例使用了带有粗略固定时间步长的`OnTimer()`回调来更新状态，以及`OnDrawFrame()`回调来渲染图形。这对于需要根据自上一帧以来经过的真实时间来更新状态的真实游戏来说是不合适的。然而，我们仍然希望使用较小的固定时间步长在`OnTimer()`的调用中。我们可以通过巧妙地交错调用`OnTimer()`和`OnDrawFrame()`，并将此逻辑放入游戏主循环中，来解决此问题。

## 准备就绪

在[`gafferongames.com/game-physics/fix-your-timestep`](http://gafferongames.com/game-physics/fix-your-timestep)有一篇非常有趣的文章，名为**修复你的时间步长！**，它详细解释了实现游戏主循环的不同方法以及固定时间步长的重要性。

## 如何操作…

1.  游戏主循环的逻辑与平台无关，可以放入一个方法中：

    ```kt
    void GenerateTicks()
    {
    ```

1.  `GetSeconds()`返回自系统启动以来的单调时间（秒）。然而，只有帧差是重要的：

    ```kt
      NewTime = GetSeconds();
      float DeltaSeconds = static_cast<float>( NewTime - OldTime );
      OldTime = NewTime;
    ```

1.  我们将使用与每秒 60 帧运行的游戏相对应的固定时间步长来更新游戏逻辑：

    ```kt
      const float TIME_QUANTUM = 1.0f / 60.0f;
    ```

1.  同时，我们还需要一个故障安全机制，以防止由于渲染速度慢而导致的游戏过度减慢。

    ```kt
      const float MAX_EXECUTION_TIME = 10.0f * TIME_QUANTUM;
    ```

1.  现在，我们累积经过的时间：

    ```kt
      ExecutionTime += DeltaSeconds;
      if ( ExecutionTime > MAX_EXECUTION_TIME )
      { ExecutionTime = MAX_EXECUTION_TIME; }
    ```

1.  并相应地调用一系列`OnTimer()`回调函数。所有的`OnTimer()`回调都接收相同的固定时间步长值：

    ```kt
      while ( ExecutionTime > TIME_QUANTUM )
      {
        ExecutionTime -= TIME_QUANTUM;
        OnTimer( TIME_QUANTUM );
      }
    ```

1.  更新游戏后，渲染下一帧：

    ```kt
      OnDrawFrame();
    }
    ```

## 工作原理…

`OnDrawFrame()`回调应该在更新后调用。如果设备足够快，每次`OnTimer()`调用后都会调用`OnDrawFrame()`。否则，为了保持游戏逻辑的实时速度，将跳过一些帧。如果设备太慢以至于无法运行游戏逻辑，我们的保护代码将启动：

```kt
if ( ExecutionTime > MAX_EXECUTION_TIME )
  { ExecutionTime = MAX_EXECUTION_TIME; }
```

整个过程将以慢动作进行，但游戏仍然可以玩。

### 注意

你可以尝试调整传递给`OnTimer()`的值，例如`OnTimer( k * TIME_QUANTUM )`。如果`k`小于`1.0`，游戏逻辑将变为慢动作。它可以用来制作类似于子弹时间（[`en.wikipedia.org/wiki/Bullet_time`](http://en.wikipedia.org/wiki/Bullet_time)）的效果。

## 还有更多…

如果应用程序被挂起，但你想让它继续在后台运行，最好完全省略渲染阶段或更改更新量子的持续时间。你可以通过为你的游戏添加`Paused`状态并在主循环中检查它，例如：

```kt
if ( !IsPaused() ) OnDrawFrame();
```

这将有助于在后台运行游戏逻辑模拟的同时节省宝贵的 CPU 周期。

## 另请参阅

+   第二章中*实现物理中的定时*的食谱，*移植通用库*

# 创建一个多平台游戏引擎

在前面的章节和食谱中，我们手工制作了许多针对多平台游戏开发任务的临时解决方案。现在，我们将所有相关的代码整合到一个初生的便携式游戏引擎中，并学习如何为 Windows 和 Android 准备 makefile 以构建它。

## 准备就绪。

要了解这个食谱中发生的情况，建议你从本书开始阅读第一章到第七章。

## 如何操作...

1.  我们将所有代码分成几个逻辑子系统，并将它们放入以下文件夹中：

    +   `core`：这包含低级别的设施，例如侵入式智能指针和数学库。

    +   `fs`：这包含与文件系统相关的类。

    +   `GL`：这包含官方的 OpenGL 头文件。

    +   `include`：这包含一些第三方库的头文件。

    +   `graphics`：这包含高级图形相关代码，如字体、画布和图像。

    +   `LGL`：这包含我们在 第七章 中实现的 OpenGL 包装器和函数加载代码以及抽象层，*跨平台 UI 和输入系统*。

    +   `Sound`：这包含音频相关类和解码库。

    +   `threading`：这包含与多线程相关的类，包括互斥量、事件、队列和我们的多平台线程包装器。

## 它是如何工作的...

每个文件夹中的大部分代码都被分成了类。在我们的简约游戏引擎中，我们尽量保持类的数量在一个合理的最低限度。

`graphics` 文件夹包含了以下结构和类的实现：

+   结构体 `sBitmapParams` 保存位图的参数，如宽度、高度和像素格式。

+   类 `clBitmap` 是一个与 API 独立的位图表示，保存实际的像素数据以及 `sBitmapParams`。它可以加载到 clGLTexture 中。

+   类 `clCanvas` 提供了一种立即渲染的机制。

+   类 `clVertexAttribs` 是一个与 API 独立的 3D 几何表示。它可以加载到 `clGLVertexArray` 中。

+   类 `clGeomServ` 提供了创建 3D 几何的方法，返回 `clVertexAttribs`。

+   类 `iGestureResponder` 是一个接口，如果你想要响应触摸或手势，就需要实现这个接口。

+   结构体 `sMotionData` 保存当前激活的触摸点集合。

+   类 `clTextRenderer` 提供基于 FreeType 的文本渲染设施。它可以指定字体将文本字符串渲染到 `clBitmap` 中。

+   结构体 `sTouchPoint` 表示一个带有标识符、2D 归一化浮点坐标、标志和时间戳的单个触摸点。

`LGL` 文件夹保存了特定于 OpenGL 的类：

+   结构体 `sUniform` 表示着色器程序中的一个统一变量。它只是一个名称和位置索引。

+   类 `clGLSLShaderProgram` 表示一个用 GLSL 编写的着色器程序，并提供桌面 GLSL 与移动 GLSL ES 之间的自动转换功能。

+   类 `clGLTexture` 提供对 OpenGL 纹理的访问，并可以读取 `clBitmap` 的像素数据。

+   类 `clGLVertexArray` 提供了对 OpenGL 顶点数组对象和顶点缓冲对象的抽象。它使用来自 `clVertexAttribs` 的数据。

低级类，如智能指针、侵入式计数器和数学相关代码被放入 `core` 文件夹：

+   类 `clPtr` 是一个引用计数式侵入式智能指针的实现。

+   类 `iObject` 持有一个侵入式引用计数器。

+   类 `LRingBuffer` 是一个环绕式环形缓冲区的实现。

+   基本数学库包括向量类，如 `LVector2`、`LVector3`、`LVector4`、`LVector2i` 和矩阵类，如 `LMatrix3` 和 `LMatrix4`。数学库还包含设置投影的最小代码。

文件系统相关的代码位于 `fs` 文件夹中：

+   类 `clArchiveReader` 使用 **libcompress** 库实现 `.zip` 归档解压算法。它用于访问 Android `.apk` 文件中的资源。

+   类 `clBlob` 表示内存中的字节数组，可以从中读取或写入文件。

+   类 `iRawFile` 是所有表示文件的类的基类。

+   类 `clRawFile` 表示物理文件系统上的文件。

+   类 `clMemRawFile` 将内存块表示为文件，适用于访问下载的数据（例如图像）。

+   类 `clManagedMemRawFile` 与 `MemRawFile` 类似，但内存由内部的 `Blob` 对象管理。

+   类 `clFileMapper` 是只读内存映射文件的抽象。

+   类 `clFileWriter` 是写入文件的抽象。

+   类 `clFileSystem` 是流和块（blobs）的工厂。它提供了管理我们应用程序中虚拟路径的功能。

+   类 `iMountPoint`、`clPhysicalMountPoint`、`clAliasMountPoint` 和 `clArchiveMountPoint` 用于以可移植的多平台方式路由到操作系统本地文件系统和 Android `.apk` 归档的访问。

`sound` 文件夹包含我们音频子系统的抽象：

+   类 `clAudioSource` 表示虚拟环境中的音频源。它可以播放、暂停或停止。

+   类 `clAudioThread` 更新活动源并将数据提交到底层的 OpenAL API。

+   类 `iWaveDataProvider` 抽象了音频文件的解码。

+   类 `clStreamingWaveDataProvider` 从太大而不能一次性解码到内存中的音频文件流式传输数据。

+   类 `clDecodingProvider` 为流式音频提供者提供公共倒带逻辑。它是实际解码器的基类。

+   类 `clOggProvider` 和 `clModPlugProvider` 使用 **libogg**/**libvorbis** 处理 `.ogg` 文件的解码和 **libmodplug** 处理跟踪音乐。

`threading` 文件夹包含不同多线程原语的可移植实现：

+   类 `clMutex`、`LMutex` 和 `iThread` 以可移植的方式实现了基本的低级多线程原语。

+   类 `clWorkerThread` 和 `iTask` 是基于 `iThread` 的高级抽象。

+   类 `iAsyncQueue` 和 `iAsyncCapsule` 用于实现异步回调。

    ### 注意

    我们小型引擎的源代码位于上一章示例中的 Engine 文件夹内。

## 另请参阅

+   *编写匹配-3 游戏*

+   第九章, *编写图片拼图游戏*

# 编写匹配-3 游戏

现在是开始开发一个完整的**匹配-3**游戏的时候了。匹配-3 是一种拼图类型，玩家需要排列瓷砖以使相邻的瓷砖消失。这里，`3`表示当相同颜色的瓷砖相邻放置时将消失的数量。以下截图是游戏的最终版本：

![编写匹配-3 游戏](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-gm-dev-cb/img/7785_08_9.jpg)

在我们的游戏中使用了 22 种单块、双块、三块、四块和五块形状。

![编写匹配-3 游戏](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-gm-dev-cb/img/7785_08_2.jpg)

由于大部分印象来自于屏幕上可视化的结果，让我们继续了解游戏屏幕渲染的基本要点。

## 准备就绪

完整的、可直接构建的源代码位于补充材料中的`1_Game`文件夹。

这款游戏于 2011 年由本书作者在 Google Play 以某种扩展形式发布。如果你想立即在 Android 设备上尝试这款游戏，可以在以下网站找到：[`play.google.com/store/apps/details?id=com.linderdaum.engine.multibricks`](http://play.google.com/store/apps/details?id=com.linderdaum.engine.multibricks) 和 [`play.google.com/store/apps/details?id=com.linderdaum.engine.multibricks_free`](http://play.google.com/store/apps/details?id=com.linderdaum.engine.multibricks_free)。

如果你在自己的项目中使用这款游戏的图形作品，作者并不介意。这是一个学习工具，而不是商品。

对通用匹配-3 游戏机制感兴趣的人可以参考以下维基百科文章：[`en.wikipedia.org/wiki/Match_3`](http://en.wikipedia.org/wiki/Match_3)。

## 如何操作…

每帧都在`OnDrawFrame()`回调中通过几个步骤重新渲染整个游戏屏幕。让我们通过源代码看看如何操作：

1.  全屏背景图像在清除前一个帧的图形后渲染。图像存储为 512 x 512 的方形`.png`文件，并按比例缩放到全屏，如下截图所示：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-gm-dev-cb/img/7785_08_3.jpg)

    ### 注意

    为了使游戏兼容旧的 Android 硬件，使用了 2 的幂次图像。如果你的最低要求是 OpenGL ES 3，可以使用任意大小的纹理。

1.  以下是渲染背景的 C++代码：

    ```kt
    LGL3->glDisable( GL_DEPTH_TEST );
    ```

1.  首先，绑定 3 个纹理和着色器：

    ```kt
    BackTexture_Bottom->Bind(2);
    BackTexture_Top->Bind(1);
    BackTexture->Bind(0);
    BackShader->Bind();
    ```

1.  更新控制按钮的按下标志：

    ```kt
    BackShader->SetUniformNameFloatArray( "b_MoveLeft",  1, 
      b_Flags[b_MoveLeft] );
    BackShader->SetUniformNameFloatArray( "b_Down",      1, 
      b_Flags[b_Down] );
    BackShader->SetUniformNameFloatArray( "b_MoveRight", 1, 
      b_Flags[b_MoveRight] );
    BackShader->SetUniformNameFloatArray( "b_TurnLeft",  1, 
      b_Flags[b_TurnLeft] );
    BackShader->SetUniformNameFloatArray( "b_TurnRight", 1, 
      b_Flags[b_TurnRight] );
    BackShader->SetUniformNameFloatArray( "b_Reset",     1, 
      b_Flags[b_Reset] );
    BackShader->SetUniformNameFloatArray( "b_Paused",    1, 
      b_Flags[b_Paused] );
    ```

1.  最后，渲染一个全屏矩形：

    ```kt
    Canvas->GetFullscreenRect()->Draw(false);
    ```

1.  `float b_Flags[]`数组对应于控制按钮的状态；`1.0f`的值表示按钮被按下，`0.0f`表示按钮被释放。这些值被传递给着色器，相应地突出显示按钮。

1.  游戏场地的单元格在背景之上渲染，然后是当前形状：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-gm-dev-cb/img/7785_08_4.jpg)

    ```kt
    for ( int i = 0; i < g_Field.FWidth; i++ )
    {
      for ( int j = FIELD_INVISIBLE_RAWS;j < g_Field.FHeight; j++ )
      {
        int c = g_Field.FField[i][j];
        if ( c >= 0 && c < NUM_COLORS )
        {
          int Img = c % NUM_BRICK_IMAGES;
          int P = ( j - FIELD_INVISIBLE_RAWS );
    ```

1.  场的每个单元格只是一个带有纹理的小矩形：

    ```kt
          DrawTexQuad( i * 20.0f + 2.0f,
          P * 20.0f + 2.0f,16.0f, 16.0f,
          Field_X1, Field_Y1,
          g_Colors[c], Img );
        }
      }
    }
    ```

1.  当前行形状在一行中渲染：

    ```kt
    DrawFigure(&g_CurrentFigure, g_GS.FCurX,
          g_GS.FCurY - FIELD_INVISIBLE_RAWS,Field_X1, Field_Y1,
          BLOCK_SIZE );
    ```

1.  下一个图形在控制按钮附近渲染，如下面的截图所示：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-gm-dev-cb/img/7785_08_8.jpg)

1.  代码更为复杂，因为我们需要计算形状的边界框以正确渲染它：

    ```kt
      int Cx1, Cy1, Cx2, Cy2;
      g_NextFigure.GetTopLeftCorner(&Cx1, &Cy1 );
      g_NextFigure.GetBottomRightCorner(&Cx2, &Cy2 );
      LRect FigureSize = g_NextFigure.GetSize();
      float dX = ( float )Cx1 * BLOCK_SIZE_SMALL / 800.0f;
      float dY = ( float )Cy1 * BLOCK_SIZE_SMALL / 600.0f;
      float dX2 = 0.5f * (float)Cx2 * BLOCK_SIZE_SMALL/800.0f;
      float dY2 = 0.5f * (float)Cy2 * BLOCK_SIZE_SMALL/600.0f;
      DrawFigure( &g_NextFigure, 0, 0, 0.415f - dX - dX2,
        0.77f - dY - dY2, BLOCK_SIZE_SMALL );
    ```

1.  渲染当前分数文本，如下面的截图所示：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-gm-dev-cb/img/7785_08_6.jpg)

1.  文本一旦更改，就会被渲染成位图，并更新纹理：

    ```kt
    std::string ScoreString( Str_GetFormatted( "%02i:%06i",
    g_GS.FLevel, g_GS.FScore ) );
    if ( g_ScoreText != ScoreString )
    {
      g_ScoreText = ScoreString;
      g_ScoreBitmap = g_TextRenderer->RenderTextWithFont(
        ScoreString.c_str(), g_Font,32, 0xFFFFFFFF, true );
      g_ScoreTexture->LoadFromBitmap( g_ScoreBitmap );
    }
    ```

1.  我们只需在每一帧中渲染一个带有纹理的矩形：

    ```kt
      LVector4 Color( 0.741f, 0.616f, 0.384f, 1.0f );
      Canvas->TexturedRect2D( 0.19f, 0.012f, 0.82f, 0.07f,Color,
      g_ScoreTexture );
    ```

1.  如果需要，渲染游戏结束信息，如下面的截图所示：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-gm-dev-cb/img/7785_08_7.jpg)

1.  这与文本渲染类似，然而，由于这个消息框显示得不频繁，我们可以避免缓存：

    ```kt
      if ( g_GS.FGameOver )
      {
        DrawBorder( 0.05f, 0.25f, 0.95f, 0.51f, 0.19f );
        std::string ScoreStr = Str_GetPadLeft(
        Str_ToStr( g_GS.FScore ), 6, '0' );
        Canvas->TextStr( 0.20f, 0.33f, 0.84f, 0.37f,
        LocalizeString("Your score:"), 32,
        LVector4( 0.796f, 0.086f,0.086f, 1.0f ),
        g_TextRenderer, g_Font );
        Canvas->TextStr( 0.20f, 0.38f, 0.84f, 0.44f,ScoreStr,
        32, LVector4( 0.8f, 0.0f, 0.0f,1.0f ),
        g_TextRenderer, g_Font );
      }
    ```

1.  Canvas 完成了渲染文本和更新纹理所需的所有工作。然而，对于更频繁的操作来说，它有点慢。查看`graphics/Canvas.cpp`文件中的完整实现。

## 工作原理…

在前面的代码中，我们使用了一些辅助函数，可能需要一些解释。`DrawQuad()`和`DrawTexQuad()`函数绘制游戏场的一个单元格。它们包含一些硬编码的值，用于将单元格相对于背景图像定位。以下是其中一个函数的源代码：

```kt
void DrawTexQuad( float x, float y, float w, float h,
float OfsX, float OfsY,
const LVector4& Color, int ImageID )
{
```

`800.0f`和`600.0f`的魔法常数在这里出现，用于将 UI 坐标系统（为`600×800`纵向屏幕设计）转换为浮点标准化坐标：

```kt
  float X1 = x / 800.0f;
  float Y1 = y / 600.0f;
  float X2 = ( x + w ) / 800.0f;
  float Y2 = ( y + h ) / 600.0f;
```

其他魔法常数也是设计的一部分，是通过经验选择的。尝试调整它们：

```kt
  X1 *= Field_Width / 0.35f;
  X2 *= Field_Width / 0.35f;
  Y1 *= Field_Height / 0.75f;
  Y2 *= Field_Height / 0.75f;
  Canvas->TexturedRect2D( X1 + OfsX, Y1 + OfsY,
  X2 + OfsX, Y2 + OfsY,
  Color, BricksImage[ImageID] );
  }
```

`DrawFigure()`方法用于在游戏场地的任何位置绘制单个形状：

```kt
void DrawFigure( clBricksShape* Figure, int X, int Y,
float OfsX, float OfsY, float BlockSize )
{
  for ( int i = 0 ; i < Figure->FWidth ; i++ )
  {
    for ( int j = 0 ; j < Figure->FHeight ; j++ )
    {
```

跳过游戏场顶部不可见的行：

```kt
      if ( Y + j < 0 ) { continue; }
      intc = Figure->GetMask( i, j );
      if ( c >= 0 && c < NUM_COLORS )
      {
        DrawTexQuad(
          (X + i) *(BlockSize + 4.0f) + 2.0f,
          (Y + j) * (BlockSize + 4.0f) + 2.0f,
          BlockSize, BlockSize, OfsX, OfsY,
          g_Colors[c], c % NUM_BRICK_IMAGES );
        }
    }
  }
}
```

`DrawBorder()`函数只是`Canvas`的一个快捷方式：

```kt
void DrawBorder( float X1, float Y1, float X2, float Y2,
 float Border )
{
  Canvas->TexturedRect2D( X1, Y1, X1+Border, Y2,
    LVector4( 1.0f ), MsgFrameLeft  );
  Canvas->TexturedRect2D( X2-Border, Y1, X2, Y2,
    LVector4( 1.0f ), MsgFrameRight );
  Canvas->TexturedRect2DTiled( X1+Border, Y1, X2-Border, Y2,
    3, 1, LVector4( 1.0f ), MsgFrameCenter );
}
```

## 还有更多…

我们提到过，控制按钮在片段着色器中会被突出显示。以下是实现方法。

将按钮的状态作为统一变量传递：

```kt
uniform float b_MoveLeft;
uniform float b_Down;
uniform float b_MoveRight;
uniform float b_TurnLeft;
uniform float b_TurnRight;
uniform float b_Reset;
uniform float b_Paused;
```

检查矩形是否包含指定点的函数如下：

```kt
bool ContainsPoint( vec2 Point, vec4 Rect )
{
  return Point.x >= Rect.x && Point.y >= Rect.y &&
  Point.x <= Rect.z && Point.y <= Rect.w;
}
```

存储一些硬编码的值，对应于我们的控制按钮所在的位置：

```kt
void main()
{
  const vec4 MoveLeft  = vec4( 0.0,  0.863, 0.32, 1.0 );
  const vec4 Down      = vec4( 0.32, 0.863, 0.67, 1.0 );
  const vec4 MoveRight = vec4( 0.67, 0.863, 1.0,  1.0 );
  const vec4 TurnLeft  = vec4( 0.0,  0.7,  0.4,  0.863);
  const vec4 TurnRight = vec4( 0.6,  0.7,  1.0,  0.863);
  const vec4 Reset     = vec4( 0.0,  0.0,  0.2,  0.1 );
  const vec4 Paused    = vec4( 0.8,  0.0,  1.0,  0.1 );
```

阅读背景纹理和突出部分。查看随附项目中的`back.png`、`back_high_bottom.png`和`back_high_top.png`文件：

```kt
  vec4 Color      = texture( Texture0,TexCoord );
  vec4 ColorHighT = texture( Texture1,TexCoord*vec2(4.0,8.0) );
  vec4 ColorHighB = texture( Texture2,TexCoord*vec2(1.0,2.0) );
```

检查按钮是否被按下，并相应地选择正确的纹理：

```kt
  if ( b_MoveLeft>0.5 &&ContainsPoint(TexCoord.xy, MoveLeft))
    Color = ColorHighB;
  if ( b_Down> 0.5 && ContainsPoint( TexCoord.xy, Down ) )
    Color = ColorHighB;
  if ( b_MoveRight>0.5 && ContainsPoint(TexCoord.xy,MoveRight) )
    Color = ColorHighB;
  if ( b_TurnLeft>0.5 && ContainsPoint(TexCoord.xy, TurnLeft) )
    Color = ColorHighB;
  if ( b_TurnRight>0.5 && ContainsPoint(TexCoord.xy,TurnRight) )
    Color = ColorHighB;
  if ( b_Reset> 0.5 && ContainsPoint( TexCoord.xy, Reset) )
    Color = ColorHighT;
  if ( b_Paused> 0.5 && ContainsPoint( TexCoord.xy, Paused ) )
    Color = ColorHighT;
```

哇！我们只用一次传递就为所有按钮纹理化了背景：

```kt
   out_FragColor = Color;
}
```

## 另请参阅

+   *创建一个多平台游戏引擎*

# 管理形状

在上一个食谱中，我们学习了如何渲染游戏屏幕。有些类尚未实现。在本食谱中，我们将实现`clBricksShape`类，负责存储和操作游戏中出现的每个形状。

## 准备就绪

看看可以存在多少不同的五格拼板形状。维基百科提供了一个全面的概述：[`en.wikipedia.org/wiki/Pentomino`](http://en.wikipedia.org/wiki/Pentomino)。

## 如何操作…

1.  我们的`clBricksShape`类的接口如下所示：

    ```kt
    class clBricksShape
    {
    public:
    ```

1.  我们游戏中使用的形状大小。我们使用`5x5`的形状。

    ```kt
      static const int FWidth  = SHAPES_X;
      static const int FHeight = SHAPES_Y;
    ```

1.  存储构成这个形状的单元格的颜色。颜色作为索引存储：

    ```kt
    private:
      int FColor[NUM_COLORS];
    ```

1.  图形索引定义了形状类型：

    ```kt
      int FFigureIndex;
    ```

1.  旋转索引对应于图形的旋转角度：`0`、`1`、`2`和`3`分别代表`0`、`90`、`180`和`270`度：

    ```kt
      int FRotationIndex;
    ```

1.  这些方法非常简短直接，如下所示：

    ```kt
    public:
      int GetMask( int i, int j ) const
      {
        if ( i < 0 || j < 0 ) return -1;
        if ( i >= FWidth || j >= FHeight ) return -1;
        int ColorIdx =
        Shapes[FFigureIndex][FRotationIndex][i][j];
        return ColorIdx ? FColor[ColorIdx] : -1;
      }
    ```

1.  `Rotate()`方法并不旋转单个单元格。它什么也不做，只是调整旋转角度：

    ```kt
      void Rotate( bool CW )
      {
        FRotationIndex = CW ?
             ( FRotationIndex ? FRotationIndex - 1 : ROTATIONS - 1 ) :
             ( FRotationIndex + 1 ) % ROTATIONS;
      }
    ```

1.  图形生成也非常简单。它只是从预定义图形的表格中选择：

    ```kt
      void GenFigure( int FigIdx, int Col )
      {
        for ( int i = 0; i != NUM_COLORS; i++ )
          FColor[i] = Random( NUM_COLORS );
        FFigureIndex = FigIdx;
        FRotationIndex = 0;
      }
    ```

1.  这些方法用于计算形状的边界框。参考《game/Shape.h》文件以获取它们的源代码：

    ```kt
    void GetTopLeftCorner( int* x, int* y ) const;
      void GetBottomRightCorner( int* x, int* y ) const;
      LRect GetSize() const;
    };
    ```

## 工作原理…

前一节代码的主要技巧在于预定义形状的表格。其声明位于《Pentomino.h》文件中：

```kt
static const int NUM_SHAPES = 22;
static const int SHAPES_X = 5;
static const int SHAPES_Y = 5;
static const int ROTATIONS = 4;
extern char
  Shapes[ NUM_SHAPES ][ ROTATIONS ][ SHAPES_X ][ SHAPES_Y ];
```

就是这样。我们将每一个形状存储在这个 4D 数组中。《Pentomino.cpp》文件定义了数组的内容。以下代码是定义单个形状所有 4 种旋转的摘录：

```kt
char Shapes [ NUM_SHAPES ][ ROTATIONS ][ SHAPES_X ][ SHAPES_Y ] =
{
  {
    {
      {0, 0, 0, 0, 0},
      {0, 0, 0, 1, 0},
      {0, 0, 3, 2, 0},
      {0, 5, 4, 0, 0},
      {0, 0, 0, 0, 0}
    },
    {
      {0, 0, 0, 0, 0},
      {0, 5, 0, 0, 0},
      {0, 4, 3, 0, 0},
      {0, 0, 2, 1, 0},
      {0, 0, 0, 0, 0}
    },
    {
      {0, 0, 0, 0, 0},
      {0, 0, 4, 5, 0},
      {0, 2, 3, 0, 0},
      {0, 1, 0, 0, 0},
      {0, 0, 0, 0, 0}
    },
    {
      {0, 0, 0, 0, 0},
      {0, 1, 2, 0, 0},
      {0, 0, 3, 4, 0},
      {0, 0, 0, 5, 0},
      {0, 0, 0, 0, 0}
    }
  },
```

数组中的非零值定义了哪些单元格属于形状。值的绝对定义了单元格的颜色。

## 另请参阅

+   *编写匹配-3 游戏*

# 管理游戏场逻辑

现在我们知道如何存储不同的形状并渲染它们。让我们实现一些游戏逻辑，让这些形状在游戏场中相互交互。

## 准备就绪

参阅《编写匹配-3 游戏》的菜谱，了解如何渲染游戏场。

## 如何操作…

1.  `clBricksField`的接口如下所示：

    ```kt
    class clBricksField
    {
    public:
    ```

1.  我们的游戏场大小为`11×22`：

    ```kt
      static const int FWidth = 11;
      static const int FHeight = 22;
    public:
      void clearField()
    ```

1.  检查图形是否可以自由地放入某个位置的方法如下：

    ```kt
      bool figureFits( int x, int y, const clBricksShape& fig )
      bool figureWillHitNextTurn( int x, int y,
        const clBricksShape& fig )
    ```

1.  这个方法将形状印在游戏场的指定位置：

    ```kt
      void addFigure( int x, int y, const clBricksShape& fig )
    ```

1.  以下代码是主要的游戏逻辑。计算并删除同色单元格区域的方法：

    ```kt
      int deleteLines();
      int CalcNeighbours( int i, int j, int Col );
      void FillNeighbours( int i, int j, int Col );
    ```

1.  由于我们正在制作一个匹配-3 游戏，因此我们给这个方法传递了`3`的值。然而，逻辑是通用的；你可以使用自己的值调整游戏玩法：

    ```kt
      int deleteRegions( int NumRegionsToDelete );
      void collapseField();
    ```

1.  游戏场的单元格存储在这里。值对应于单元格的颜色：

    ```kt
    public:
        int FField[ FWidth ][ FHeight ];
    };
    ```

## 工作原理…

形状拟合使用简单的遮罩检查，非常简单。我们将更多关注邻近单元格的计算。它基于递归的洪水填充算法（[`en.wikipedia.org/wiki/Flood_fill`](http://en.wikipedia.org/wiki/Flood_fill)）：

```kt
int clBricksField::deleteRegions( int NumRegionsToDelete )
{
  int NumRegions = 0;
  for ( int j = 0; j != FHeight; j++ )
  {
    for ( int i = 0 ; i != FWidth ; i++ )
    {
      if ( FField[i][j] != -1 )
      {
```

递归地计算每个单元格的邻居数量：

```kt
        int Neighbors = CalcNeighbours( i, j,
        FField[i][j] );
```

如果邻居数量足够多，则标记单元格：

```kt
        if ( Neighbors >= NumRegionsToDelete )
        {
          FillNeighbours( i, j, FField[i][j] );
          NumRegions += Neighbours;
        }
      }
    }
  }
```

从游戏场中移除标记的单元格：

```kt
  CollapseField(); 
```

返回删除区域的数量。这用于评估当前分数：

```kt
  return NumRegions;
}
```

递归的洪水填充是直接的。以下代码计算相邻单元格的数量：

```kt
intclBricksField::CalcNeighbours( int i, int j, int Col )
{
  if ( i < 0 || j < 0 || i >= FWidth ||
  j >= FHeight || FField[i][j] != Col ) return 0;
  FField[i][j] = -1;
  int Result =  1 + CalcNeighbours( i + 1, j + 0, Col ) +
  CalcNeighbours( i - 1, j + 0, Col ) +
  CalcNeighbours( i + 0, j + 1, Col ) +
  CalcNeighbours( i + 0, j - 1, Col );
  FField[i][j] = Col;
  return Result;
}
```

以下代码标记相邻的单元格：

```kt
void clBricksField::FillNeighbours( int i, int j, int Col )
{
  if ( i < 0 || j < 0 || i >= FWidth ||
    j >= FHeight || FField[i][j] != Col ) { return; }
  FField[i][j] = -1;
  FillNeighbours( i + 1, j + 0, Col );
  FillNeighbours( i - 1, j + 0, Col );
  FillNeighbours( i + 0, j + 1, Col );
  FillNeighbours( i + 0, j - 1, Col );
}
```

## 还有更多…

这个项目中还实现了另一种游戏逻辑变体。查看文件 `game/Field.h` 中的 `deleteLines()` 方法以了解如何实现它。

# 在游戏循环中实现用户交互

在之前的食谱中，我们学习了如何渲染游戏环境并实现游戏逻辑。开发中还有一个重要的方面需要我们关注：用户交互。

## 准备就绪

查看项目 `1_Game` 中的 `main.cpp` 文件以获取完整实现。

## 如何操作…

我们需要实现一些函数来移动当前下落的形状：

1.  在移动图形左右时强制执行游戏场地限制：

    ```kt
    bool MoveFigureLeft()
    {
      if ( g_Field.FigureFits( g_GS.FCurX - 1, g_GS.FCurY,
      g_CurrentFigure ) )
      {
        g_GS.FCurX--;
        return true;
      }
      return false;
    }
    ```

1.  `MoveFigureRight()` 的源代码与 `MoveFigureLeft()` 类似。`MoveFigureDown()` 的代码需要在形状触地后更新得分：

    ```kt
    bool MoveFigureDown()
    {
      if ( g_Field.FigureFits( g_GS.FCurX, g_GS.FCurY + 1,
      g_CurrentFigure ) )
      {
        g_GS.FScore += 1 + g_GS.FLevel / 2;
        g_GS.FCurY++;
        return true;
      }
      return false;
    }
    ```

1.  旋转代码需要检查旋转是否实际可行：

    ```kt
    bool RotateFigure( bool CW )
    {
      clBricksShape TempFigure( g_CurrentFigure );
      TempFigure.Rotate( CW );
      if ( g_Field.FigureFits(g_GS.FCurX, g_GS.FCurY, TempFigure))
      {
        g_CurrentFigure = TempFigure;
        return false;
      }
      return true;
    }
    ```

1.  我们需要响应按键或触摸来调用这些方法。

## 工作原理…

`ProcessClick()` 函数处理单个点击。为了简化代码，我们将点击位置存储在全局变量 `g_Pos` 中：

```kt
void ProcessClick( bool Pressed )
{
```

重置按钮的状态：

```kt
  b_Flags[b_MoveLeft] = 0.0f;
  b_Flags[b_MoveRight] = 0.0f;
  b_Flags[b_Down] = 0.0f;
  b_Flags[b_TurnLeft] = 0.0f;
  b_Flags[b_TurnRight] = 0.0f;
  b_Flags[b_Paused] = 0.0f;
  b_Flags[b_Reset] = 0.0f;
  bool MousePressed = Pressed;
  if ( Reset.ContainsPoint( g_Pos ) )
  {
    if ( MousePressed ) { ResetGame(); }
    b_Flags[b_Reset] = MousePressed ? 1.0f : 0.0f;
  }
```

一旦游戏结束，不允许按下任何按钮：

```kt
  if ( g_GS.FGameOver ) { if ( !Pressed ) ResetGame(); return; }
```

运行操作并更新按钮的高亮状态：

```kt
  if ( Pressed )
  {
    if ( MoveLeft.ContainsPoint( g_Pos ) )
    { MoveFigureLeft(); b_Flags[b_MoveLeft] = 1.0f; }
    if ( MoveRight.ContainsPoint( g_Pos ) )
    { MoveFigureRight(); b_Flags[b_MoveRight] = 1.0f; }

    if ( Down.ContainsPoint( g_Pos ) )
{
if ( !MoveFigureDown() ) { NextFigure(); } b_Flags[b_Down] = 1.0f;
}
    if ( TurnLeft.ContainsPoint( g_Pos ) )
    { rotateFigure( false ); b_Flags[b_TurnLeft] = 1.0f; }
    if ( TurnRight.ContainsPoint( g_Pos ) )
    { rotateFigure( true ); b_Flags[b_TurnRight] = 1.0f; }
    if ( Paused.ContainsPoint( g_Pos ) )
    {
      b_Flags[b_Paused] = 1.0f;
```

这被用于在触摸屏上实现自动重复：

```kt
      g_KeyPressTime = 0.0f;
    }
  }
}
```

## 还有更多…

我们游戏的主循环是在 `OnTimer()` 回调中实现的：

```kt
void OnTimer( float DeltaTime )
{
  if ( g_GS.FGameOver ) { return; }
  g_GS.FGameTimeCount += DeltaTime;
  g_GS.FGameTime += DeltaTime;
  g_KeyPressTime += DeltaTime;
```

在这里，我们检查标志位的值以在触摸屏上实现方便的自动重复：

```kt
  if ( (b_Flags[b_MoveLeft] > 0 || 
      b_Flags[b_MoveRight] > 0 || 
      b_Flags[b_Down] > 0 || 
      b_Flags[b_TurnLeft] > 0 || 
      b_Flags[b_TurnRight] > 0 ) &&
  g_KeyPressTime > g_KeyTypematicDelay )
  {
    g_KeyPressTime -= g_KeyTypematicRate;
    ProcessClick( true );
  }
  while ( g_GS.FGameTimeCount > g_GS.FUpdateSpeed )
  {
    if ( !MoveFigureDown() )
    {
      NextFigure();
    }
```

检查行删除：

```kt
    int Count = g_Field.deleteRegions( BlocksToDisappear );

    …Update the game score here…
  }
}
```

自动重复值是按照现代操作系统中开发人员通常使用的值来选择的：

```kt
const float g_KeyTypematicDelay = 0.2f;  // 200 ms delay
const float g_KeyTypematicRate  = 0.03f; // 33 Hz repeat rate
```

我们原始的 MultiBricks 游戏包含一个暂停按钮。你可以使用 第九章 *编写图片谜题游戏* 中描述的基于页面的用户界面作为练习来实现它。

## 另请参阅…

+   *编写三消游戏*

+   第九章 *编写图片谜题游戏* 中的 *基于页面的用户界面* 食谱
