# 精通安卓 NDK（五）

> 原文：[`zh.annas-archive.org/md5/F3DC9D6FA4DADE68301DCD4BEC565947`](https://zh.annas-archive.org/md5/F3DC9D6FA4DADE68301DCD4BEC565947)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：编写“小行星”游戏

我们将继续整合之前章节的材料。我们将使用前几章介绍的技术和代码片段实现一个带有 3D 图形、阴影、粒子和声音的“小行星”游戏。首先，我们将在之前的内容中增加一些新的想法，然后继续编写一个完整的游戏应用程序。我们从屏幕操纵杆开始。

# 创建一个屏幕上的操纵杆

屏幕上的操纵杆基于多点触控处理。两个结构体包含了一个单一操纵杆按钮和轴的描述。按钮被赋予一个索引，并在`sBitmapButton`结构的`FColour`字段中通过其颜色指定。当用户在屏幕上点击，且操纵杆遮罩下方的像素颜色与其中一个按钮相匹配时，`clScreenJoystick`类将设置该按钮的按下标志：

```java
struct sBitmapButton
{
  ivec4 FColour;
  int FIndex;
};
```

`sBitmapAxis`结构体代表了一个游戏手柄的操纵杆，包含对应垂直和水平方向的两个轴。在游戏手柄的位图遮罩中，它以一个以`FPosition`为中心，半径为`FRadius`的圆形元素表示。`FAxis1`和`FAxis2`索引指定了哪些逻辑游戏手柄轴受到这个屏幕操纵杆的影响。

`FColour`字段用于确定用户是否触摸了这个轴：

```java
struct sBitmapAxis
{
  float FRadius;
  vec2 FPosition;
  int FAxis1, FAxis2;
  ivec4 FColour;
};
```

`clScreenJoystick`类的声明如下：

```java
class ScreenJoystick: public iIntrusiveCounter
{
public:
  std::vector<sBitmapButton> FButtonDesc;
  std::vector<sBitmapAxis> FAxisDesc;
  std::vector<float> FAxisValue;
  std::vector<bool> FKeyValue;
```

这个位图包含了一个带有按钮的颜色遮罩：

```java
  clPtr<clBitmap> FMaskBitmap;
public:
  ScreenJoystick()
  {}
```

分配按钮和轴状态数组：

```java
  void InitKeys()
  {
    FKeyValue.resize( FButtonDesc.size() );
    if ( FKeyValue.size() > 0 )
    {
      for ( size_t j = 0 ; j < FKeyValue.size() ; j++ ) { FKeyValue[j] = false; }
    }
    FAxisValue.resize( FAxisDesc.size() * 2 );
    if ( FAxisValue.size() > 0 )
    {
      memset( &FAxisValue[0], 0, FAxisValue.size() * sizeof( float ) );
    }
  }
```

重置操纵杆按钮和轴的状态：

```java
  void Restart()
  {
    memset( &FPushedAxis[0], 0, sizeof( sBitmapAxis* ) * MAX_TOUCH_CONTACTS );
    memset( &FPushedButtons[0], 0, sizeof( sBitmapButton* ) * MAX_TOUCH_CONTACTS );
  }
```

检查按钮是否被按下：

```java
  bool IsPressed( int KeyIdx ) const
  {
    return ( KeyIdx < 0 || KeyIdx >= ( int )FKeyValue.size() ) ? false : FKeyValue[KeyIdx];
  }
```

获取轴的当前值：

```java
  float GetAxisValue( int AxisIdx ) const
  {
    return ( ( AxisIdx < 0 ) || AxisIdx >= ( int )FAxisValue.size() ) ? 0.0f : FAxisValue[AxisIdx];
  }
```

按钮和轴的设置器以类似的方式实现：

```java
  void SetKeyState( int KeyIdx, bool Pressed )
  {
    if ( KeyIdx < 0 || KeyIdx >= ( int )FKeyValue.size() )
    { return; }
    FKeyValue[KeyIdx] = Pressed;
  }
  void SetAxisValue( int AxisIdx, float Val )
  {
    if ( AxisIdx < 0 || AxisIdx >= static_cast<int>( FAxisValue.size() ) )
    { return; }
    FAxisValue[AxisIdx] = Val;
  }
```

尝试根据游戏手柄位图遮罩中找到的颜色来检测一个按钮：

```java
  sBitmapButton* GetButtonForColour( const ivec4& Colour )
  {
    for ( size_t k = 0 ; k < FButtonDesc.size(); k++ )
    if ( FButtonDesc[k].FColour == Colour )
    return &FButtonDesc[k];
    return nullptr;
  }
```

同样的逻辑也适用于轴的检测：

```java
  sBitmapAxis* GetAxisForColour( const ivec4& Colour )
  {
    for ( size_t k = 0 ; k < FAxisDesc.size(); k++ )
    {
      if ( FAxisDesc[k].FColour == Colour )
      { return &FAxisDesc[k]; }
    }
    return nullptr;
  }
```

当前按下的按钮和活动的轴存储在这些成员变量中：

```java
public:
  sBitmapButton* FPushedButtons[MAX_TOUCH_CONTACTS];
  sBitmapAxis* FPushedAxis[MAX_TOUCH_CONTACTS];
  void ReadAxis( sBitmapAxis* Axis, const vec2& Pos )
  {
    if ( !Axis ) { return; }
```

根据轴的中心点和触摸点读取轴的值。从中心点出发的距离代表相应轴上的一个值：

```java
    float v1 = ( Axis->FPosition - Pos ).x / Axis->FRadius;
    float v2 = ( Pos - Axis->FPosition ).y / Axis->FRadius;
    this->SetAxisValue( Axis->FAxis1, v1 );
    this->SetAxisValue( Axis->FAxis2, v2 );
  }
};
```

多点触控处理程序以下列方式实现：

```java
void ScreenJoystick::HandleTouch( int ContactID, const vec2& Pos, bool Pressed, eMotionFlag Flag )
{
  if ( ContactID == L_MOTION_START )
  {
    for ( size_t i = 0; i != MAX_TOUCH_CONTACTS; i++ )
    {
      if ( FPushedButtons[i] )
      {
        this->SetKeyState( FPushedButtons[i]->FIndex, false );
        FPushedButtons[i] = nullptr;
      }
      if ( FPushedAxis[i] )
      {
        this->SetAxisValue( FPushedAxis[i]->FAxis1, 0.0f );
        this->SetAxisValue( FPushedAxis[i]->FAxis2, 0.0f );
        FPushedAxis[i] = nullptr;
      }
    }
    return;
  }
  if ( ContactID == L_MOTION_END )
  { return; }
  if ( ContactID < 0 || ContactID >= MAX_TOUCH_CONTACTS )
  { return; }
```

清除所有之前的按下和轴的状态：

```java
  if ( Flag == L_MOTION_DOWN || Flag == L_MOTION_MOVE )
  {
    int x = (int)(Pos.x * (float)FMaskBitmap->GetWidth());
    int y = (int)(Pos.y * (float)FMaskBitmap->GetHeight());
    ivec4 Colour = FMaskBitmap->GetPixel(x, y);
    sBitmapButton* Button = GetButtonForColour( Colour );
    sBitmapAxis* Axis = GetAxisForColour( Colour );
    if ( Button && Pressed )
    {
      // touchdown, set the key
      int Idx = Button->FIndex;
      this->SetKeyState( Idx, true );
```

存储按钮的初始颜色，以便稍后跟踪其移动：

```java
      FPushedButtons[ContactID] = Button;
    }
    if ( Axis && Pressed )
    {
      this->ReadAxis( Axis, Pos );
      FPushedAxis[ContactID] = Axis;
    }
  }
}
```

为了演示`clScreenJoystick`类的使用，我们修改了前一章中的 boids 示例。绿色的盒子表示的目标用屏幕操纵杆控制。

# 实现粒子系统

为了让我们的游戏看起来更加光彩照人，我们在渲染引擎中添加了另一个组件：粒子系统。粒子类似于前一章中的 boids 移动，但数量大大超过它们，并且不打算参与复杂的交互。由于单个粒子是透明的，我们需要注意渲染顺序，并在帧内所有固体对象渲染后渲染粒子。

当谈论动力学时，每个粒子都被视为一个点状对象，并以屏幕对齐的四边形进行渲染。单个粒子并非永远存在，其初始生命周期`FLifeTime`和当前生存时间`FTTL`被存储。`sParticle`结构包含描述其运动和动力学属性的`FPosition`、`FVelocity`和`FAcceleration`字段。除了物理属性外，`FRGBA`字段包含粒子的颜色，而`FSize`字段描述了其视觉大小。我们可以这样说：

```java
struct sParticle
{
  sParticle(): FPosition(),
  FVelocity(),
  FAcceleration(),
  FLifeTime( 0.0f ),
  FTTL( 0.0f ),
  FRGBA( 1.0f, 1.0f, 1.0f, 1.0f ),
  FSize( 0.5f )
  {};
  LVector3    FPosition;             // current position
  LVector3    FVelocity;             // current velocity
  LVector3    FAcceleration;         // current acceleration
  float       FLifeTime;             // total life time
  float       FTTL;                  // time to live left
  LVector4    FRGBA;                 // overlay color
  float       FSize;                 // particle size
};
```

### 注意

为了简化我们的实现，我们以**结构数组**（**AoS**）而不是**数组结构**（**SoA**）的形式存储粒子。SoA 方法对缓存更加友好且速度更快。如果你对如何更有效地实现基于 CPU 的粒子系统感兴趣，请参考以下系列博客文章：[`www.bfilipek.com/2014/04/flexible-particle-system-start.html`](http://www.bfilipek.com/2014/04/flexible-particle-system-start.html)。

`clParticleSystem`类的私有部分包含一个带有 GPU 就绪粒子数据的`clVertexAttribs`对象，一个`sParticle`实例的容器，一个用于我们渲染系统的材质描述，以及当前活动的粒子数量：

```java
class clParticleSystem: public iIntrusiveCounter
{
private:
  clPtr<clVertexAttribs> FVertices;
  std::vector<sParticle> FParticles;
  sMaterial FMaterial;
  int FCurrentMaxParticles;
```

构造函数为初始数量的粒子预分配顶点：

```java
public:
  clParticleSystem(): FCurrentMaxParticles( 100 )
  {
    const int VerticesPerParticle = 6;
    FVertices = make_intrusive<clVertexAttribs>( VerticesPerParticle * FCurrentMaxParticles );
```

指定了一个特殊的材质类名。我们的渲染系统将识别这种材质，并使用适当的着色器来渲染粒子系统：

```java
    FMaterial.m_MaterialClass = "Particle";
  }
  virtual void AddParticle( const sParticle& Particle )
  {
    FParticles.push_back( Particle );
```

如果粒子的数量超过了顶点数组的当前容量，使用系数`1.2`进行扩容。这里增长系数的最优选择取决于实验，并依赖于向粒子系统提供粒子的发射器：

```java
    if ( FCurrentMaxParticles <
      static_cast<int>( FParticles.size() ) )
    {
      SetMaxParticles(int(FCurrentMaxParticles * 1.2f));
    }
  }
```

`SetMaxParticles()`方法调整`FVertices`顶点数组的大小，以至少容纳`MaxParticles`：

```java
  void SetMaxParticles( int MaxParticles );
```

我们还需要一系列的获取成员函数来访问类的私有字段：

```java
  virtual std::vector<sParticle>& GetParticles()
  { return FParticles; }
  virtual clPtr<clVertexAttribs> GetVertices() const
  { return FVertices; }
  virtual const sMaterial& GetDefaultMaterial() const
  { return FMaterial; }
  virtual sMaterial& GetDefaultMaterial() { return FMaterial; }
```

这里是所有操作发生的地方。我们将在下一页中探讨这个方法：

```java
  virtual void UpdateParticles( float DeltaSeconds );
};
```

`SetMaxParticles()`方法可能看起来很简单，但实际上除了容器大小的调整之外，还包含一些有用的代码。为了渲染粒子，我们使用了称为 billboarding 的技术。对于每个粒子，我们创建一个由两个三角形组成的屏幕对齐的四边形。四边形角的纹理坐标是固定的，对于每个粒子，我们在`SetMaxParticles()`方法中填充`U`和`V`值：

```java
void clParticleSystem::SetMaxParticles( int MaxParticles )
{
  FCurrentMaxParticles = MaxParticles;
```

首先，我们将调整`FParticles`数组和`FVertices`对象的大小：

```java
  const int VerticesPerParticle = 6;
  FParticles.reserve( FCurrentMaxParticles );
  FVertices = make_intrusive<clVertexAttribs>
    ( VerticesPerParticle * MaxParticles );
  vec2* Vec = FVertices->FTexCoords.data();
```

遍历粒子并给每个顶点分配六个纹理坐标对：

```java
  for ( int i = 0; i != MaxParticles; ++i )
  {
    int IdxI = i * 6;
    Vec[IdxI + 0] = vec2( 0.0f, 0.0f );
    Vec[IdxI + 1] = vec2( 1.0f, 0.0f );
    Vec[IdxI + 2] = vec2( 1.0f, 1.0f );
    Vec[IdxI + 3] = vec2( 0.0f, 0.0f );
    Vec[IdxI + 4] = vec2( 1.0f, 1.0f );
    Vec[IdxI + 5] = vec2( 0.0f, 1.0f );
  }
}
```

我们每帧都在`FVertices`和`FParticles`字段之间同步粒子坐标、生命周期和颜色。`UpdateParticles()`方法为每个粒子计算新的位置和速度，然后更新`FVertices`对象的各个组件：

```java
void clParticleSystem::UpdateParticles( float DeltaSeconds )
{
  vec3* Vec = FVertices->FVertices.data();
  vec3* Norm = FVertices->FNormals.data();
  vec4* RGB = FVertices->FColors.data();
  size_t NumParticles = FParticles.size();
  for ( size_t i = 0; i != NumParticles; ++i )
  {
    sParticle& P = FParticles[i];
    P.FTTL -= DeltaSeconds;
```

如果粒子的生存时间小于零，我们用数组中的最后一个粒子替换它，这样我们可以有效地将死粒子从容器中弹出：

```java
    if ( P.FTTL < 0 )
    {
      P = FParticles.back();
      FParticles.pop_back();
      NumParticles--;
      i--;
      continue;
    }
```

使用牛顿物理学和显式欧拉积分器，正如我们在上一章对鸟群所做的那样，我们为每个粒子重新计算新的速度和位置：

```java
    P.FVelocity += P.FAcceleration * DeltaSeconds;
    P.FPosition += P.FVelocity * DeltaSeconds;
```

粒子的生存时间、总生命时间和大小被打包到一个`vec3`变量中，这样它们就可以存储在顶点数组中：

```java
    LVector3 TTL = LVector3( P.FTTL, P.FLifeTime, P.FSize );
```

为了简化公式，我们归一化粒子的生命周期，并在我们的颜色计算中使用它：

```java
    float NormalizedTime = (P.FLifeTime-P.FTTL) / P.FLifeTime;
```

根据归一化时间，我们计算当前粒子的颜色。`GetParticleBrightness()`函数的描述如下：

```java
    vec4 Color = P.FRGBA * GetParticleBrightness( NormalizedTime );
```

由于每个粒子由两个三角形表示，我们在顶点数组中为连续的六个元素分配相同的值：

```java
    size_t IdxI = i * 6;
    for ( int j = 0; j < 6; j++ )
    {
      Vec [IdxI + j] = P.FPosition;
      Norm[IdxI + j] = TTL;
      RGB [IdxI + j] = Color;
    }
  }
```

更新每个粒子后，我们调整顶点数组中要渲染的顶点数量，以匹配当前活动的粒子数：

```java
  FVertices->SetActiveVertexCount ( 6 * static_cast<int>( FParticles.size() ) );
}
```

`GetParticleBrightness()`函数计算了一个梯形函数，对于从`0.1`到`0.9`的参数值，该函数的值为`1.0`。从视觉上讲，这意味着在粒子生命周期的开始，粒子从零渐变到完全可见，然后以恒定强度发光，然后线性衰减到零：

```java
inline float GetParticleBrightness( float NormalizedTime )
{
  const float Cutoff_Lo = 0.1f;
  const float Cutoff_Hi = 0.9f;
  if ( NormalizedTime < Cutoff_Lo )
  {
    return NormalizedTime / Cutoff_Lo;
  }
  if ( NormalizedTime > Cutoff_Hi )
  {
    return 1.0f - ( ( NormalizedTime - Cutoff_Hi ) / ( 1.0f - Cutoff_Hi ) );
  }
  return 1.0f;
}
```

在这一点上，我们只定义了持有粒子实例的类。为了将这些新对象集成到我们的渲染系统中，我们必须定义一种新的场景图节点，即`clParticleSystemNode`节点。在我们这样做之前，应该先讲述一下粒子的发射方式。

我们介绍了`iParticleEmitter`接口，该接口声明了一个纯虚方法`EmitParticles()`，该方法有两个参数。`DeltaTime`参数用于更新时间计数器并在`PS`粒子系统中计算新粒子的位置：

```java
class iParticleEmitter: public iIntrusiveCounter
{
public:
  iParticleEmitter():
  FColorMin( 0 ), FColorMax( 1 ),
  FSizeMin( 0.5f ), FSizeMax( 1.0f ),
  FVelMin( 0 ), FVelMax( 0 ),
  FMaxParticles( 1000 ),
  FEmissionRate( 100.0f ),
  FLifetimeMin( 1.0f ), FLifetimeMax( 60.0f ),
  FInvEmissionRate( 1.0f / FEmissionRate ),
  FAccumulatedTime( 0.0f )
  {}
  virtual void EmitParticles( const clPtr<clParticleSystem>& PS, float DeltaTime ) const = 0;
```

该类的字段定义了粒子每个参数的允许范围。颜色、大小、速度和生命周期的限制由带有`Min`和`Max`后缀的变量给出。`FEmissionRate`定义了我们每秒发射的粒子数，而`FMaxParticles`给出了粒子数量的上限。`FAccumulatedTime`字段包含了自上次粒子系统更新以来大约经过的时间：

```java
public:
  vec4 FColorMin, FColorMax;
  float FSizeMin, FSizeMax;
  vec3 FVelMin, FVelMax;
  size_t FMaxParticles;
  float FEmissionRate;
  float FLifetimeMin, FLifetimeMax;
protected:
  float FInvEmissionRate;
  mutable float FAccumulatedTime;
};
```

`EmitParticles()`方法在两个子类中被重写。第一个子类是`clParticleEmitter_Box`，它在一个轴向对齐的盒子区域发射粒子：

```java
class clParticleEmitter_Box: public iParticleEmitter
{
public:
  clParticleEmitter_Box(): FPosMin( 0 ), FPosMax( 1 ) {}
  virtual void EmitParticles( const clPtr<clParticleSystem>& PS, float DeltaTime ) const override
  {
    FAccumulatedTime += DeltaTime;
```

下面的循环一次发射一个所需数量的粒子。位置、速度、颜色、生存时间和大小都用均匀随机变量填充：

```java
    while ( FAccumulatedTime > 1.0f / FEmissionRate && PS->GetParticles().size() < FMaxParticles )
    {
      FAccumulatedTime -= 1.0f / FEmissionRate;
      sParticle P;
      P.FPosition = Math::RandomVector3InRange( FPosMin, FPosMax );
      P.FVelocity = Math::RandomVector3InRange( FVelMin, FVelMax );
      P.FAcceleration = LVector3( 0.0f );
      P.FTTL = Math::RandomInRange( FLifetimeMin, FLifetimeMax );
      P.FLifeTime = P.FTTL;
      P.FRGBA = Math::RandomVector4InRange( FColorMin, FColorMax );
      P.FRGBA.w = 1.0f;
      P.FSize = Math::RandomInRange(FSizeMin, FSizeMax);
      PS->AddParticle( P );
    }
  }
public:
  vec3 FPosMin, FPosMax;
};
```

这是可能最简单的发射器之一。

## 在游戏中使用粒子系统

我们的游戏还需要一个看起来不错爆炸效果。在`clParticleEmitter_Explosion`类中实现了以燃烧方式发射粒子的功能：

```java
class clParticleEmitter_Explosion: public iParticleEmitter
{
public:
  clParticleEmitter_Explosion()
  : FEmitted( false ), FCenter( 0.0f )
  , FRadialVelocityMin( 0.1f ), FRadialVelocityMax( 1.0f )
  , FAcceleration( 0.0f )
  {}
```

```java
  virtual void EmitParticles( const clPtr<clParticleSystem>& PS,
    float DeltaTime ) const override;
public:
  mutable bool FEmitted;
  vec3 FCenter;
  float FRadialVelocityMin, FRadialVelocityMax;
  vec3 FAcceleration;
};
```

构造函数将`FEmitted`字段设置为`false`。在第一次调用`EmitParticles()`时，此字段被设置为`true`，并发射固定数量的主粒子：

```java
void clParticleEmitter_Explosion::EmitParticles( const clPtr<clParticleSystem>& PS, float DeltaTime ) const
{
  auto& Particles = PS->GetParticles();
  size_t OriginalSize = Particles.size();
```

爆炸效果只添加一次大量粒子，但在每次顺序调用`EmitParticles()`时，会创建次级粒子，形成跟随主粒子路径的轨迹。对于现有粒子集合中的每个实体，都会创建一个附加粒子，以使粒子总数保持在`FMaxParticles`变量设定的预算内：

```java
  for ( size_t i = 0; i != OriginalSize; i++ )
  {
    if ( Particles[i].FRGBA.w > 0.99f && Particles.size() < FMaxParticles )
    {
      sParticle P;
      P.FPosition = Particles[i].FPosition;
      P.FVelocity = Particles[i].FVelocity * Math::RandomVector3InRange( vec3(0.1f), vec3(1.0f) );
      P.FAcceleration = FAcceleration;
      P.FTTL = Particles[i].FTTL * 0.5f;
      P.FLifeTime = P.FTTL;
      P.FRGBA = Particles[i].FRGBA * Math::RandomVector4InRange( vec4(0.5f), vec4(0.9f) );
      P.FRGBA.w = 0.95f;
      P.FSize = Particles[i].FSize * Math::RandomInRange(0.1f, 0.9f);
      PS->AddParticle( P );
    }
  }
```

一旦我们创建了爆炸效果，这个发射器将不再工作：

```java
  if ( FEmitted ) return;
  FEmitted = true;
```

下面的循环创建了一个方向在球体上均匀分布的粒子喷雾：

```java
  for ( size_t i = 0; i != FEmissionRate; i++ )
  {
    sParticle P;
```

使用两个均匀分布的随机变量作为角度，我们计算了均匀的随机方向：

```java
    float Theta = Math::RandomInRange( 0.0f, Math::TWOPI );
    float Phi = Math::RandomInRange( 0.0f, Math::TWOPI );
    float SinTheta = sin(Theta);
    float x = SinTheta * cos(Phi);
    float y = SinTheta * sin(Phi);
    float z = cos(Theta);
```

每个粒子从爆炸中心开始，速度与前面代码中计算出的随机方向相乘的随机大小一致：

```java
    P.FPosition = FCenter;
    P.FVelocity = vec3( x, y, z ).GetNormalized() * Math::RandomInRange( FRadialVelocityMin, FRadialVelocityMax );
    P.FAcceleration = FAcceleration;
```

生存时间、颜色和大小字段填充了均匀的随机值：

```java
    P.FTTL = Math::RandomInRange( FLifetimeMin, FLifetimeMax );
    P.FLifeTime = P.FTTL;
    P.FRGBA = Math::RandomVector4InRange( FColorMin, FColorMax );
    P.FRGBA.w = 1.0f;
    P.FSize = Math::RandomInRange( FSizeMin, FSizeMax );
    PS->AddParticle( P );
  }
}
```

## 在场景图中使用粒子系统

现在，我们准备声明并定义`clParticleSystemNode`类，它拥有一个`clParticleSystem`对象，带有粒子几何的`clGeometryNode`，以及`iParticleEmitter`对象的容器：

```java
class clParticleSystemNode: public clMaterialNode
{
private:
  std::vector< clPtr<iParticleEmitter> > m_Emitters;
  clPtr<clParticleSystem> m_Particles;
  clPtr<clGeometryNode> m_ParticlesNode;
public:
  clParticleSystemNode();
  virtual void UpdateParticles( float DeltaSeconds );
  virtual clPtr<clParticleSystem> GetParticleSystem() const 
  { return m_Particles; };
```

以下五个方法提供了对私有粒子发射器容器的访问权限：

```java
  virtual void AddEmitter( const clPtr<iParticleEmitter>& E )
  { m_Emitters.push_back(E); }
  virtual void RemoveEmitter( const clPtr<iParticleEmitter>& E )
  {
    m_Emitters.erase( std::remove( m_Emitters.begin(), m_Emitters.end(), E ), m_Emitters.end() );
  }
  virtual clPtr<iParticleEmitter> GetEmitter( size_t i ) const
  { return m_Emitters[i]; }
  virtual void SetEmitter( size_t i, const clPtr<iParticleEmitter> E )
  { m_Emitters[i] = E; }
  virtual size_t GetTotalEmitters() const
  { return m_Emitters.size(); }
};
```

构造函数实例化了一个粒子系统以及所有必要的场景节点：

```java
clParticleSystemNode::clParticleSystemNode()
{
  m_Particles = make_intrusive<clParticleSystem>();
  size_t MaxParticles = 20000;
  for ( const auto& i : m_Emitters )
  {
    if (i->FMaxParticles > MaxParticles)
      MaxParticles = i->FMaxParticles;
  }
  m_Particles->SetMaxParticles( static_cast<int>(MaxParticles) );
```

创建一个几何节点以存储粒子顶点：

```java
  m_ParticlesNode = make_intrusive<clGeometryNode>();
  m_ParticlesNode->SetVertexAttribs(m_Particles->GetVertices());
  this->Add( m_ParticlesNode );
```

从粒子系统中获取材质，并将其应用到场景节点上：

```java
  this->SetMaterial( m_Particles->GetDefaultMaterial() );
  UpdateParticles( 0.0f );
}
```

`clParticleSystemNode::UpdateParticles()`方法调用所有发射器，然后为`m_Particles`调用`clParticleSystem::UpdateParticles()`，并最终使用`clGLVertexAray::CommitChanges()`调用将新的粒子顶点数据发送到渲染 API：

```java
void clParticleSystemNode::UpdateParticles( float DeltaSeconds )
{
  for ( const auto& i : m_Emitters )
  {
    i->EmitParticles( m_Particles, DeltaSeconds );
  }
  m_Particles->UpdateParticles( DeltaSeconds );
  m_ParticlesNode->GetVA()->CommitChanges();
}
```

包含粒子属性的`clVertexAttribs`的渲染需要编写新的着色器。由于粒子代表了一种新的几何类型，我们扩展了我们的`clMaterialSystem`类，使其能够处理粒子材质：

```java
class clParticleMaterialSystem: public clMaterialSystem
{
public:
  clParticleMaterialSystem()
  {
    m_ParticleShaderPrograms[ ePass_Ambient ] = make_intrusive<clGLSLShaderProgram>( g_vShaderParticleStr, g_fShaderAmbientParticleStr );
    m_ParticleShaderPrograms[ ePass_Light ] = make_intrusive<clGLSLShaderProgram>( g_vShaderParticleStr, g_fShaderLightParticleStr );
    m_ParticleShaderPrograms[ ePass_Shadow ] = make_intrusive<clGLSLShaderProgram>( g_vShaderShadowParticleStr, g_fShaderShadowParticleStr );
  }
```

`GetShaderProgramForPass()`成员函数检查材质类是否为*Particle*，并从一组新的粒子着色器程序中选择一个着色器程序。否则，它会回退到旧的`clMaterialSystem`实现：

```java
  virtual clPtr<clGLSLShaderProgram> GetShaderProgramForPass( ePass Pass, const sMaterial& Mtl ) override
  {
    if ( Mtl.m_MaterialClass == "Particle" )
    return m_ParticleShaderPrograms[ Pass ];
    return clMaterialSystem::GetShaderProgramForPass( Pass, Mtl );
  }
```

此类中唯一的新字段是一个映射，用于保存每个通道的新编译着色器程序：

```java
private:
  std::map<ePass, clPtr<clGLSLShaderProgram>> m_ParticleShaderPrograms;
};
```

以下是渲染粒子所需的所有新着色器的源代码。顶点着色器在所有渲染通道之间共享，并执行公告板处理；这会将粒子对准到相机：

```java
static const char g_vShaderParticleStr[] = R"(
  uniform mat4 in_ModelViewProjectionMatrix;
  uniform mat4 in_NormalMatrix;
  uniform mat4 in_ModelMatrix;
  uniform mat4 in_ModelViewMatrix;
  uniform mat4 in_ShadowMatrix;
  in vec4 in_Vertex;
  in vec2 in_TexCoord;
  in vec3 in_Normal;
  in vec4 in_Color;
  out vec2 v_Coords;
  out vec3 v_Normal;
  out vec3 v_WorldNormal;
  out vec4 v_ProjectedVertex;
  out vec4 v_ShadowMapCoord;
  out vec3 v_Params;
  out vec4 v_Color;
```

与默认材质相同的投影变换缩放偏置：

```java
  mat4 GetProjScaleBiasMat()
  {
    // transform from -1..1 to 0..1
    return mat4( 
      0.5, 0.0, 0.0, 0.0,
      0.0, 0.5, 0.0, 0.0,
      0.0, 0.0, 0.5, 0.0,
      0.5, 0.5, 0.5, 1.0 );
  }
  void main()
  {
```

粒子应该被定向，使它们始终面向相机。让我们构建一个参考框架，其中向量`X`和`Y`与屏幕平行：

```java
    vec3 X = vec3( in_ModelViewMatrix[0][0], in_ModelViewMatrix[1][0], in_ModelViewMatrix[2][0] );
    vec3 Y = vec3(in_ModelViewMatrix[0][1], in_ModelViewMatrix[1][1], in_ModelViewMatrix[2][1] );
```

获取存储在法线 Z 分量中的粒子大小：

```java
    float SizeX = in_Normal.z;
    float SizeY = in_Normal.z;
```

使用纹理坐标来计算粒子中心偏移量：

```java
    vec3 XOfs = ( 2.0 * (in_TexCoord.x-0.5) * SizeX ) * X;
    vec3 YOfs = ( 2.0 * (in_TexCoord.y-0.5) * SizeY ) * Y;
    vec3 Position = in_Vertex.xyz + XOfs + YOfs;
```

使用模型视图投影矩阵变换顶点位置：

```java
    vec4 TransformedPos = in_ModelViewProjectionMatrix * vec4( Position, 1.0 );
    gl_Position = TransformedPos;
```

传递所有其他变量：

```java
    v_Coords = in_TexCoord.xy;
    v_Normal = mat3(in_NormalMatrix) * in_Normal;
    v_WorldNormal = ( in_ModelMatrix * vec4( in_Normal, 0.0 ) ).xyz;
    v_ProjectedVertex = GetProjScaleBiasMat() * in_ModelViewProjectionMatrix * vec4(Position, 1.0);
    v_ShadowMapCoord = in_ShadowMatrix * in_ModelMatrix * vec4(Position, 1.0);
    v_Params = in_Normal;
    v_Color  = in_Color;
  }
)";
```

片段着色器更为多样，需要不同的着色器来处理环境光、阴影和光照传递，以正确渲染粒子。以下是环境传递的粒子片段着色器：

```java
static const char g_fShaderAmbientParticleStr[] = R"(
  in vec2 v_Coords;
  in vec3 v_Normal;
  in vec3 v_WorldNormal;
```

`v_Params`的值来自`clParticleSystem::UpdateParticles()`函数，其中 TTL、生命周期和大小打包在一起：

```java
  in vec3 v_Params;
  in vec4 v_Color;
  out vec4 out_FragColor;
  uniform vec4 u_AmbientColor;
  uniform vec4 u_DiffuseColor;
  void main()
  {
    vec4 Color = v_Color * u_AmbientColor;
    float NormalizedTime = (v_Params.y-v_Params.x) / v_Params.y;
```

根据到粒子中心的距离计算透明度。这样可以得到没有使用任何纹理的圆润粒子：

```java
    float Falloff = 1.0 - 2.0 * length(v_Coords-vec2(0.5, 0.5));
    if ( NormalizedTime < 0.1 )
    {
      Falloff *= NormalizedTime / 0.1;
    }
    else if ( NormalizedTime > 0.5 )
    {
      Falloff *= 1.0 - (NormalizedTime-0.5) / 0.5;
    }
    Color.w = Falloff;
    out_FragColor = Color;
  }
)";
```

光照传递的片段着色器如下所示。它只是丢弃了片段，粒子不会对光源产生反应：

```java
static const char g_fShaderLightParticleStr[] = R"(
  in vec2 v_Coords;
  in vec3 v_Normal;
  in vec3 v_WorldNormal;
  in vec4 v_ProjectedVertex;
  in vec4 v_ShadowMapCoord;
  in vec3 v_Params;
  in vec4 v_Color;
  out vec4 out_FragColor;
  void main()
  {
    discard;
  }
)";
```

阴影映射生成传递可以用以下片段着色器处理。为每个粒子创建一个圆形阴影：

```java
static const char g_fShaderShadowParticleStr[] = R"(
  in vec2 v_Coords;
  in vec3 v_Params; /* TTL, LifeTime, Size */
  out vec4 out_FragColor;
  void main()
  {
    float NormalizedTime = (v_Params.y-v_Params.x) / v_Params.y;
```

在粒子生命周期的一半内，阴影会增大，之后缩小到零：

```java
    float Falloff = ( NormalizedTime < 0.5 ) ? NormalizedTime : 1.0-NormalizedTime;
    if ( length(v_Coords-vec2(0.5, 0.5)) > 0.5 * Falloff ) discard;
    out_FragColor = vec4( 1.0 );
  }
)";
```

在`1_Particles`示例中可以找到粒子渲染的演示。以下是运行应用程序的截图：

![在场景图中使用粒子系统](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-ndk/img/image00232.jpeg)

初始阶段，我们创建一个空的粒子系统节点，并将其传递给`GenerateExplosion()`函数，该函数为粒子系统添加了另一个爆炸效果。以下是实现方式：

```java
void GenerateExplosion( const clPtr<clParticleSystemNode>& ParticleNode, const vec3& Pos )
{
```

演示旨在在 Android 设备上运行；不要生成太多粒子：

```java
  if ( ParticleNode->GetParticleSystem()->GetParticles() .size() > 8000 ) return;
```

三种不同爆炸类型的调色板包括蓝色、红色和绿色：

```java
  const vec4 Pal[] = {
    vec4(0.2f, 0.30f, 0.8f, 1.0f),
    vec4(0.7f, 0.25f, 0.3f, 1.0f),
    vec4(0.1f, 0.80f, 0.2f, 1.0f)
  };
```

随机选择一种染色：

```java
  vec4 Color = Pal[ Math::RandomInRange(0, 3) ];
```

创建并设置发射器对象。强烈建议您玩转这些参数：

```java
  auto Emitter = make_intrusive<clParticleEmitter_Explosion>();
  Emitter->FCenter = Pos;
  Emitter->FSizeMin = 0.02f;
  Emitter->FSizeMax = 0.05f;
  Emitter->FLifetimeMin = 0.1f;
  Emitter->FLifetimeMax = 1.0f;
  Emitter->FMaxParticles = 10000;
  Emitter->FEmissionRate = 300;
  Emitter->FRadialVelocityMin = 1.0f;
  Emitter->FRadialVelocityMax = 2.0f;
  Emitter->FColorMin = Color;
  Emitter->FColorMax = Color;
  Emitter->FAcceleration = vec3( 0.0f, 0.0f, -3.0f );
  ParticleNode->AddEmitter( Emitter );
}
```

该函数从主循环中调用：

```java
  while( g_Window && g_Window->HandleInput() )
  {
    double NextSeconds = Env_GetSeconds();
    float DeltaTime = static_cast<float>( NextSeconds - Seconds );
    Seconds = NextSeconds;
    float SlowMotionCoef = 0.5f;
    if ( g_UpdateParticles )
    ParticleNode->UpdateParticles( SlowMotionCoef * DeltaTime );
```

投掷骰子以决定是否应添加另一个爆炸效果：

```java
    bool Add = Math::RandomInRange( 0, 100 ) > 50.0f;
```

如果粒子系统不包含活跃的粒子，则始终添加新的爆炸效果：

```java
    if ( !ParticleNode->GetParticleSystem()-> GetParticles().size() || Add )
    {
      GenerateExplosion( ParticleNode, Math::RandomVector3InRange(vec3(-1), vec3(+1)) );
    }
    OnDrawFrame();
    g_Window->Swap();
  }
```

尝试为 Android 构建此演示并在您的设备上运行。

# 小行星游戏

现在，我们已经准备好处理实际的游戏。本质上，游戏包含了许多前例拼接在一起，以共同运行并实现应用程序的不同方面。定义游戏逻辑的“胶水”在`clGameManager`类中，该类在`Game.cpp`和`Game.h`中定义。实际的类似鸟类的实体在`Actors.cpp`和`Actors.h`中实现。让我们从基类`iActor`开始：

```java
class iActor: public iIntrusiveCounter
{
public:
  iActor():
  m_Pos(0),
  m_Vel(0),
  m_Accel(0)
  {}
```

与所有前例的主要区别在于，这个游戏框架中没有`Render()`方法。相反，所有实体都应该知道如何附加到场景图以及从中分离。这些方法在子类中被重写，并且因不同类型的参与者而异：

```java
  virtual void AttachToScene( const clPtr<clSceneNode>& Scene ) = 0;
  virtual void DetachFromScene( const clPtr<clSceneNode>& Scene ) = 0;
```

一些代码在所有子类之间共享：

```java
  virtual void Update( float dt )
  {
    m_Vel += m_Accel * dt;
    m_Pos += m_Vel * dt;
  }
  virtual float GetRadius() const
  {
    return 0.1f;
  }
public:
  vec3 m_Pos;
  vec3 m_Vel;
  vec3 m_Accel;
};
```

小行星游戏实体是`clAsteroid`类的实例，非常简单：

```java
class clAsteroid: public iActor
{
public:
  clAsteroid()
  : m_Angle( Math::RandomInRange( 0.0f, 1.0f ) )
  {}
  virtual void AttachToScene( const clPtr<clSceneNode>& Scene ) override;
  virtual void DetachFromScene( const clPtr<clSceneNode>& Scene ) override;
  virtual void Update( float dt ) override;
private:
  clPtr<clMaterialNode> m_Node;
  float m_Angle;
};
```

实现几乎微不足道。更新位置并将其限制在游戏关卡的大小内：

```java
void clAsteroid::Update( float dt )
{
  iActor::Update( dt );
  m_Angle += dt;
  m_Pos = g_Game->ClampToLevel( m_Pos );
  mat4 ScaleFix = mat4::GetScaleMatrix( vec3(0.002f ) );
  mat4 Pos = mat4::GetTranslateMatrix( m_Pos );
```

小行星总是围绕`(1,1,1)`轴旋转：

```java
  mat4 Rot = mat4::GetRotateMatrixAxis( m_Angle, vec3( 1, 1, 1 ) );
  if ( m_Node )
    m_Node->SetLocalTransform( ScaleFix * Rot * Pos );
}
```

附加到场景主要是加载一个适当的 3D 模型的`.obj`文件并设置材质。黄色会很好看：

```java
void clAsteroid::AttachToScene( const clPtr<clSceneNode>& Scene )
{
  if ( !m_Node )
  {
    auto Geometry = LoadOBJSceneNode( g_FS->CreateReader( "deimos.obj" ) );
    sMaterial Material;
    Material.m_Ambient = vec4( 0.5f, 0.5f, 0.0f, 1.0f );
    Material.m_Diffuse = vec4( 0.5f, 0.5f, 0.0f, 1.0f );
    m_Node = make_intrusive<clMaterialNode>();
    m_Node->SetMaterial( Material );
    m_Node->Add( Geometry );
  }
  Scene->Add( m_Node );
}
```

从场景中分离很简单：

```java
void clAsteroid::DetachFromScene( const clPtr<clSceneNode>& Scene )
{
  Scene->Remove( m_Node );
}
```

`clRocket`类表示从太空船发射的火箭。除了`Update()`方法之外，一切都与`clAsteroid`的实现相似：

```java
void clRocket::Update(float dt)
{
  iActor::Update( dt );
  mat4 Pos = mat4::GetTranslateMatrix( m_Pos );
  if ( m_Node ) m_Node->SetLocalTransform( Pos );
```

如果火箭离开了关卡区域，就销毁它：

```java
  if ( !g_Game->IsInsideLevel( m_Pos ) )
  {
    g_Game->Kill( this );
  }
}
```

爆炸在`clExplosion`类中实现。`clExplosion::AttachToScene()`方法创建了一个与`GenerateExplosion()`中相似的发射器的粒子系统节点。那里没有什么有趣的。然而，`Update()`方法略有不同：

```java
void clExplosion::Update( float dt )
{
  iActor::Update( dt );
  mat4 ScaleFix = mat4::GetScaleMatrix( vec3(1.0f ) );
  mat4 Pos = mat4::GetTranslateMatrix(m_Pos);
  if ( m_Node )
  {
```

粒子系统节点需要更新。使用系数让粒子移动得更慢：

```java
    const float SlowMotionCoef = 0.1f;
    m_Node->SetLocalTransform( ScaleFix * Pos );
    m_Node->UpdateParticles( SlowMotionCoef * dt );
  }
```

当所有粒子消失后，销毁爆炸：

```java
  if ( !m_Node->GetParticleSystem()->GetParticles().size() )
  {
    g_Game->Kill( this );
  }
}
```

最后但同样重要的是，`clSpaceShip`类表示一个可由玩家控制的实体。同样，最有趣的部分是处理用户控制的`Update()`方法：

```java
void clSpaceShip::Update( float dt )
{
  iActor::Update( dt );
```

询问游戏管理器是否按下了任何控制键：

```java
  if ( g_Game->IsKeyPressed( SDLK_LEFT ) )
  {
    m_Angle += dt;
  }
  if ( g_Game->IsKeyPressed( SDLK_RIGHT ) )
  {
    m_Angle -= dt;
  }
  bool Accel = g_Game->IsKeyPressed( SDLK_UP );
  bool Decel = g_Game->IsKeyPressed( SDLK_DOWN );
  m_Accel = vec3( 0.0f );
  if ( Accel )
  {
    m_Accel = GetDirection();
  }
  if ( Decel )
  {
    m_Accel += -GetDirection();
  }
  if ( g_Game->IsKeyPressed( SDLK_SPACE ) )
  {
    Fire();
  }
```

让船在关卡的相对两侧之间进行跃迁：

```java
  m_Pos = g_Game->ClampToLevel( m_Pos );
```

我们不希望它移动得太快；这里实现了速度衰减和限制。

```java
  m_Vel *= 0.99f;
  const float MaxVel = 1.1f;
  if ( m_Vel.Length() > MaxVel ) m_Vel = ( m_Vel / m_Vel.Length() ) * MaxVel;
```

使用时间计数器限制发射速率：

```java
  m_FireTime -= dt;
  if ( m_FireTime < 0 ) m_FireTime = 0.0f;
```

缩放和旋转 3D 模型以匹配所需的大小和方向：

```java
  mat4 ScaleFix = mat4::GetScaleMatrix( vec3(0.1f ) );
  mat4 RotFix = mat4::GetRotateMatrixAxis( 90.0f * Math::DTOR, vec3(0,0,1) );
  mat4 Pos = mat4::GetTranslateMatrix(m_Pos);
  mat4 Rot = mat4::GetRotateMatrixAxis( m_Angle, vec3(0,0,1) );
```

应用累积变换：

```java
  if ( m_Node ) m_Node->SetLocalTransform( ScaleFix * RotFix * Rot * Pos );
}
```

`Fire`方法所做的正是它看起来要做的事。它发射火箭并维持发射速率：

```java
void clSpaceShip::Fire()
{
  if ( m_FireTime > 0.0f ) return;
```

尝试改变武器冷却时间。一秒是默认值：

```java
  const float FireCooldown = 1.0f;
  m_FireTime = FireCooldown;
```

游戏管理器添加实际的火箭实体：

```java
  g_Game->FireRocket( m_Pos, m_Vel * Math::RandomInRange( 1.1f, 1.5f ) + GetDirection() );
}
```

这些都是游戏中存在的实体。让我们快速浏览一下统治它们的`clGameManager`类：

```java
class clGameManager: public iIntrusiveCounter
{
public:
  clGameManager();
```

更新所有对象的状态并计算碰撞：

```java
  virtual void GenerateTicks();
```

使用渲染技术绘制游戏世界：

```java
  virtual void Render();
  virtual void OnKey( int Key, bool Pressed );
  clPtr<clSceneNode> GetSceneRoot() const { return m_Scene; };
  virtual bool IsKeyPressed( int Code );
```

有两个函数用于创建新实体；它们在`clSpaceShip`和`CheckCollisions()`中使用：

```java
  virtual void FireRocket( const vec3& Pos, const vec3& Vel );
  virtual void AddExplosion( const vec3& Pos, const vec3& Dir );
```

一些高级数学函数用于处理实体位置：

```java
  virtual bool IsInsideLevel( const vec3& Pos );
  virtual vec3 ClampToLevel( const vec3& Pos );
```

销毁游戏演员，可能是小行星、爆炸或火箭。在我们的游戏中，太空船永存。`Kill()`方法不会立即移除演员。相反，它会将演员添加到一个容器中，稍后在`PerformExecution()`方法中处理：

```java
  virtual void Kill( iActor* Actor );
```

名字说明了一切。以“即发即忘”的方式播放音频文件：

```java
  virtual void PlayAudioFile( const std::string& FileName );
private:
  void PerformExecution();
  void SpawnRandomAsteroids( size_t N );
  void CheckCollisions();
private:
  clPtr<clSceneNode> m_Scene;
  clPtr<clSpaceShip> m_SpaceShip;
  std::vector< clPtr<clAsteroid> > m_Asteroids;
  std::vector< clPtr<clRocket> > m_Rockets;
  std::vector< clPtr<clExplosion> > m_Explosions;
  std::unordered_map<int, bool> m_Keys;
  vec3 m_LevelMin;
  vec3 m_LevelMax;
  std::vector< iActor* > m_DeathRow;
  std::vector< clPtr<clAudioSource> > m_Sounds;
  // file name -> blob
  std::map< std::string, clPtr<clBlob> > m_SoundFiles;
};
```

游戏逻辑的大中央调度位于`GenerateTicks()`方法中：

```java
void clGameManager::GenerateTicks()
{
  const float DeltaSeconds = 0.05f;
```

更新一切，检查碰撞，并移除死亡对象：

```java
  for ( const auto& i: m_Asteroids ) i->Update( DeltaSeconds );
  for ( const auto& i: m_Rockets ) i->Update( DeltaSeconds );
  for ( const auto& i: m_Explosions ) i->Update( DeltaSeconds );
  m_SpaceShip->Update( DeltaSeconds );
  CheckCollisions();
  PerformExecution();
  for ( size_t i = 0; i != m_Sounds.size(); i++ )
  {
    if ( !m_Sounds[i]->IsPlaying() )
    {
```

逐一移除已停止的音频源：

```java
      g_Audio.UnRegisterSource( m_Sounds[i].GetInternalPtr() );
      m_Sounds[i]->Stop();
      m_Sounds[i] = m_Sounds.back();
      m_Sounds.pop_back();
      break;
    }
  }
}
```

碰撞检查是用一个简单的`O(n²)`算法完成的：

```java
void clGameManager::CheckCollisions()
{
  for ( size_t i = 0; i != m_Rockets.size(); i++ )
  {
    for ( size_t j = 0; j != m_Asteroids.size(); j++ )
    {
      vec3 PosR = m_Rockets[i]->m_Pos;
      vec3 PosA = m_Asteroids[j]->m_Pos;
      float R = m_Asteroids[j]->GetRadius();
```

如果火箭足够接近小行星，就销毁两者并产生巨大的爆炸：

```java
      if ( (PosR-PosA).Length() < R )
      {
        this->Kill(m_Rockets[i].GetInternalPtr());
        this->Kill(m_Asteroids[j].GetInternalPtr());
        AddExplosion( m_Asteroids[j]->m_Pos, m_Rockets[i]->m_Vel );
      }
    }
  }
}
```

执行很快，但需要一些 C++模板魔法：

```java
void clGameManager::PerformExecution()
{
  for ( const auto& i : m_DeathRow )
  {
    i->DetachFromScene( m_Scene );
    Remove( m_Asteroids, i );
    Remove( m_Explosions, i );
    Remove( m_Rockets, i );
  }
  m_DeathRow.clear();
}
```

这是处理异构实体容器的模板代码：

```java
template <typename Container, typename Entity>
void Remove( Container& c, Entity e )
{
  auto iter = std::remove_if( c.begin(), c.end(),  e 
    {
      return Ent == e;
    } );
  c.erase( iter, c.end() );
}
```

如果你是一个 C++14 的粉丝，你绝对可以用`const auto&`替换 lambda 参数中的`const typename Container::value_type&`，但我们的 Visual Studio 2013 拒绝编译新代码。

这里未提及的其他功能可以在`1_Asteroids`示例中找到。构建并运行代码，效果应如下所示：

![Asteroids 游戏](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-ndk/img/image00233.jpeg)

# 总结

在本章中，我们总结了书中展示的许多技巧，并使用 Android NDK 实现了一个可移植的游戏应用。我们所有 C++代码调试的核心在于能够不变地在桌面计算机上运行我们的游戏。这种方法在调试大型 C++移动应用以及在将这些应用整合到新内容时提供了极大的便利和更快的迭代速度。此外，专业的移动开发永远不会只关注一个平台。通过这些开发实践，你可以编写在许多移动平台（包括 Android 和 iOS）上运行的 C++代码。
