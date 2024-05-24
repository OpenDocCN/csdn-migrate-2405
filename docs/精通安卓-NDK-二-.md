# 精通安卓 NDK（二）

> 原文：[`zh.annas-archive.org/md5/F3DC9D6FA4DADE68301DCD4BEC565947`](https://zh.annas-archive.org/md5/F3DC9D6FA4DADE68301DCD4BEC565947)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：组织虚拟文件系统

在本章中，我们将实现低级别的抽象，以处理操作系统无关的文件和文件系统访问。我们将展示如何实现可移植且透明地访问`.apk`文件内部打包的 Android 资源，而不依赖于任何内置 API。在桌面环境中构建可调试的多平台应用程序时，这种方法是必要的。

# 挂载点

挂载点的概念几乎在现代每一个文件系统中都可以找到。对于跨平台 C++程序来说，以一种统一的方式来访问异构存储设备中的文件非常方便。例如，在 Android 上，每个只读数据文件可以存储在`.apk`包内，开发者被迫使用特定的 Android 资产管理 API。在 OSX 和 iOS 上，访问程序束需要另一个 API，在 Windows 上，应用程序应该将其所有内容存储在其文件夹中，该文件夹的物理路径也取决于应用程序安装的位置。

为了在不同平台之间组织文件访问，我们提出了一个浅层类层次结构，它抽象了文件管理的差异，如下面的图所示：

![挂载点](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-ndk/img/image00221.jpeg)![挂载点](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-andr-ndk/img/image00222.jpeg)

虚拟文件系统是挂载点的集合。每个挂载点都是一个文件系统文件夹的抽象。这种组织方式允许我们将实际的操作系统特定文件访问例程和文件名映射从应用程序代码中隐藏起来。本章涵盖了文件系统、挂载点和流接口的描述。

我们定义了一个`iMountPoint`接口，它可以解析虚拟文件名，并创建文件阅读对象的实例：

```java
class iMountPoint: public iIntrusiveCounter
{
public:
```

检查在这个挂载点是否存在的虚拟文件：

```java
  virtual bool FileExists( const std::string& VirtualName ) const = 0;
```

将虚拟文件名转换为绝对文件名：

```java
  virtual std::string MapName( const std::string& VirtualName ) const = 0;
```

`CreateReader()`成员函数创建一个文件阅读器对象，该对象实现了本章后续介绍的`iRawFile`接口。这个方法通常只被`clFileSystem`类使用：

```java
  virtual clPtr<iRawFile> CreateReader( const std::string& VirtualName ) const = 0;
```

最后两个成员函数获取和设置此挂载点的内部名称。这个字符串稍后会在`clFileSystem`接口中使用，以搜索和识别挂载点：

```java
  virtual void SetName( const std::string& N ) { FName = N; }
  virtual std::string GetName() const { return FName; }
private:
  std::string FName;
};
```

我们的虚拟文件系统实现为挂载点的线性集合。这里的`clFileSystem::CreateReader()`方法创建一个`iIStream`对象，该对象封装了对文件数据的访问：

```java
clPtr<iIStream> CreateReader( const std::string& FileName ) const;
```

`Mount()`方法将一个物理（这里*物理*指的是特定操作系统的路径）路径添加到挂载点列表中。如果`PhysicalPath`值表示本地文件系统的一个文件夹，则会创建一个`clPhysicalMountPoint`实例。如果`PhysicalPath`是一个`.zip`或`.apk`文件的名称，则会将`clArchiveMountPoint`实例添加到挂载点列表中。`clPhysicalMountPoint`和`ArchiveMountPoint`类的定义可以在代码包中的示例`1_ArchiveFileAccess`中找到：

```java
void Mount( const std::string& PhysicalPath );
```

`VirtualNameToPhysical()`将我们的虚拟路径转换为特定操作系统的系统文件路径：

```java
std::string VirtualNameToPhysical(
  const std::string& Path ) const;
```

`FileExists()`方法检查每个挂载点，以确定文件是否存在于其中一个挂载点中：

```java
  bool FileExists( const std::string& Name ) const;
```

`clFileSystem`类的私有部分负责管理内部挂载点列表。`FindMountPoint()`方法搜索包含名为`FileName`的文件的挂载点。`FindMountPointByName()`方法在内部使用，允许文件名称的别名。`AddMountPoint()`检查提供的挂载点是否唯一，如果是，则将其添加到`FMountPoints`容器中：

```java
private:
  clPtr<iMountPoint> FindMountPointByName( const std::string& ThePath );
  void AddMountPoint( const clPtr<iMountPoint>& MP );
  clPtr<iMountPoint> FindMountPoint( const std::string& FileName ) const;
```

最终，挂载点集合存储在`std::vector`中：

```java
  std::vector< clPtr<iMountPoint> > FMountPoints;
};
```

当我们想在应用程序代码中访问一个文件时，我们是通过文件系统对象`g_FS`来实现的：

```java
auto f = g_FS->CreateReader( "test.txt" );
```

# 挂载点与流

在 Android 上，`test.txt`文件很可能位于`.apk`包中，需要在`CreateReader()`调用中完成大量工作。`test.txt`的数据被提取出来，并创建了一个`clMemFileMapper`实例。让我们深入探究文件操作背后的隐藏管道。

`CreateReader()`的代码很简单。首先，我们将路径中的斜杠和反斜杠转换为与底层操作系统匹配的样式。然后找到一个包含名为`FileName`的文件的挂载点。最后，创建一个`clFileMapper`实例。这个类实现了`iIStream`接口。让我们仔细看看这些类：

```java
clPtr<iIStream> clFileSystem::CreateReader(
  const std::string& FileName ) const
{
  std::string Name = Arch_FixFileName( FileName );
  clPtr<iMountPoint> MountPoint = FindMountPoint( Name );
```

在这里，我们使用空对象模式（[`en.wikipedia.org/wiki/Null_Object_pattern`](http://en.wikipedia.org/wiki/Null_Object_pattern)）来定义非存在文件的中性行为。`clNullRawFile`类表示一个不与任何实际设备关联的空文件：

```java
  if ( !MountPoint ) { return make_intrusive<clFileMapper>( make_intrusive<clNullRawFile>() ); }
  return make_intrusive<clFileMapper>( MountPoint->CreateReader( Name ) );
}
```

`FindMountPoint()`方法遍历挂载点集合，以找到包含给定名称文件的挂载点：

```java
clPtr<iMountPoint> clFileSystem::FindMountPoint( const std::string& FileName ) const
{
  if ( FMountPoints.empty() )
  {
    return nullptr;
  }
  if ( ( *FMountPoints.begin() )->FileExists( FileName ) )
  {
    return ( *FMountPoints.begin() );
  }
```

反向迭代挂载点，以便首先检查最近挂载的路径：

```java
  for ( auto i = FMountPoints.rbegin();
    i != FMountPoints.rend(); ++i )
  {
    if ( ( *i )->FileExists( FileName ) )
    {
      return ( *i );
    }
  }
  return *( FMountPoints.begin() );
}
```

`clFileSystem`类将大部分工作委托给各个`iMountPoint`实例。例如，检查文件是否存在是通过找到适当的`iMountPoint`对象并询问该点是否存在文件来执行的：

```java
bool clFileSystem::FileExists( const std::string& Name ) const
{
  if ( Name.empty() || Name == "." ) { return false; }
  clPtr<iMountPoint> MP = FindMountPoint( Name );
  return MP ? MPD->FileExists( Name ) : false;
}
```

也可以通过适当的`iMountPoint`实例找到物理文件名：

```java
std::string clFileSystem::VirtualNameToPhysical(
  const std::string& Path ) const
{
  if ( FS_IsFullPath( Path ) ) { return Path; }
  clPtr<iMountPoint> MP = FindMountPoint( Path );
  return ( !MP ) ? Path : MP->MapName( Path );
}
```

物理文件名不直接用于访问文件。例如，如果挂载了一个存档，并且我们想要访问存档中的文件，那么该文件的物理路径对操作系统来说是没有意义的。相反，一切都由挂载点抽象化，物理文件名只在我们应用程序中作为标识符使用。

只有当新的挂载点是唯一的时候，它才会被添加到集合中；没有理由允许重复。

```java
void clFileSystem::AddMountPoint( const clPtr<iMountPoint>& MP )
{
  if ( !MP ) { return; }
  if ( std::find( FMountPoints.begin(), FMountPoints.end(), MP ) == FMountPoints.end() )
  {
    FMountPoints.push_back( MP );
  }
}
```

`clFileSystem::Mount()`的代码选择要实例化的挂载点类型：

```java
void clFileSystem::Mount( const std::string& PhysicalPath )
{
  clPtr<iMountPoint> MP;
```

我们在这里使用了一个简单的硬编码逻辑。如果路径以`.zip`或`.apk`子字符串结尾，我们将实例化`clArchiveMountPoint`：

```java
  if ( Str::EndsWith( PhysicalPath, ".apk" ) || Str::EndsWith( PhysicalPath, ".zip" ) )
  {
    auto Reader = make_intrusive<clArchiveReader>();
    bool Result = Reader->OpenArchive( CreateReader( PhysicalPath ) );
    MP = make_intrusive<clArchiveMountPoint>( Reader );
  }
  else
```

否则，我们将检查`clPhysicalPath`是否存在，然后创建`clPhysicalMountPoint`：

```java
  {
    #if !defined( OS_ANDROID )
      if ( !FS_FileExistsPhys( PhysicalPath ) )
      return;
    #endif
      MP = make_intrusive<clPhysicalMountPoint>(PhysicalPath );
  }
```

如果创建挂载点成功，我们设置其名称并将其添加到集合中：

```java
  MP->SetName( PhysicalPath );
  AddMountPoint( MP );
}
```

我们稍后会回到挂载点的实现。现在，我们转向流。对文件的实际读取访问是通过`iIStream`接口完成的：

```java
class iIStream: public iIntrusiveCounter
{
public:
```

接下来的两个方法分别获取虚拟和物理文件名：

```java
  virtual std::string GetVirtualFileName() const = 0;
  virtual std::string GetFileName() const = 0;
```

`Seek()`方法设置绝对读取位置；`GetSize()`和`GetPos()`确定大小和当前的读取位置，而`Eof()`检查是否已达到文件末尾：

```java
  virtual void   Seek( const uint64 Position ) = 0;
  virtual uint64 GetSize() const = 0;
  virtual uint64 GetPos() const = 0;
  virtual bool   Eof() const = 0;
```

`Read()`方法将指定`Size`的数据块读取到无类型内存缓冲区`Buf`中：

```java
  virtual uint64 Read( void* Buf, const uint64 Size ) = 0;
```

最后两个方法使用内存映射实现对文件数据的数组式访问。第一个返回与此文件对应的共享内存的指针：

```java
  virtual const ubyte* MapStream() const = 0;
```

第二个方法返回从当前文件位置开始的内存指针。这对于在块和内存映射访问样式之间无缝切换非常方便：

```java
  virtual const ubyte* MapStreamFromCurrentPos() const = 0;
};
```

为了避免 UI 线程阻塞，这些方法通常应该在工作者线程上调用。

所有访问物理文件的工作都在`clFileMapper`类中完成。它是`iIStream`接口的一个实现，将所有 I/O 操作委托给实现`iRawFile`接口的对象。`iRawFile`本身在应用程序代码中不直接使用，所以让我们先看看`clFileMapper`类：

```java
class clFileMapper: public iIStream
{
public:
```

构造函数只是存储了对`iRawFile`实例的引用，并重置了读取指针：

```java
  explicit FileMapper( clPtr<iRawFile> File ):
    FFile( File ), FPosition( 0 ) {}
  virtual ~FileMapper() {}
```

`GetVirtualFileName()`和`GetFileName()`方法使用`iRawFile`的实例分别获取虚拟和物理文件名：

```java
  virtual std::string GetVirtualFileName() const
  { return FFile->GetVirtualFileName(); }
  virtual std::string GetFileName() const
  { return FFile->GetFileName(); }
```

`Read()`方法模拟了`std::ifstream.read`和`libc`中的`read()`例程。它可能看起来不寻常，但读取是通过访问内存映射文件的`memcpy`调用完成的。`iRawFile::GetFileData()`的描述将澄清这些问题：

```java
  virtual uint64 Read( void* Buf, uint64 Size )
  {
    uint64 RealSize = ( Size > GetBytesLeft() ) ? GetBytesLeft() : Size;
    if ( !RealSize ) { return 0; }
    memcpy( Buf, ( FFile->GetFileData() + FPosition ),static_cast<size_t>( RealSize ) );
    FPosition += RealSize;
    return RealSize;
  }
```

定位和内存映射都委托给底层的`iRawFile`实例：

```java
  virtual void Seek( const uint64 Position)
  { FPosition = Position; }
  virtual uint64 GetSize() const
  { return FFile->GetFileSize(); }
  virtual bool Eof() const
  { return ( FPosition >= FFile->GetFileSize() ); }
  virtual const ubyte* MapStream() const
  { return FFile->GetFileData(); }
  virtual const ubyte* MapStreamFromCurrentPos() const
  { return ( FFile->GetFileData() + FPosition ); }
```

私有部分包含了对`iRawFile`的引用和当前的读取位置：

```java
private:
  clPtr<iRawFile> FFile;
  uint64 FPosition;
};
```

现在我们可以声明`iRawFile`接口，它非常简单：

```java
class iRawFile: public iIntrusiveCounter
{
public:
  iRawFile() {}
  virtual ~iRawFile() {}
```

前四个方法获取和设置虚拟和物理文件名：

```java
  std::string GetVirtualFileName() const
  { return FVirtualFileName; }
  std::string  GetFileName() const
  { return FFileName; }
    void SetVirtualFileName( const std::string& VFName )
    { FVirtualFileName = VFName; }
    void SetFileName( const std::string& FName )
    { FFileName = FName; }
```

这个接口的实质在于以下两个方法，它们获取文件数据的原始指针和文件的大小：

```java
    virtual const ubyte* GetFileData() const = 0;
    virtual uint64 GetFileSize() const = 0;
```

私有部分包含文件名的字符串：

```java
  private:
    std::string    FFileName;
    std::string    FVirtualFileName;
  };
```

声明完所有接口后，我们可以继续进行它们的实现。

# 访问宿主文件系统中的文件

我们从`clRawFile`类开始，它使用特定于操作系统的内存映射例程将文件映射到内存中：

```java
class clRawFile: public iRawFile
{
public:
  RawFile() {}
  virtual ~RawFile() { Close(); }
```

`Open()`成员函数完成了大部分繁重的工作。它存储物理和虚拟文件名，打开文件句柄并创建文件的映射视图：

```java
  bool Open( const std::string& FileName,
    const std::string& VirtualFileName )
  {
    SetFileName( FileName );
    SetVirtualFileName( VirtualFileName );
    FSize = 0;
    FFileData = nullptr;
```

在 Windows 上，我们使用`CreateFileA()`来打开文件。像往常一样，我们将特定于操作系统的部分用`#ifdef`块括起来。：

```java
    #ifdef _WIN32
      FMapFile = CreateFileA( FFileName.c_str(), GENERIC_READ,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS,
        nullptr );
```

打开文件后，我们创建一个映射对象，并使用 `MapViewOfFile()` 系统调用获取指向文件数据的指针：

```java
      FMapHandle = CreateFileMapping( FMapFile,
        nullptr, PAGE_READONLY, 0, 0, nullptr );
      FFileData = ( ubyte* )MapViewOfFile( FMapHandle, FILE_MAP_READ, 0, 0, 0 );
```

如果出现错误，请关闭句柄并取消操作：

```java
      if ( !FFileData )
      {
        CloseHandle( ( HANDLE )FMapHandle );
        return false;
      }
```

为了防止读取超出文件末尾，我们应该获取文件的大小。在 Windows 中是这样完成的：

```java
      DWORD dwSizeLow = 0, dwSizeHigh = 0;
      dwSizeLow = ::GetFileSize( FMapFile, &dwSizeHigh );
      FSize = ( ( uint64 )dwSizeHigh << 32 )
        | ( uint64 )dwSizeLow;
```

在 Android 中，我们使用 `open()` 初始化文件句柄，并使用 `fstat()` 获取其大小：

```java
    #else
      FFileHandle = open( FileName.c_str(), O_RDONLY );
      struct stat FileInfo;
```

如果 `fstat()` 成功，我们可以获取其大小。如果文件大小非零，我们调用 `mmap()` 函数将文件映射到内存中：

```java
      if ( !fstat( FFileHandle, &FileInfo ) )
      {
        FSize = static_cast<uint64_t>( FileInfo.st_size );
```

确保对于大小为零的文件不调用 `mmap()`：

```java
      if ( FSize )
        FFileData = ( uint8_t* )( mmap( nullptr, FSize, PROT_READ, MAP_PRIVATE, FFileHandle, 0 ) );
      }
```

一旦我们有了 `mmap`-ed 的内存块，就可以立即关闭文件句柄。这是标准做法：

```java
      close( FFileHandle );
    #endif
      return true;
  }
```

`Close()` 方法取消内存块映射并关闭文件句柄：

```java
  void Close()
  {
```

在 Windows 中，我们使用 `UnmapViewOfFile()` 和 `CloseHandle()` 系统调用：

```java
    #ifdef _WIN32
      if ( FFileData  ) { UnmapViewOfFile( FFileData ); }
      if ( FMapHandle ) { CloseHandle( (HANDLE)FMapHandle ); }
      CloseHandle( ( HANDLE )FMapFile );
```

在 Android 中，我们调用 `munmap()` 函数：

```java
    #else
      if ( FFileData )
      {
        munmap( reinterpret_cast<void*>( FFileData ), FSize );
      }
    #endif
  }
```

`clRawFile` 类的其余部分包含两个简单的方法，返回文件数据指针和文件大小。私有部分声明文件句柄、文件大小和数据指针：

```java
  virtual const ubyte* GetFileData() const { return FFileData; }
  virtual uint64       GetFileSize() const { return FSize; }
private:
  #ifdef _WIN32
    HANDLE    FMapFile;
    HANDLE    FMapHandle;
  #else
    int       FFileHandle;
  #endif
    ubyte*    FFileData;
    uint64    FSize;
};
```

要使用 `clFileSystem` 类访问虚拟文件系统中的物理文件夹，我们声明了 `clPhysicalMountPoint` 类，代表宿主文件系统上的单个文件夹：

```java
class clPhysicalMountPoint: public iMountPoint
{
public:
```

`clPhysicalMountPoint` 的构造函数通过添加一个路径分隔符（根据底层操作系统的约定是斜杠或反斜杠）来修复物理文件夹路径：

```java
  clPhysicalMountPoint( const std::string& PhysicalName ):FPhysicalName( PhysicalName )
  {
    Str_AddTrailingChar( &FPhysicalName, PATH_SEPARATOR );
  }
  virtual ~PhysicalMountPoint() {}
```

`FileExists()` 方法使用依赖于操作系统的例程来检查文件是否存在：

```java
  virtual bool FileExists( const std::string& VirtualName ) const override
  {
    return FS_FileExistsPhys( MapName( VirtualName ) );
  }

```

`MapName()` 方法通过添加 `FPhysicalName` 前缀将虚拟文件转换为物理文件名。`FS_IsFullPath()` 例程在以下代码中定义：

```java
  virtual std::string  MapName( const std::string& VirtualName )const override
  {
    return FS_IsFullPath( VirtualName ) ? VirtualName : ( FPhysicalName + VirtualName );
  }
```

`clRawFile` 实例是在 `clPhysicalMountPoint::CreateReader()` 方法中创建的：

```java
  virtual clPtr<iRawFile> CreateReader(
    const std::string& VirtualName ) const override
  {
    std::string PhysName = MapName( VirtualName );
    auto File = make_intrusive<clRawFile>();
    if ( File->Open( FS_ValidatePath( PhysName ), VirtualName ) ) { return File; }
    return make_intrusive<clNullRawFile>();
  }
```

类的私有部分包含文件夹的物理名称：

```java
private:
  std::string FPhysicalName;
};
```

为了完成此代码，我们必须实现一些服务例程。第一个是 `FS_IsFullPath()`，它检查路径是否为绝对路径。对于 Android，这意味着路径以 `/` 字符开始，对于 Windows，完整路径必须以 `<drive>:\` 子字符串开始，其中 `<drive>` 是驱动器字母：

```java
inline bool FS_IsFullPath( const std::string& Path )
{
  return ( Path.find( ":\\" ) != std::string::npos ||
  #if !defined( _WIN32 )
    ( Path.length() && Path[0] == '/' ) ||
  #endif
    Path.find( ":/" )  != std::string::npos ||
    Path.find( ".\\" ) != std::string::npos );
}
```

`FS_ValidatePath()` 方法将每个斜杠或反斜杠字符替换为特定于平台的 `PATH_SEPARATOR`：

```java
inline std::string FS_ValidatePath( const std::string& PathName )
{
  std::string Result = PathName;
  for ( size_t i = 0; i != Result.length(); ++i )
    if ( Result[i] == '/' || Result[i] == '\\' )
    {
      Result[i] = PATH_SEPARATOR;
    }
  return Result;
}
```

要检查文件是否存在，我们使用 `stat()` 例程，其语法在 Windows 和 Android 上略有不同：

```java
inline bool FS_FileExistsPhys( const std::string& PhysicalName )
{
  #ifdef _WIN32
    struct _stat buf;
    int Result = _stat( FS_ValidatePath( PhysicalName ).c_str(),
      &buf );
  #else
    struct stat buf;
    int Result = stat( FS_ValidatePath( PhysicalName ).c_str(),
      &buf );
  #endif
    return Result == 0;
}
```

`PATH_SEPARATOR` 是一个特定于平台的字符常量：

```java
#if defined( _WIN32 )
  const char PATH_SEPARATOR = '\\';
#else
  const char PATH_SEPARATOR = '/';
#endif
```

上述代码足以访问直接存储在宿主文件系统上的文件。接下来，我们继续了解其他抽象概念以获取 Android `.apk` 包。

# 内存文件

以下 `iRawFile` 接口的实现封装了对未类型化内存块的访问作为文件访问。我们将使用此类来访问存档中的未压缩数据。

```java
class clMemRawFile: public iRawFile
{
public:
```

参数化构造函数用于初始化指向数据缓冲区的指针及其大小：

```java
  clMemRawFile( const uint8_t* BufPtr, size_t BufSize, bool OwnsBuffer )
  : FOwnsBuffer( OwnsBuffer )
  , FBuffer( BufPtr )
  , FBufferSize( BufSize )
  {}
```

对于一个内存块来说，内存映射是微不足道的，我们只需返回存储的原始指针：

```java
  virtual const uint8_t* GetFileData() const override
  { return FBuffer; }
  virtual uint64_t GetFileSize() const override
  { return FBufferSize; }
private:
  const uint8_t* FBuffer;
  size_t FBufferSize;
};
```

当我们处理归档文件读取时，将回到这个类。现在，让我们熟悉一个更多重要的概念，这是透明访问`.apk`包所必需的。

# 别名

前一节提到的文件抽象非常强大。它们可以用来创建嵌套的挂载点，以访问其他文件中打包的文件。让我们通过定义`clAliasMountPoint`来展示这种方法的灵活性，它类似于 Unix 或 NTFS 文件系统中的符号链接。

该实现将每个`iMountPoint::`方法调用重定向到另一个挂载点实例，同时在运行时通过为我们想要访问的每个虚拟文件名添加一个特定的`FAlias`前缀来转换文件名：

```java
class clAliasMountPoint: public iMountPoint
{
public:
  explicit clAliasMountPoint( const clPtr<iMountPoint>& Src )
  : Falias(), FMP( Src )
  {}
  virtual bool FileExists( const std::string& VirtualName ) const { return FMP->FileExists( FAlias + VirtualName ); }
  virtual std::string MapName( const std::string& VirtualName ) const { return FMP->MapName( FAlias + VirtualName ); }
  virtual clPtr<iRawFile> CreateReader( const std::string& VirtualName ) const { return FMP->CreateReader( FAlias + VirtualName ); }
private:
  std::string FAlias;
  clPtr<iMountPoint> FMP;
};
```

我们添加了`FileSystem::AddAlias()`成员函数，它通过将它们与`FAlias`前缀连接起来，来装饰现有挂载点的文件名：

```java
void clFileSystem::AddAlias( const std::string& SrcPath, const std::string& Alias )
{
  if (clPtr<iMountPoint> MP = FindMountPointByName( SrcPath ) ) AddMountPoint(new AliasMountPoint( MP, Alias ) );
}
```

这种机制可以用来将路径（如`assets/`）透明地重映射到我们文件系统的根目录，这对于 Android 上的应用程序功能至关重要。

# 写文件

在开始更复杂的归档解包工作之前，让我们先休息一下，看看如何写入文件。我们使用`iOStream`接口，它只声明了四个纯虚方法。`GetFileName()`方法返回虚拟文件名。`Seek()`方法设置写入位置，`GetFilePos()`返回它。`Write()`方法接受一个无类型的内存缓冲区并将其写入输出流：

```java
class iOStream: public iIntrusiveCounter
{
public:
  iOStream() {};
  virtual ~iOStream() {};
  virtual std::string GetFileName() const = 0;
  virtual void   Seek( const uint64 Position ) = 0;
  virtual uint64 GetFilePos() const = 0;
  virtual uint64 Write(const void* Buf, const uint64 Size) = 0;
};
```

我们在这里提供的`iOStream`的唯一实现是`clMemFileWriter`，它将一个无类型的内存块视为输出流。这个类用于访问`.zip`文件中的数据。首先，数据被解包，然后使用`clMemRawFile`进行包装：

```java
class clMemFileWriter: public iOStream
{
public:
```

实际的底层内存块由存储在此类中的`clBlob`对象通过 RAII 管理（[`en.wikipedia.org/wiki/Resource_Acquisition_Is_Initialization`](https://en.wikipedia.org/wiki/Resource_Acquisition_Is_Initialization)）：

```java
  clMemFileWriter()
  : FBlob( make_intrusive<clBlob>() )
  , FFileName()
  , FPosition( 0 )
  {}
  explicit clMemFileWriter( const clPtr<clBlob>& Blob )
  : FBlob( Blob )
  , FFileName()
  , FPosition( 0 )
  {}
```

`Seek()`方法增加当前的写入位置：

```java
  virtual void Seek( const uint64 Position )
  {
    FPosition = ( Position > FBlob->GetSize() ) ? FBlob->GetSize() - 1 : Position;
  }
```

`Write()`方法重定向到`clBlob`对象：

```java
  virtual uint64_t Write( const void* Buf, uint64_t Size ) override
  {
    return FBlob->AppendBytes( Buf,static_cast<size_t>( Size ) );
  }
```

伴随的源代码包含了`clFileWriter`类的实现，其中包含了类似于`clRawFile::Open()`的`Open()`方法。`Write()`方法使用系统 I/O 例程将数据写入物理文件。

现在，我们有足够的脚手架代码可以进一步处理`.zip`归档。

# 访问归档文件

由于`.apk`实际上就是一个花哨的`.zip`压缩包，我们使用了 Jean-loup Gailly 的 ZLib 库结合 MiniZIP 库来从中获取压缩文件。完整的源代码大约有 500 千字节大小，因此我们提供了两个文件，`libcompress.c`和`libcompress.h`，它们可以轻松地集成到任何构建过程中。我们的目标是实现`clArchiveMountPoint`，它枚举归档中的文件，为特定文件解压缩数据，并创建一个`clMemFileMapper`来读取其数据。为此，我们需要引入一个辅助类，`clArchiveReader`，它读取和解压缩`.zip`归档文件：

```java
class clArchiveReader: public iIntrusiveCounter
{
private:
```

`clArchiveReader`类中定义的私有的`sFileInfo`结构体封装了一组有用的文件属性以及指向压缩文件数据的指针：

```java
  struct sFileInfo
  {
    /// offset to the file
    uint64 FOffset;
    /// uncompressed file size
    uint64 FSize;
    /// compressed file size
    uint64 FCompressedSize;
    /// Compressed data
    void* FSourceData;
  };
```

`clArchiveReader`类的私有部分包含一个`sFileInfo`结构的集合，在`FFileInfos`字段中，一个包含大写文件名的`FFileNames`向量，一个包含归档内文件名的`FReadFileNames`向量，以及一个`std::map`对象，它将每个文件名映射到解压文件向量`FExtractedFromArchive`中的索引：

```java
  std::vector<sFileInfo> FFileInfos;
  std::vector<std::string> FFileNames;
  std::vector<std::string> FRealFileNames;
  mutable std::map<std::string, int> FFileInfoIdx;
  std::map<int, const void*> FExtractedFromArchive;
```

`FSourceFile`字段保存指向`.apk`文件的源文件流的指针：

```java
  clPtr<iIStream> FSourceFile;
public:
  clArchiveReader()
  : FFileInfos()
  , FRealFileNames()
  , FFileInfoIdx()
  , FSourceFile()
  {}
  virtual ~clArchiveReader()
  { CloseArchive(); }
```

`OpenArchive()`成员函数调用`Enumerate_ZIP()`来填充`FFileInfos`容器。`CloseArchive()`执行一些必要的清理工作：

```java
  bool OpenArchive( const clPtr<iIStream>& Source )
  {
   if ( !Source ) { return false; }
   if ( !CloseArchive() ) { return false; }
   if ( !Source->GetSize() ) { return false ; }
   FSourceFile = Source;
   return Enumerate_ZIP();
  }
  bool CloseArchive()
  {
    FFileInfos.clear();
    FFileInfoIdx.clear();
    FFileNames.clear();
    FRealFileNames.clear();
    ClearExtracted();
    FSourceFile = nullptr;
    return true;
  }
```

下面将详细描述长的`ExtractSingleFile()`方法。它接受来自归档的压缩文件名和一个包含文件数据的`iOStream`对象。`AbortFlag`是指向原子布尔标志的指针，用于多线程解压缩。解压缩器会不时地轮询它。如果值设置为`true`，则内部解压缩循环会提前终止，`ExtractSingleFile()`返回`false`。

`Progress`指针用于更新解压缩进程的进度，这也应该是原子操作。如果归档文件已加密，可以提供一个可选的`Password`参数：

```java
  bool ExtractSingleFile( const std::string& FileName,
    const std::string& Password, std::atomic<int>* AbortFlag,
    std::atomic<float>* Progress, const clPtr<iOStream>& Out );
```

接下来的两个方法使用`FFileInfos`向量来检查此归档中是否存在文件并获取其解压缩的大小：

```java
  bool FileExists( const std::string& FileName ) const
  {
    return GetFileIdx( FileName ) > -1;
  }
  uint64 GetFileSizeIdx( const std::string& FileName ) const
  {
    return ( Idx > -1 ) ? FFileInfos[ Idx ].FSize : 0;
  }
```

`GetFileDataIdx()`方法首先检查文件是否已经解压缩。在这种情况下，返回来自`FExtractedFromArchive`的指针：

```java
  const void* GetFileDataIdx( int Idx )
  {
    if ( Idx <= -1 ) { return nullptr; }
    if ( FExtractedFromArchive.count( Idx ) > 0 )
    {
      return FExtractedFromArchive[Idx]->GetDataConst();
    }
```

如果文件尚未解压缩，将调用`GetFileData_ZIP()`函数，并从`clBlob`返回一个已解包的内存块：

```java
    auto Blob = GetFileData_ZIP( Idx );
    if ( Blob )
    {
      FExtractedFromArchive[Idx] = Blob;
      return Blob->GetDataConst();
    }
    return nullptr;
  }
```

`GetFileIdx()`方法将`FileName`映射到`FFileInfos`向量内部的索引。它使用辅助的`FFileInfoIdx`对象来存储字符串到索引的对应关系：

```java
  int GetFileIdx( const std::string& FileName ) const
  {
    return ( FFileInfoIdx.count( FileName ) > 0 ) ? FFileInfoIdx[ FileName ] : -1;
  }
```

最后两个公共函数返回归档中的文件数量和每个文件的名称：

```java
  size_t GetNumFiles() const { return FFileInfos.size(); }
  std::string GetFileName( int Idx ) const
  { return FFileNames[Idx]; }
```

`clArchiveReader`类的私有部分声明了用于解压缩数据管理的内部方法。`Enumerate_ZIP()`方法通过读取归档头填充`FFileInfos`容器。`GetFileData_ZIP()`成员函数从归档中提取文件数据：

```java
private:
  bool Enumerate_ZIP();
  const void* GetFileData_ZIP( size_t Idx );
```

`ClearExtracted()`方法是从`CloseArchive()`中调用的。它会释放每个解压文件所分配的内存。这里的一切都是通过`clBlob`类使用 RAII 管理的：

```java
  void ClearExtracted()
  {
    FExtractedFromArchive.clear();
  }
```

让我们看看使用`ExtractSingleFile()`方法的`GetFileData_ZIP()`方法的实现：

```java
  clPtr<clBlob> clArchiveReader::GetFileData_ZIP( int Idx )
  {
    if ( FExtractedFromArchive.count( Idx ) > 0 )
    {
      return FExtractedFromArchive[ Idx ];
    }
```

创建包含解压缩数据的`clMemFileWriter`对象：

```java
    clPtr<clMemFileWriter> Out =
      clFileSystem::CreateMemWriter( "mem_blob",
        FFileInfos[ Idx ].FSize );
```

`ExtractSingleFile()`处理解压缩。在这里我们使用了一个阻塞调用（`AbortFlag`参数为`nullptr`）和一个空密码：

```java
    if ( ExtractSingleFile( FRealFileNames[ Idx ], "",
      nullptr, nullptr, Out ) )
    {
```

如果调用成功，我们从`clMemFileWriter`对象返回解压缩的内容：

```java
      return Out->GetBlob();
    }
    return make_intrusive<clBlob>();
  }
```

`ExtractSingleFile()`方法创建`zlib`读取对象，将读取器定位在压缩文件数据的开头，并调用`ExtractCurrentFile_ZIP()`方法以执行实际解压缩：

```java
  bool clArchiveReader::ExtractSingleFile(
    const std::string& FileName, const std::string& Password,
    std::atomic<int>* AbortFlag, std::atomic<float>* Progress,
    const clPtr<iOStream>& Out )
  {
    std::string ZipName = FileName;
    std::replace( ZipName.begin(), ZipName.end(), '\\', '/' );
    clPtr<iIStream> TheSource = FSourceFile;
    FSourceFile->Seek( 0 );
```

我们创建内部结构，允许`zlib`从我们的`iIStream`对象中读取。稍后在`Enumerate_ZIP()`中也会进行同样的操作。`fill_functions()`例程以及与此相关的所有回调都在本节下面描述：

```java
    zlib_filefunc64_def ffunc;
    fill_functions( TheSource.GetInternalPtr(), &ffunc );
    unzFile UnzipFile = unzOpen2_64( "", &ffunc );
    if ( unzLocateFile(UnzipFile, ZipName.c_str(), 0) != UNZ_OK )
    {
```

如果在归档中没有找到文件，则返回`false`：

```java
      return false;
    }
```

一旦定位了读取器，我们调用`ExtractCurrentFile_ZIP()`方法：

```java
    int ErrorCode = ExtractCurrentFile_ZIP( UnzipFile,
      Password.empty() ? nullptr : Password.c_str(),
      AbortFlag, Progress, Out );
    unzClose( UnzipFile );
    return ErrorCode == UNZ_OK;
  }
```

我们解压缩器的核心在于`ExtractCurrentFile_Zip`()。该方法接收一个内存块作为输入，读取文件的解压缩字节，并将其写入输出流：

```java
  int ExtractCurrentFile_ZIP( unzFile UnzipFile,
    const char* Password, std::atomic<int>* AbortFlag,
    std::atomic<float>* Progress, const clPtr<iOStream>& Out )
  {
    char FilenameInzip[1024];
    unz_file_info64 FileInfo;
```

`unzGetCurrentFileInfo64()`函数检索未压缩的文件大小。我们用它来计算总进度并将其写入`Progress`参数：

```java
    int ErrorCode = unzGetCurrentFileInfo64( UnzipFile,
      &FileInfo, FilenameInzip, sizeof( FilenameInzip ),
      nullptr, 0, nullptr, 0 );
    if ( ErrorCode != UNZ_OK ) { return ErrorCode; }
```

`unzOpenCurrentFilePassword()`调用初始化了解压缩过程：

```java
    ErrorCode = unzOpenCurrentFilePassword( uf, password );
    if ( ErrorCode != UNZ_OK ) { return err; }
```

方法的最后部分是一个循环，该循环读取一包解压缩的字节，并调用`Out`对象的`iOStream::Write`方法：

```java
    uint64_t FileSize = ( uint64_t )FileInfo.uncompressed_size;
```

在基于内存映射文件的示例实现中，我们将 64 位文件大小转换为`size_t`。这实际上在 32 位目标上打破了大于 2Gb 文件的支持。然而，这种权衡在大多数实际移动应用中是可以接受的，除非你正在编写通用的`.zip`解压缩器，当然：

```java
    Out->Reserve( ( size_t )FileSize );
    unsigned char Buffer[ WRITEBUFFERSIZE ];
    uint64_t TotalBytes = 0;
    int BytesRead = 0;
    do
    {
```

如果需要，我们可以通过检查`AbortFlag`指针（由另一个线程设置）来决定是否跳出循环：

```java
      if ( AbortFlag && *AbortFlag ) break;

```

`unzReadCurrentFile()`函数执行到输出流的解压缩：

```java
      BytesRead = unzReadCurrentFile( UnzipFile, Buffer, WRITEBUFFERSIZE );
      if ( BytesRead < 0 ) { break; }
      if ( BytesRead > 0 )
      {
        TotalBytes += BytesRead;
        Out->Write( Buffer, BytesRead );
      }
```

写入解压缩数据后，我们相应地更新`Progress`计数器：

```java
      if ( Progress )
      {
        *Progress = (float)TotalBytes / (float)FileSize;
      }
    }
    while ( BytesRead > 0 );
```

最后，我们关闭`UnzipFile`读取器对象：

```java
    ErrorCode = unzCloseCurrentFile( UnzipFile );
    return ErrorCode;
  }
```

归档中文件的枚举是通过另一个名为`Enumerate_ZIP()`的成员函数完成的：

```java
  bool Enumerate_ZIP()
  {
    clPtr<iIStream> TheSource = FSourceFile;
    FSourceFile->Seek( 0 );
```

首先，我们填充`zlib`所需的回调以读取自定义文件流，在本例中是我们的`iIStream`对象：

```java
    zlib_filefunc64_def ffunc;
    fill_functions( TheSource.GetInternalPtr(), &ffunc );
    unzFile UnzipFile = unzOpen2_64( "", &ffunc );
```

然后，读取归档的头部以确定压缩文件的数量：

```java
    unz_global_info64 gi;
    int ErrorCode = unzGetGlobalInfo64( uf, &gi );
```

对于每个压缩文件，我们提取稍后用于解压缩的信息：

```java
    for ( uLong i = 0; i < gi.number_entry; i++ )
    {
      if ( ErrorCode != UNZ_OK ) { break; }
      char filename_inzip[256];
      unz_file_info64 file_info;
      ErrorCode = unzGetCurrentFileInfo64( UnzipFile, &file_info, filename_inzip, sizeof(filename_inzip), nullptr, 0, nullptr, 0 );
      if ( ErrorCode != UNZ_OK ) { break; }
      if ( ( i + 1 ) < gi.number_entry )
      {
        ErrorCode = unzGoToNextFile( UnzipFile );
        if ( ErrorCode != UNZ_OK ) { break; }
      }
```

在每次迭代中，我们填充`sFileInfo`结构并将其存储在`FFileInfos`向量中：

```java
      sFileInfo Info;
      Info.FOffset = 0;
      Info.FCompressedSize = file_info.compressed_size;
      Info.FSize = file_info.uncompressed_size;
      FFileInfos.push_back( Info );
```

文件名中的所有反斜杠都被转换为在归档内路径元素之间起分隔作用的字符。`FFileInfoIdx`映射被填充，以便快速查找文件索引：

```java
      std::string TheName = Arch_FixFileName(filename_inzip);
      FFileInfoIdx[ TheName ] = ( int )FFileNames.size();
      FFileNames.emplace_back( TheName );
      FRealFileNames.emplace_back( filename_inzip );
    }
```

最后，我们清理`zlib`读取器对象并返回成功代码：

```java
    unzClose( UnzipFile );
    return true;
  }
```

让我们仔细看看`fill_functions()`方法。内存块包含在`iIStream`中，因此我们实现了一组`zlib`需要的回调，以便与我们的流类一起工作。第一个方法`zip_fopen()`对`iIStream`进行准备：

```java
  static voidpf ZCALLBACK zip_fopen ( voidpf opaque, const void* filename, int mode )
  {
    ( ( iIStream* )opaque )->Seek( 0 );
    return opaque;
  }
```

从`iIStream`读取字节的操作在`zip_fread()`中实现：

```java
  static uLong ZCALLBACK zip_fread ( voidpf opaque, voidpf stream, void* buf, uLong size )
  {
    iIStream* S = ( iIStream* )stream;
    int64 CanRead = ( int64 )size;
    int64 Sz = S->GetSize();
    int64 Ps = S->GetPos();
    if ( CanRead + Ps >= Sz ) { CanRead = Sz - Ps; }
    if ( CanRead > 0 ) {  S->Read( buf, ( uint64 )CanRead ); }
    else { CanRead = 0; }
    return ( uLong )CanRead;
  }
```

`zip_ftell()`函数告诉`iIStream`中的当前位置：

```java
  static ZPOS64_T ZCALLBACK zip_ftell(voidpf opaque, voidpf stream)
  {
    return ( ZPOS64_T )( ( iIStream* )stream )->GetPos();
  }
```

`zip_fseek()`例程设置读取指针，就像`libc`的`fseek()`一样：

```java
  static long ZCALLBACK zip_fseek ( voidpf  opaque, voidpf stream, ZPOS64_T offset, int origin )
  {
    iIStream* S = ( iIStream* )stream;
    int64 NewPos = ( int64 )offset;
    int64 Sz = ( int64 )S->GetSize();
    switch ( origin )
    {
      case ZLIB_FILEFUNC_SEEK_CUR:
        NewPos += ( int64 )S->GetPos(); break;
      case ZLIB_FILEFUNC_SEEK_END:
        NewPos = Sz - 1 - NewPos; break;
      case ZLIB_FILEFUNC_SEEK_SET: break;
      default:  return -1;
    }
    if ( NewPos >= 0 && ( NewPos < Sz ) )
    {
      S->Seek( ( uint64 )NewPos );
    }
    else
    {
      return -1;
    }
    return 0;
  }
```

对于`iIstream`类，`fclose()`和`ferror()`的类似操作是微不足道的：

```java
  static int ZCALLBACK zip_fclose( voidpf opaque, voidpf stream )
  {
    return 0;
  }
  static int ZCALLBACK zip_ferror( voidpf opaque, voidpf stream )
  {
    return 0;
  }
```

辅助`fill_functions()`例程填充了`zlib`使用的回调结构：

```java
  void fill_functions( iIStream* Stream, zlib_filefunc64_def* pzlib_filefunc_def )
  {
    pzlib_filefunc_def->zopen64_file = zip_fopen;
    pzlib_filefunc_def->zread_file = zip_fread;
    pzlib_filefunc_def->zwrite_file = NULL;
    pzlib_filefunc_def->ztell64_file = zip_ftell;
    pzlib_filefunc_def->zseek64_file = zip_fseek;
    pzlib_filefunc_def->zclose_file = zip_fclose;
    pzlib_filefunc_def->zerror_file = zip_ferror;
    pzlib_filefunc_def->opaque = Stream;
  }
```

这就是关于低级解压缩细节的全部内容。让我们进入更友好的抽象和包装领域。`clArchiveMountPoint`类包装了`clArchiveReader`的一个实例，并实现了`CreateReader()`、`FileExists()`和`MapName()`方法：

```java
  class clArchiveMountPoint: public iMountPoint
  {
  public:
    explicit clArchiveMountPoint( const clPtr<ArchiveReader>& R )
    : FReader(R) {}
```

`CreateReader()`方法实例化`clMemRawFile`类并附加一个提取的内存块：

```java
    virtual clPtr<iRawFile> CreateReader(
      const std::string& VirtualName ) const
    {
      std::string Name = Arch_FixFileName( VirtualName );
      const void* DataPtr  = FReader->GetFileData( Name );
      size_t FileSize = static_cast<size_t>( FReader->GetFileSize( Name ) );
      auto File = clMemRawFile::CreateFromManagedBuffer( DataPtr, FileSize );
      File->SetFileName( VirtualName );
      File->SetVirtualFileName( VirtualName );
      return File;
    }
```

`FileExists()`方法是对`clArchiveReader::FileExists()`的间接调用：

```java
    virtual bool FileExists( const std::string& VirtualName )const
    {
      return FReader->FileExists( Arch_FixFileName( VirtualName ) );
    }
```

对于此类挂载点，`MapName()`的实现是微不足道的：

```java
    virtual std::string MapName( const std::string& VirtualName ) const
    { return VirtualName; }
```

私有部分只包含对`clArchiveReader`对象的引用：

```java
  private:
    clPtr<clArchiveReader> FReader;
  };
```

显而易见，简单的`clArchiveMountPoint`的缺点在于其非异步阻塞实现。构造函数接受一个完全初始化的`clArchiveReader`对象，这意味着我们需要阻塞直到`clArchiveReader::OpenArchive()`完成其工作。克服此问题的一种方法是在不同的线程上运行`OpenArchive()`，在任务队列中，并在解析归档后创建挂载点。当然，所有后续调用`CreateReader()`以期望从此挂载点获取数据的操作应该推迟，直到收到信号。我们鼓励读者使用前一章讨论的`clWorkerThread`类实现这种异步机制。更复杂的归档挂载点实现可以接受构建的`clArchiveReader`并自行调用`OpenArchive()`。这需要更复杂的架构，因为`clFileSystem`和/或`clArchiveMountPoint`类应该能够访问专用的工人线程。然而，它本质上将所有耗时的解压缩操作复杂性隐藏在简洁的接口背后。

# 访问应用程序资产

要在 Android 上的 C++代码中访问`.apk`包内的数据，我们需要使用 Java 代码获取`.apk`的路径，并使用 JNI 将结果传递给我们的 C++代码。

在`onCreate()`方法中，将来自`getApplication().getApplicationInfo().sourceDir`的值传递给我们的本地代码：

```java
  @Override protected void onCreate( Bundle icicle )
  {
    onCreateNative( getApplication().getApplicationInfo().sourceDir );
  }
  public static native void onCreateNative( String APKName );
```

`onCreateNative()`的实现可以在`1_ArchiveFileAccess\jni\Wrappers.cpp`中找到，如下所示：

```java
  extern "C"
  {
    JNIEXPORT void JNICALL
    Java_com_packtpub_ndkmastering_AppActivity_onCreateNative( JNIEnv* env, jobject obj, jstring APKName )
    {
      g_APKName = ConvertJString( env, APKName );
      LOGI( "APKName = %s", g_APKName.c_str() );
      OnStart( g_APKName );
    }
  }
```

我们使用`ConvertJString()`函数将`jstring`转换为`std::string`。JNI 方法`GetStringUTFChars()`和`ReleaseStringUTFChars()`获取和释放指向字符串的 UTF8 编码字符数组的指针：

```java
  std::string ConvertJString( JNIEnv* env, jstring str )
  {
    if ( !str ) { return std::string(); }
    const jsize len = env->GetStringUTFLength( str );
    const char* strChars = env->GetStringUTFChars( str, ( jboolean* )0 );
    std::string Result( strChars, len );
    env->ReleaseStringUTFChars( str, strChars );
    return Result;
  }
```

在`main.cpp`文件中的`OnStart()`回调中实现了简单的使用示例。它挂载路径，在 Android 上创建归档挂载点，打开归档`test.zip`并列出其内容。在桌面上，此代码运行并读取存储在`assets/test.zip`的`test.zip`：

```java
  void OnStart( const std::string& RootPath )
  {
    auto FS = make_intrusive<clFileSystem>();
    FS->Mount( "" );
    FS->Mount( RootPath );
    FS->AddAliasMountPoint( RootPath, "assets" );
    const char* ArchiveName = "test.zip";
    auto File = FS->CreateReader( ArchiveName );
    auto Reader = make_intrusive<clArchiveReader>();
    if ( !Reader->OpenArchive( File ) )
    {
      LOGI( "Bad archive: %s", ArchiveName );
      return;
    }
```

遍历此归档中的所有文件并打印它们的名字和内容：

```java
    for ( size_t i = 0; i != Reader->GetNumFiles(); i++ )
    {
      LOGI( "File[%i]: %s", i,
      Reader->GetFileName( i ).c_str() );
      const char* Data = reinterpret_cast<const char*>( Reader->GetFileDataIdx( i ) );
      LOGI( "Data: %s", std::string( Data,
        static_cast<size_t>(
          Reader->GetFileSizeIdx( i ) ) ).c_str() );
    }
  }
```

查看并尝试`1_ArchiveFileAccess`示例。它为在桌面上调试 Android 文件访问代码提供了很好的体验。使用`make all`构建桌面环境，使用`ndk-build & ant debug`构建 Android。

# 概述

在本章中，我们学习了如何以与平台无关的方式通过 C++处理文件和`.apk`归档。我们将在后续章节中使用此功能来访问文件。


# 第五章：跨平台音频流

在本章中，我们考虑构建交互式移动应用程序所需的最后一个非视觉组件。我们寻找的是一个真正可移植的音频播放实现，适用于 Android 和桌面 PC。我们建议使用 OpenAL 库，因为它在桌面平台上已经非常成熟。音频播放本质上是一个异步过程，因此解码并将数据提交给声音 API 应该在单独的线程上完成。我们将基于第三章的*网络编程*中的多线程代码创建一个音频流库。

原始未压缩音频可能占用大量内存，因此经常使用不同种类的压缩格式。我们将在本章考虑其中一些格式，并展示如何使用原生 C++代码和流行的第三方库在 Android 中播放它们。

# 初始化和播放

本章节我们将使用跨平台的 OpenAL 音频库。为了使所有示例保持简洁且自包含，我们从可以播放未压缩`.wav`文件的最小化示例开始。

让我们简要描述一下产生声音需要做些什么。OpenAL 的例程处理播放和录音过程中遇到的对象。`ALCdevice`对象代表音频硬件的一个单元。由于多个线程可能同时产生声音，因此引入了另一个名为`ALCcontext`的对象。首先，应用程序打开一个设备，然后创建一个上下文并将其附加到打开的设备上。每个上下文都维护着多个`Audio Source`对象，因为即使单个应用程序也可能需要同时播放多个声音。

我们越来越接近实际的声音产生。还需要一个对象作为波形容器，这称为缓冲区。音频录音可能相当长，所以我们不会将整个声音作为一个缓冲区提交。我们以小块读取样本，并使用几个缓冲区（通常是一对）将这些块提交到音频源的队列中。

以下伪代码描述了如何播放完全适合内存的声音：

1.  首先打开一个设备，创建一个上下文，并将上下文附加到设备上。

1.  创建一个音频源，分配一个声音缓冲区。

1.  将波形数据加载到缓冲区中。

1.  将缓冲区入队到音频源。

1.  等待播放完成。

1.  销毁缓冲区、源和上下文，并关闭设备。

在第 5 步有一个明显的问题。我们无法将应用程序的 UI 线程阻塞几秒钟，因此声音播放必须是异步的。幸运的是，OpenAL 调用是线程安全的，我们可以在没有自己进行任何 OpenAL 同步的情况下在单独的线程中执行播放。

让我们检查示例`1_InitOpenAL`。为了在步骤 3 中执行波形加载并尽可能保持代码简单，我们取一个`.wav`文件并将其加载到`clBlob`对象中。在步骤 2 中，我们创建一个音频源和缓冲区，其参数与`WAV`头中的参数相对应。步骤 1、4 和 6 仅包含一些 OpenAL API 调用。步骤 5 通过在原子条件变量上进行忙等待循环来完成。

这个示例的本地 C++入口点从创建一个单独的音频线程开始，该线程声明为全局对象`g_Sound`。`g_FS`对象包含`clFileSystem`类的实例，用于从文件加载音频数据：

```java
clSoundThread g_Sound;
clPtr<clFileSystem> g_FS;
int main()
{
  g_FS = make_intrusive<clFileSystem>();
  g_FS->Mount( "." );
  g_Sound.Start();
  g_Sound.Exit( true );
  return 0;
}
```

`clSoundThread`类包含一个 OpenAL 设备和上下文。音频源和缓冲区句柄也为此单一源单一缓冲区的示例而声明：

```java
class clSoundThread: public iThread
{
  ALCdevice* FDevice;
  ALCcontext* FContext;
  ALuint FSourceID;
  ALuint FBufferID;
```

`Run()`方法负责所有初始化、加载和结束工作：

```java
  virtual void Run()
  {
```

要使用 OpenAL 例程，我们应该加载库。对于 Android、Linux 和 OS X，实现很简单，我们只需使用静态链接库即可。然而，对于 Windows，我们加载`OpenAL32.dll`文件，并从动态链接库中获取所有必要的函数指针：

```java
    LoadAL();
```

首先，我们打开一个设备并创建一个上下文。`alcOpenDevice()`的`nullptr`参数意味着我们正在使用默认的音频设备：

```java
    FDevice = alcOpenDevice( nullptr );
    FContext = alcCreateContext( FDevice, nullptr );
    alcMakeContextCurrent( FContext );
```

然后我们创建一个音频源并将其音量设置为最大级别：

```java
    alGenSources( 1, &FSourceID );
    alSourcef( FSourceID, AL_GAIN, 1.0 );
```

波形的加载，对应于我们伪代码中的第 3 步，通过将整个`.wav`文件读取到`clBlob`对象中完成：

```java
    auto data = LoadFileAsBlob( g_FS, "test.wav" );
```

可以通过以下方式访问头文件：

```java
    const sWAVHeader* Header = ( const sWAVHeader* )Blob->GetData();
```

我们从`clBlob`中复制字节到声音缓冲区，跳过头文件对应大小的字节数：

```java
    const unsigned char* WaveData = ( const unsigned char* )Blob->GetData() +
      sizeof( sWAVHeader );
    PlayBuffer( WaveData, Header->DataSize,
      Header->SampleRate );
```

现在让我们忙等待声音播放完毕：

```java
    while ( IsPlaying() ) {}
```

最后，我们停止源，删除所有对象并卸载 OpenAL 库：

```java
    alSourceStop( FSourceID );
    alDeleteSources( 1, &FSourceID );
    alDeleteBuffers( 1, &FBufferID );
    alcDestroyContext( FContext );
    alcCloseDevice( FDevice );
    UnloadAL();
  }
```

`clSoundThread`类还包含两个辅助方法。`IsPlaying()`方法通过请求其状态来检查声音是否仍在播放：

```java
  bool IsPlaying() const
  {
    int State;
    alGetSourcei( FSourceID, AL_SOURCE_STATE, &State );
    return State == AL_PLAYING;
  }
```

`PlayBuffer()`方法创建一个缓冲区对象，用`Data`参数中的波形填充它并开始播放：

```java
  void PlayBuffer( const unsigned char* Data, int DataSize, int SampleRate )
  {
    alBufferData( FBufferID, AL_FORMAT_MONO16,
      Data, DataSize, SampleRate );
    alSourcei( FSourceID, AL_BUFFER, FBufferID );
    alSourcei( FSourceID, AL_LOOPING, AL_FALSE );
    alSourcef( FSourceID, AL_GAIN, 1.0f );
    alSourcePlay( FSourceID );
  }
```

上述代码依赖于两个全局函数。`Env_Sleep()`函数以给定的毫秒数休眠。Windows 版本的代码与 Android 和 OS X 略有不同：

```java
  void Env_Sleep( int Milliseconds )
  {
    #if defined(_WIN32)
      Sleep( Milliseconds );
    #elif defined(ANDROID)
      std::this_thread::sleep_for(
        std::chrono::milliseconds( Milliseconds ) );
    #else
      usleep( static_cast<useconds_t>( Milliseconds ) * 1000 );
    #endif
  }
```

### 注意

我们在 Windows 上使用`Sleep()`以与一些缺乏对`std::chrono`支持的 MinGW 发行版兼容。如果你想要使用 Visual Studio，只需坚持使用`std::this_thread::sleep_for()`。

`LoadFileAsBlob()`函数使用提供的`clFileSystem`对象将文件内容加载到内存块中。我们在后续的大部分代码示例中重复使用这个例程。

```java
  clPtr<clBlob> LoadFileAsBlob( const clPtr<clFileSystem>& FileSystem, const std::string& Name )
  {
    auto Input = FileSystem->CreateReader( Name );
    auto Res = make_intrusive<clBlob>();
    Res->AppendBytes( Input->MapStream(), Input->GetSize() );
    return Res;
  }
```

如果你在桌面机器上通过输入`make all`编译并运行此示例，你应该能听到一个短暂的叮当声。在我们结束 Android 应用程序之前，让我们进一步了解如何进行声音流处理。

# 流式声音

现在我们能够播放短音频样本，是时候将音频系统组织成类，并仔细查看`2_Streaming`示例了。长音频样本（如背景音乐）在解压缩形式下需要大量内存。流式传输是一种小块小块地、逐片解压缩它们的技术。`clAudioThread`类负责初始化并处理除播放声音之外的所有工作：

```java
  class clAudioThread: public iThread
  {
  public:
    clAudioThread()
    : FDevice( nullptr )
    , FContext( nullptr )
    , FInitialized( false )
    {}
    virtual void Run()
    {
      if ( !LoadAL() ) { return; }
      FDevice = alcOpenDevice( nullptr );
      FContext = alcCreateContext( FDevice, nullptr );
      alcMakeContextCurrent( FContext );
      FInitialized = true;
      while ( !IsPendingExit() ) { Env_Sleep( 100 ); }
      alcDestroyContext( FContext );
      alcCloseDevice( FDevice );
      UnloadAL();
    }
```

此方法用于将音频线程的开始与其用户同步：

```java
    virtual void WaitForInitialization() const
    {
      while ( !FInitialized ) {}
    }
  private:
    std::atomic<bool> FInitialized;
    ALCdevice* FDevice;
    ALCcontext* FContext;
  };
```

`clAudioSource`类代表单一声音产生实体。波形数据不是存储在源本身中，我们推迟对`clAudioSource`类的描述。现在，我们介绍提供下一个音频缓冲区数据的`iWaveDataProvider`接口类。对`iWaveDataProvider`实例的引用存储在`clAudioSource`类中：

```java
  class iWaveDataProvider: public iIntrusiveCounter
  {
  public:
```

音频信号属性存储在这三个字段中：

```java
    int FChannels;
    int FSamplesPerSec;
    int FBitsPerSample;
    iWaveDataProvider()
    : FChannels( 0 )
    , FSamplesPerSec( 0 )
    , FBitsPerSample( 0 ) {}
```

两个纯虚方法提供了对音频源当前播放的波形数据的访问。它们应在实际的解码器子类中实现：

```java
    virtual unsigned char* GetWaveData() = 0;
    virtual size_t GetWaveDataSize() const = 0;
```

`IsStreaming()`方法告诉我们此提供程序是否代表连续流或如前一个示例中的单个音频数据块。`StreamWaveData()`方法加载、解码或生成`GetWaveData()`函数访问的缓冲区中的值；它通常也在子类中实现。当`clAudioSource`需要更多音频数据以排队进入缓冲区时，它会调用`StreamWaveData()`方法：

```java
    virtual bool IsStreaming() const { return false; }
    virtual int StreamWaveData( int Size ) { return 0; }
```

最后一个辅助函数返回 OpenAL 使用的内部数据格式。这里我们只支持每样本 8 位或 16 位的立体声和单声道信号：

```java
    ALuint GetALFormat() const
    {
      if ( FBitsPerSample == 8 )
        return ( FChannels == 2 ) ?
          AL_FORMAT_STEREO8 : AL_FORMAT_MONO8;
      if ( FBitsPerSample == 16 )
        return ( FChannels == 2 ) ?
          AL_FORMAT_STEREO16 : AL_FORMAT_MONO16;
      return AL_FORMAT_MONO8;
    }
  };
```

我们的基本声音解码是在`clStreamingWaveDataProvider`类中完成的。它包含`FBuffer`数据向量和其中的有用字节数：

```java
  class clStreamingWaveDataProvider: public iWaveDataProvider
  {
  public:
    clStreamingWaveDataProvider()
    : FBufferUsed( 0 )
    {}
    virtual bool IsStreaming() const override
    { return true; }
    virtual unsigned char* GetWaveData() override
    { return ( unsigned char* )&FBuffer[0]; }
    virtual size_t GetWaveDataSize() const override
    { return FBufferUsed; }
    std::vector<char> FBuffer;
    size_t FBufferUsed;
  };
```

我们准备描述实际执行繁重任务的`clAudioSource`类。构造函数创建一个 OpenAL 音频源对象，设置音量级别并禁用循环：

```java
  class clAudioSource: public iIntrusiveCounter
  {
  public:
    clAudioSource()
    : FWaveDataProvider( nullptr )
    , FBuffersCount( 0 )
    {
      alGenSources( 1, &FSourceID );
      alSourcef( FSourceID, AL_GAIN, 1.0 );
      alSourcei( FSourceID, AL_LOOPING, AL_FALSE );
    }
```

我们有两种不同的使用场景。如果附加的`iWaveDataProvider`支持流式传输，我们需要创建并维护至少两个声音缓冲区。这两个缓冲区都被加入到 OpenAL 播放队列中，并在其中一个缓冲区播放完成后进行交换。在每次交换事件中，我们调用`iWaveDataProvider`的`StreamWaveData()`方法将数据流式传输到下一个音频缓冲区。如果`iWaveDataProvider`不支持流式传输，我们只需要一个在开始时初始化的单个缓冲区。

`Play()`方法用解码后的数据填充两个缓冲区，并调用`alSourcePlay()`开始播放：

```java
    void Play()
    {
      if ( IsPlaying() ) { return; }
      if ( !FWaveDataProvider ) { return; }
      int State;
      alGetSourcei( FSourceID, AL_SOURCE_STATE, &State );
      if ( State != AL_PAUSED && FWaveDataProvider->IsStreaming() )
      {
        UnqueueAll();
        StreamBuffer( FBufferID[0], BUFFER_SIZE );
        StreamBuffer( FBufferID[1], BUFFER_SIZE );
        alSourceQueueBuffers( FSourceID, 2, &FBufferID[0] );
      }
      alSourcePlay( FSourceID );
    }
```

`Stop()`和`Pause()`方法分别调用适当的 OpenAL 例程来停止和暂停播放：

```java
    void Stop()
    {
      alSourceStop( FSourceID );
    }
    void Pause()
    {
      alSourcePause( FSourceID );
      UnqueueAll();
    }
```

`LoopSound()`和`SetVolume()`方法控制播放参数：

```java
    void LoopSound( bool Loop )
    {
    alSourcei( FSourceID, AL_LOOPING, Loop ? 1 : 0 );
    }
    void SetVolume( float Volume )
    {
      alSourcef( FSourceID, AL_GAIN, Volume );
    }
```

`IsPlaying()`方法是从上一个示例中复制而来的：

```java
    bool IsPlaying() const
    {
      int State;
      alGetSourcei( FSourceID, AL_SOURCE_STATE, &State );
      return State == AL_PLAYING;
    }
```

`StreamBuffer()`方法将新产生的音频数据写入其中一个缓冲区：

```java
    int StreamBuffer( unsigned int BufferID, int Size )
    {
      int ActualSize = FWaveDataProvider->StreamWaveData( Size );
      alBufferData( BufferID,
        FWaveDataProvider->GetALFormat(),
        FWaveDataProvider->GetWaveData(),
        ( int )FWaveDataProvider->GetWaveDataSize(),
        FWaveDataProvider->FSamplesPerSec );
      return ActualSize;
    }
```

`Update()` 方法应该足够频繁地被调用，以防止音频缓冲区出现下溢。然而，只有当附加的 `iWaveDataProvider` 表示音频流时，此方法才重要：

```java
    void Update( float DeltaSeconds )
    {
      if ( !FWaveDataProvider ) { return; }
      if ( !IsPlaying() ) { return; }
      if ( FWaveDataProvider->IsStreaming() )
      {
```

我们询问 OpenAL 已经处理了多少个缓冲区：

```java
      int Processed;
      alGetSourcei( FSourceID, AL_BUFFERS_PROCESSED, &Processed );
```

我们从队列中移除每个已处理的缓冲区，并调用 `StreamBuffer()` 来解码更多数据。最后，我们将缓冲区重新加入播放队列：

```java
      while ( Processed-- )
      {
        unsigned int BufID;
        alSourceUnqueueBuffers( FSourceID, 1, &BufID );
        StreamBuffer( BufID, BUFFER_SIZE );
        alSourceQueueBuffers( FSourceID, 1, &BufID );
      }
    }
  }
```

析构函数会停止播放并销毁 OpenAL 音频源和缓冲区：

```java
  virtual ~clAudioSource()
  {
    Stop();
    alDeleteSources( 1, &FSourceID );
    alDeleteBuffers( FBuffersCount, &FBufferID[0] );
  }
```

`BindWaveform()` 方法将一个新的 `iWaveDataProvider` 附加到这个音频源实例：

```java
  void BindWaveform( clPtr<iWaveDataProvider> Wave )
  {
    FWaveDataProvider = Wave;
    if ( !Wave ) { return; }
```

对于流式的 `iWaveDataProvider`，我们需要两个缓冲区。一个正在播放，另一个正在更新：

```java
    if ( FWaveDataProvider->IsStreaming() )
    {
      FBuffersCount = 2;
      alGenBuffers( FBuffersCount, &FBufferID[0] );
    }
    else
```

如果附加的波形不是流式，或者更具体地说，它不是压缩的，我们会创建一个单一缓冲区并将所有数据复制到其中：

```java
    {
      FBuffersCount = 1;
      alGenBuffers( FBuffersCount, &FBufferID[0] );
      alBufferData( FBufferID[0],
        FWaveDataProvider->GetALFormat(),
        FWaveDataProvider->GetWaveData(),
        ( int )FWaveDataProvider->GetWaveDataSize(),
        FWaveDataProvider->FSamplesPerSec );
      alSourcei( FSourceID, AL_BUFFER, FBufferID[0] );
    }
  }
```

私有方法 `UnqueueAll()` 使用 `alSourceUnqueueBuffers()` 来清除 OpenAL 播放队列：

```java
private:
  void UnqueueAll()
  {
    int Queued;
    alGetSourcei( FSourceID, AL_BUFFERS_QUEUED, &Queued );
    if ( Queued > 0 )
    {
      alSourceUnqueueBuffers( FSourceID, Queued, &FBufferID[0] );
    }
  }
```

类的尾部部分定义了附加的 `iWaveDataProvider` 的引用，OpenAL 对象的内部句柄以及已分配缓冲区的数量：

```java
  clPtr<iWaveDataProvider> FWaveDataProvider;
  unsigned int FSourceID;
  unsigned int FBufferID[2];
  int FBuffersCount;
};
```

为了展示一些基本的流式处理能力，我们更改了 `1_InitOpenAL` 的示例代码，并创建了一个带有附加音调发生器的音频源，如下代码所示：

```java
class clSoundThread: public iThread
{
  virtual void Run()
  {
    g_Audio.WaitForInitialization();
    auto Src = make_intrusive<clAudioSource>();
    Src->BindWaveform( make_intrusive<clToneGenerator>() );
    Src->Play();
    double Seconds = Env_GetSeconds();
    while ( !IsPendingExit() )
    {
      float DeltaSeconds = static_cast<float>( Env_GetSeconds() - Seconds );
      Src->Update( DeltaSeconds );
      Seconds = Env_GetSeconds();
    }
  }
};
```

在此示例中，我们故意避免了解压缩声音的问题，以便专注于流式处理逻辑。因此，我们从程序生成的声音开始。`clToneGenerator` 类重写了 `StreamWaveData()` 方法并生成正弦波，即纯音调。为了避免可听见的故障，我们必须仔细采样正弦函数并记住最后一个生成样本的整数索引。这个索引存储在 `FLastOffset` 字段中，并在每次迭代中的计算中使用。

类的构造函数将音频参数设置为 16 位 44.1kHz，并在 `FBuffer` 容器中分配一些空间。这个音调的基本频率设置为 440 Hz：

```java
class clToneGenerator : public clStreamingWaveDataProvider
{
public:
  clToneGenerator()
  : FFrequency( 440.0f )
  , FAmplitude( 350.0f )
  , FLastOffset( 0 )
  {
    FBufferUsed = 100000;
    FBuffer.resize( 100000 );
    FChannels = 2;
    FSamplesPerSec = 44100;
    FBitsPerSample = 16;
  }
```

在 `StreamWaveData()` 中，我们检查 `FBuffer` 向量中是否有可用空间，并在必要时重新分配它：

```java
  virtual int StreamWaveData( int Size )
  {
    if ( Size > static_cast<int>( FBuffer.size() ) )
    {
      FBuffer.resize( Size );
      LastOffset = 0;
    }
```

最后，我们计算音频样本。频率会根据样本数量重新计算：

```java
    const float TwoPI = 2.0f * 3.141592654f;
    float Freq = TwoPI * FFrequency /
      static_cast<float>( FSamplesPerSec );
```

由于我们需要 `Size` 字节，并且我们的信号包含两个声道，每个声道 16 位样本，因此我们需要总共 `Size/4` 个样本：

```java
    for ( int i = 0 ; i < Size / 4 ; i++ )
    {
      float t = Freq * static_cast<float>( i + LastOffset );
      float val = FAmplitude * std::sin( t );
```

我们将浮点数值转换为 16 位有符号整数，并将此整数的低字节和高字节放入 `FBuffer` 中。对于每个声道，我们存储两个字节：

```java
      short V = static_cast<short>( val );
      FBuffer[i * 4 + 0] = V & 0xFF;
      FBuffer[i * 4 + 1] = V >> 8;
      FBuffer[i * 4 + 2] = V & 0xFF;
      FBuffer[i * 4 + 3] = V >> 8;
    }
```

计算后，我们增加样本计数并取余数，以避免计数器中的整数溢出：

```java
    LastOffset += Size / 4;
    LastOffset %= FSamplesPerSec;
    return ( FBufferUsed = Size );
  }
  float FFrequency;
  float FAmplitude;
private:
  int LastOffset;
};
```

编译后的示例将产生一个 440 Hz 的纯音调。我们鼓励您更改 `clToneGenerator::FFrequency` 的值，看看它是如何工作的。您甚至可以使用此示例为您的乐器创建一个简单的音叉应用程序。至于乐器，让我们生成一些模仿弦乐器的音频数据。

# 弦乐器的音乐模型

让我们使用前一个示例的代码来实现一个简单的弦乐器物理模型。稍后你可以使用这些例程为 Android 创建一个小型的交互式合成器。

弦被建模为一系列垂直振动的点质量。严格来说，我们求解具有特定初始和边界条件的线性一维波动方程。声音是通过在声音接收位置取得解的值来产生的。

我们需要`clGString`类来存储所有的模型值和最终结果。`GenerateSound()`方法会预先计算字符串参数，并相应地调整数据容器的大小：

```java
class clGString
{
public:
  void GenerateSound()
  {
    // 4 seconds, 1 channel, 16 bit
    FSoundLen  = 44100 * 4 * 2;
    FStringLen = 200;
```

`Frc`值是声音的规范化基频。泛音是由物理模型隐式创建的：

```java
    float Frc = 0.5f;
    InitString( Frc );
    FSamples.resize( FsoundLen );
    FSound.resize( FsoundLen );
    float MaxS = 0;
```

在初始化阶段之后，我们通过在循环中调用`Step()`方法来执行波动方程的积分。`Step()`成员函数返回弦在接收位置处的位移：

```java
    for ( int i = 0; i < FSoundLen; i++ )
    {
      FSamples[i] = Step();
```

在每一步，我们将值限制在最大值：

```java
      if ( MaxS < fabs(FSamples[i]) )
      MaxS = fabs( FSamples[i] );
    }
```

最后，我们将浮点数值转换为有符号短整型。为了避免溢出，每个样本都要除以`MaxS`的值：

```java
    const float SignedShortMax = 32767.0f;
    float k = SignedShortMax / MaxS;
    for ( int i = 0; i < FSoundLen; i++ )
    {
      FSound [i] = FSamples [i] * k;
    }
  }
  std::vector<short int> FSound;
private:
  int FPickPos;
  int FSoundLen;
  std::vector<float> FSamples;
  std::vector<float> FForce;
  std::vector<float> FVel;
  std::vector<float> FPos;
  float k1, k2;
  int FStringLen;
  void InitString(float Freq)
  {
    FPos.resize(FStringLen);
    FVel.resize(FStringLen);
    FForce.resize(FStringLen);
    const float Damping = 1.0f / 512.0f;
    k1 = 1 - Damping;
    k2 = Damping / 2.0f;
```

我们将声音接收器放置在靠近末尾的位置：

```java
    FPickPos = FStringLen * 5 / 100;
    for ( int i = 0 ; i < FStringLen ; i++ )
    {
      FVel[i] = FPos[i] = 0;
    }
```

为了获得更好的结果，我们在弦元素的质地上产生轻微的变化：

```java
    for ( int i = 1 ; i < FStringLen - 1 ; i++ )
    {
      float m = 1.0f + 0.5f * (frand() - 0.5f);
      FForce[i] = Freq / m;
    }
```

在开始时，我们为弦的第二部分设置非零速度：

```java
    for ( int i = FStringLen/2; i < FStringLen - 1; i++ )
    {
      FVel[i] = 1;
    }
  }
```

`frand()`成员函数返回 0..1 范围内的伪随机浮点值：

```java
  inline float frand()
  {
    return static_cast<float>( rand() ) / static_cast<float>( RAND_MAX );
  }
```

### 注意

如果你的编译器支持，使用`std::random`是获取伪随机数的首选方式。

这是使用新的 C++11 标准库生成 0…1 范围内均匀分布的伪随机浮点数的方法：

```java
  std::random_device rd;
  std::mt19937 gen( rd() );
  std::uniform_real_distribution<> dis( 0.0, 1.0 );
  float frand()
  {
    return static_cast<float>( dis( gen ) );
  }
```

尽管这段简短的代码片段在我们的源代码包中未使用，但它可能对你有用。让我们回到我们示例的代码。

`Step()`方法进行单步操作并整合弦运动的方程。在步骤结束时，从`FPos`向量在`FPickPos`位置的值作为声音的下一个样本。对于熟悉数值方法的读者来说，可能看起来很奇怪，因为没有指定时间步长，它是隐式为 1/44100 秒的：

```java
  float Step()
  {
```

首先，我们强制施加边界条件，即弦两端的固定端点：

```java
    FPos[0] = FPos[FStringLen - 1] = 0;
    FVel[0] = FVel[FStringLen - 1] = 0;
```

根据胡克定律（[`en.wikipedia.org/wiki/Hooke's_law`](http://en.wikipedia.org/wiki/Hooke's_law)），力与伸长量成正比：

```java
    for ( int i = 1 ; i < FStringLen - 1 ; i++ )
    {
      float d = (FPos[i - 1] + FPos[i + 1]) * 0.5f - FPos[i];
      FVel[i] += d * FForce[i];
    }
```

为了确保数值稳定性，我们应用一些人工阻尼，并取相邻速度的平均值。如果不这样做，会产生一些不想要的声音：

```java
    for ( int i = 1 ; i < FStringLen - 1 ; i++ )
    {
      FVel[i] = FVel[i] * k1 +
        (FVel[i - 1] + FVel[i + 1]) * k2;
    }
```

最后，我们更新位置：

```java
    for ( int i = 1 ; i < FStringLen ; i++ )
    {
      FPos[i] += FVel[i];
    }
```

为了记录我们的声音，我们只取弦的一个位置：

```java
    return FPos[FPickPos];
    }
  };
```

`1_InitOpenAL`示例可以轻松修改，以生成字符串声音，而不是加载`.wav`文件。我们创建`clGString`实例并调用`GenerateSound()`方法。之后，我们获取`FSound`向量并将其提交给音频源的`PlayBuffer()`方法：

```java
  clGString String;
  String.GenerateSound();
  const unsigned char* Data = (const unsigned char*)&String.FSound[0];
  PlayBuffer( Data, (int)String.FSound.size() );
```

在这里，采样率被硬编码为 44100 Hz。尝试`3_GuitarStringSound`示例以获取完整代码并亲自聆听。请注意，由于在播放声音之前需要进行大量预计算，启动时间可能会稍长。然而，代码非常简单，我们将其作为一个练习留给读者，让他们为 Android 编译，并从后续示例中获取所有必要的 makefile 和包装器。同时，我们将处理那些可以立即在 Android 上运行的内容。

# 解码压缩音频

现在我们已经实现了基本的音频流系统，是时候使用几个第三方库来读取压缩的音频文件了。基本上，我们需要做的是覆盖`clStreamingWaveDataProvider`类中的`StreamWaveData()`函数。这个函数反过来调用`ReadFromFile()`方法，实际解码就在这里完成。解码器的初始化在构造函数中进行，对于抽象的`iDecodingProvider`类，我们只存储对数据块引用。文件的所有压缩数据都存储在`clBlob`对象中：

```java
  class iDecodingProvider: public StreamingWaveDataProvider
  {
  protected:
    virtual int ReadFromFile( int Size, int BytesRead ) = 0;
    clPtr<clBlob> FRawData;
  public:
    bool FLoop;
    bool FEof;
    iDecodingProvider( const clPtr<clBlob>& Blob )
    : FRawData( Blob )
    , FLoop( false )
    , FEof( false )
    {}
    virtual bool IsEOF() const { return FEof; }
```

`StreamWaveData()`方法负责解码工作。前几行确保`FBuffer`有足够的空间来包含解码后的数据：

```java
    virtual int StreamWaveData( int Size ) override
    {
      int OldSize = ( int )FBuffer.size();
      if ( Size > OldSize )
      {
```

重新分配缓冲区后，我们用零填充新字节，因为非零值可能会产生意外的噪音：

```java
        FBuffer.resize( Size, 0 );
      }
      if ( FEof ) { return 0; }
```

由于`ReadFromFile()`可能会返回不充分的数据，我们以循环的方式调用它，并增加读取的字节数：

```java
      int BytesRead = 0;
      while ( BytesRead < Size )
      {
        int Ret = ReadFromFile( Size, BytesRead );
        if ( Ret > 0 ) BytesRead += Ret;

```

`ReadFromFile()`返回零意味着我们已达到流末尾：

```java
        else if ( Ret == 0 )
        {
          FEof = true;
```

通过调用`Seek()`并设置`FEof`标志来实现循环：

```java
          if ( FLoop )
          {
            Seek( 0 );
            FEof = false;
            continue;
          }
          break;
        }
```

`Ret`中的负值表示发生了读取错误。在这种情况下，我们停止解码：

```java
        else
        {
          Seek( 0 );
          FEof = true;
          break;
        }
      }
      return ( FBufferUsed = BytesRead );
    }
  };
```

接下来的两节将展示如何使用流行的第三方库解码不同格式的音频文件。

## 使用 ModPlug 库解码跟踪器音乐

我们将要处理的第一个用于解码音频文件的库是 Olivier Lapicque 的 ModPlug 库。大多数流行的跟踪器音乐文件格式[`en.wikipedia.org/wiki/Module_file`](http://en.wikipedia.org/wiki/Module_file)可以使用 ModPlug 解码并转换为适合 OpenAL 的波形。我们将介绍实现`ReadFromFile()`例程的`clModPlugProvider`类。该类的构造函数将内存块加载到`ModPlugFile`对象中，并分配默认的音频参数：

```java
  class clModPlugProvider: public iDecodingProvider
  {
  private:
    ModPlugFile* FModFile;
  public:
    ModPlugProvider( const clPtr<clBlob>& Blob ):
    {
      DecodingProvider( Blob )
      FChannels = 2;
      FSamplesPerSec = 44100;
      FBitsPerSample = 16;
      FModFile = ModPlug_Load_P(
        ( const void* ) FRawData->GetDataConst(), ( int )FRawData->GetSize()
      );
    }
```

析构函数清理 ModPlug：

```java
    virtual ~ModPlugProvider() { ModPlug_Unload_P( FModFile ); }
```

`ReadFromFile()`方法调用`ModPlug_Read()`来填充`FBuffer`：

```java
    virtual int ReadFromFile( int Size, int BytesRead )
    {
      return ModPlug_Read_P( FModFile,
        &FBuffer[0] + BytesRead, Size - BytesRead );
    }
```

流定位是通过使用`ModPlug_Seek()`例程完成的。在 ModPlug API 内部，所有的时间计算都是以毫秒为单位的：

```java
    virtual void Seek( float Time )
    {
      FEof = false;
      ModPlug_Seek_P( FModFile, ( int )( Time * 1000.0f ) );
    }
  };
```

要使用这个波形数据提供者，我们将其实例附加到`clAudioSource`对象：

```java
  Src->BindWaveform( make_intrusive<clModPlugProvider>( LoadFileAsBlob( g_FS, "augmented_emotions.xm" ) 
    )
   );
```

其他细节是从我们之前的示例中复用的。`4_ModPlug`文件夹可以在 Android 和 Windows 上构建和运行。使用`ndk-build`和`ant debug`为 Android 创建`.apk`，使用`make all`创建 Windows 可执行文件。

## 解码 MP3 文件

MPEG-1 Layer 3 格式的多数专利在 2015 年底到期，因此值得提及 Fabrice Bellard 的 MiniMP3 库。使用这个库不会比 ModPlug 更难，因为我们已经在`iDecodingProvider`中完成了所有繁重的工作。让我们看看`5_MiniMP3`示例。`clMP3Provider`类创建了解码器实例，并通过读取开头的几帧来读取流参数：

```java
  class clMP3Provider: public iDecodingProvider
  {
  public:
    clMP3Provider( const clPtr<clBlob>& Blob )
    : iDecodingProvider( Blob )
    {
      FBuffer.resize(MP3_MAX_SAMPLES_PER_FRAME * 8);
      FBufferUsed = 0;
      FBitsPerSample = 16;
      mp3 = mp3_create();
      bytes_left = ( int )FRawData->GetSize();
```

一开始，我们将流位置设置为`clBlob`对象的开始处：

```java
      stream_pos = 0;
      byte_count = mp3_decode((mp3_decoder_t*)mp3,
        ( void* )FRawData->GetData(), bytes_left,
        (signed short*)&FBuffer[0], &info);
      bytes_left -= byte_count;
```

我们需要关于音频数据的信息，因此我们从`info`结构中获取它：

```java
      FSamplesPerSec = info.sample_rate;
      FChannels = info.channels;
    }
```

析构函数中没有特别之处，以下是它的样子：

```java
    virtual ~MP3Provider()
    {
      mp3_done( &mp3 );
    }
```

`ReadFromFile()`方法跟踪源流中剩余的字节数，并填充`FBuffer`容器。构造函数和这个方法都使用`bytes_left`和`stream_pos`字段来保持当前的流位置和剩余的字节数：

```java
    virtual int ReadFromFile( int Size, int BytesRead )
    {
      byte_count = mp3_decode( (mp3_decoder_t*)mp3, (( char* )FRawData->GetData()) + stream_pos, bytes_left, (signed short *)(&FBuffer[0] + BytesRead), &info);
      bytes_left -= byte_count;
      stream_pos += byte_count;
      return info.audio_bytes;
    }
```

对于可变比特率的流，寻道并不是那么明显，因此我们将这个实现留给感兴趣的读者作为一个练习。在固定比特率的最简单情况下，只需从秒重新计算`Time`到采样率单位，然后设置`stream_pos`变量：

```java
    virtual void Seek( float Time ) override
    {
      FEof = false;
    }
  private:
    mp3_decoder_t mp3;
    mp3_info_t info;
    int stream_pos;
    int bytes_left;
    int byte_count;
  };
```

要使用它，我们将提供者附加到`clAudioSource`对象，就像使用 ModPlug 一样：

```java
  Src->BindWaveform( make_intrusive<clMP3Provider>( LoadFileAsBlob( g_FS, "test.mp3" ) ) );
```

同样，这个示例可以在 Android 上运行，去试试吧。

### 注意

这段代码没有正确处理一些 ID3 标签。如果你想基于我们的代码编写一个通用的音乐播放器，可以参考作者编写的这个开源项目：[`github.com/corporateshark/PortAMP`](https://github.com/corporateshark/PortAMP)。

## 解码 OGG 文件

还有一个值得提及的流行音频格式。Ogg Vorbis 是一种完全开放、无专利、专业的音频编码和流媒体技术，具有开源的所有好处[`www.vorbis.com`](http://www.vorbis.com)。OGG 解码和播放过程的大致流程与 MP3 类似。让我们看看示例`6_OGG`。`Decoders.cpp`文件用 OGG Vorbis 函数的定义进行了扩展，包括`OGG_clear_func()`、`OGG_open_callbacks_func()`、`OGG_time_seek_func()`、`OGG_read_func()`、`OGG_info_func()`和`OGG_comment_func()`。这些函数在 Android 上链接到一个静态库，或者在 Windows 上从`.dll`文件加载。与 MiniMP3 API 的主要区别在于向 OGG 解码器提供一组数据读取回调。这些回调在`OGG_Callbacks.inc`文件中实现。`OGG_ReadFunc()`回调将数据读取到解码器中：

```java
  static size_t OGG_ReadFunc( void* Ptr, size_t Size, size_t NMemB, void* DataSource )
  {
    clOggProvider* OGG = static_cast<clOggProvider*>( DataSource );
    size_t DataSize = OGG->FRawData->GetSize();
    ogg_int64_t BytesRead = DataSize - OGG->FOGGRawPosition;
    ogg_int64_t BytesSize = Size * NMemB;
    if ( BytesSize < BytesRead ) { BytesRead = BytesSize; }
```

它基于我们的文件系统抽象和内存映射文件：

```java
    memcpy(Ptr, ( unsigned char* )OGG->FRawData->GetDataConst() +
      OGG->FOGGRawPosition, ( size_t )BytesRead );
    OGG->FOGGRawPosition += BytesRead;
    return ( size_t )BytesRead;
  }
```

`OGG_SeekFunc()` 回调使用不同的相对定位模式来查找输入流：

```java
  static int OGG_SeekFunc( void* DataSource, ogg_int64_t Offset, int Whence )
  {
    clOggProvider* OGG = static_cast<clOggProvider*>( DataSource );
    size_t DataSize = OGG->FRawData->GetSize();
    if ( Whence == SEEK_SET )
    {
      OGG->FOGGRawPosition = Offset;
    }
    else if ( Whence == SEEK_CUR )
    {
      OGG->FOGGRawPosition += Offset;
    }
    else if ( Whence == SEEK_END )
    {
      OGG->FOGGRawPosition = DataSize + Offset;
    }
    if ( OGG->FOGGRawPosition > ( ogg_int64_t )DataSize )
    {
      OGG->FOGGRawPosition = ( ogg_int64_t )DataSize;
    }
    return static_cast<int>( OGG->FOGGRawPosition );
  }
```

`OGG_CloseFunc()` 和 `OGG_TellFunc()` 函数非常简单：

```java
  static int OGG_CloseFunc( void* DataSource )
  {
    return 0;
  }
   static long OGG_TellFunc( void* DataSource )
  {
   return static_cast<int>(
     (( clOggProvider* )DataSource )->FOGGRawPosition );
  }
```

这些回调在 `clOggProvider` 的构造函数中使用，以设置解码器：

```java
  clOggProvider( const clPtr<clBlob>& Blob )
  : iDecodingProvider( Blob )
  , FOGGRawPosition( 0 )
  {
    ov_callbacks Callbacks;
    Callbacks.read_func  = OGG_ReadFunc;
    Callbacks.seek_func  = OGG_SeekFunc;
    Callbacks.close_func = OGG_CloseFunc;
    Callbacks.tell_func  = OGG_TellFunc;
    OGG_ov_open_callbacks( this, &FVorbisFile, nullptr, -1, Callbacks );
```

流参数（如通道数、采样率和每样本位数）在这里获取：

```java
    vorbis_info* VorbisInfo = OGG_ov_info ( &FVorbisFile, -1 );
    FChannels = VorbisInfo->channels;
    FSamplesPerSec = VorbisInfo->rate;
    FBitsPerSample = 16;
  }
```

析构函数非常简单：

```java
  virtual ~clOggProvider()
  {
    OGG_ov_clear( &FVorbisFile );
  }
```

`ReadFromFile()` 和 `Seek()` 方法在精神上与我们处理 MiniMP3 时所做的非常相似：

```java
  virtual int ReadFromFile( int Size, int BytesRead ) override
  {
    return ( int )OGG_ov_read( &FVorbisFile, &FBuffer[0] + BytesRead, Size - BytesRead, 0, FBitsPerSample / 8, 1, &FOGGCurrentSection );
  }
  virtual void Seek( float Time ) override
  {
    FEof = false;
    OGG_ov_time_seek( &FVorbisFile, Time );
  }
private:
```

这是在前面章节提到的回调函数定义的地方。当然，它们可以在原地定义，而不必将它们移到单独的文件中。然而，我们认为这种分离对于本例来说在逻辑上更为清晰；将数据提供者概念和 `OGG Vorbis` 相关 API 逻辑上分开：

```java
  #include "OGG_Callbacks.inc"
  OggVorbis_File FVorbisFile;
  ogg_int64_t FOGGRawPosition;
  int FOGGCurrentSection;
};
```

这个示例也开箱即用，支持 Android。运行以下命令以在您的设备上获取 `.apk`：

```java
>ndk-build
>ant debug
>adb install -r bin/App1-debug.apk

```

现在启动活动，享受音乐吧！在后续章节中，我们将在本章内容的基础上添加更多有趣的音频内容。

# 总结

在本章中，我们学习了如何使用可移植的 C++ 代码和开源第三方库在 Android 上播放音频。提供的示例能够播放 `.mp3` 和 `.ogg` 音频文件以及 `.it`、`.xm`、`.mod` 和 `.s3m` 模块。我们还学习了如何生成自己的波形来模拟乐器。代码可以在许多系统间移植，并且可以在 Android 和 Windows 上运行和调试。现在，我们已经完成了音频部分，是时候进入下一章，使用 OpenGL 渲染一些图形了。
