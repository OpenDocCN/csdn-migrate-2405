# C++ 专家编程（六）

> 原文：[`annas-archive.org/md5/57ea316395e58ce0beb229274ec493fc`](https://annas-archive.org/md5/57ea316395e58ce0beb229274ec493fc)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十九章：使用 GPGPU 进行多线程处理

最近的一个发展是使用视频卡（GPU）进行通用计算（GPGPU）。使用 CUDA 和 OpenCL 等框架，可以加速例如在医疗、军事和科学应用中并行处理大型数据集的处理。在本章中，我们将看看如何使用 C++和 OpenCL 来实现这一点，以及如何将这一特性集成到 C++中的多线程应用程序中。

本章的主题包括：

+   将 OpenCL 集成到基于 C++的应用程序中

+   在多线程环境中使用 OpenCL 的挑战

+   延迟和调度对多线程性能的影响

# GPGPU 处理模型

在第十六章中，*使用分布式计算进行多线程处理*，我们讨论了在集群系统中跨多个计算节点运行相同任务的情况。这样设置的主要目标是以高度并行的方式处理数据，从理论上讲，相对于具有较少 CPU 核心的单个系统，可以加快处理速度。

**GPGPU**（图形处理单元上的通用计算）在某些方面与此类似，但有一个主要区别：虽然只有常规 CPU 的计算集群擅长标量任务--即在一个单一数据集上执行一个任务（SISD）--GPU 是擅长 SIMD（单输入，多数据）任务的矢量处理器。

基本上，这意味着可以将大型数据集发送到 GPU，以及单个任务描述，GPU 将在其数百或数千个核心上并行执行该数据的部分相同任务。因此，可以将 GPU 视为一种非常专门的集群：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/38ada78a-8f9a-4bf3-971e-de8343e0cfd9.png)

# 实现

当首次提出 GPGPU 概念（大约在 2001 年左右）时，编写 GPGPU 程序的最常见方式是使用 GLSL（OpenGL 着色语言）和类似的着色器语言。由于这些着色器语言已经针对 SIMD 任务（图像和场景数据）进行了优化，因此将它们调整为更通用的任务相对比较简单。

自那时起，出现了许多更专业的实现：

| **名称** | **自** | **所有者** | **备注** |
| --- | --- | --- | --- |
| CUDA | 2006 | NVidia | 这是专有的，只能在 NVidia GPU 上运行 |
| Close to Metal | 2006 | ATi/AMD | 这已被放弃，转而采用 OpenCL |
| DirectCompute | 2008 | Microsoft | 这是与 DX11 一起发布的，可在 DX10 GPU 上运行，并且仅限于 Windows 平台 |
| OpenCL | 2009 | Khronos Group | 这是开放标准，可在 AMD、Intel 和 NVidia GPU 上运行，并且适用于所有主流平台，以及移动平台 |

# OpenCL

在各种当前的 GPGPU 实现中，由于没有限制，OpenCL 是迄今为止最有趣的 GPGPU API。它几乎适用于所有主流 GPU 和平台，甚至在部分移动平台上也得到支持。

OpenCL 的另一个显着特点是它不仅限于 GPGPU。作为其名称的一部分（开放计算语言），它将系统抽象为所谓的*计算设备*，每个设备都有自己的功能。GPGPU 是最常见的应用，但这一特性使得在 CPU 上进行测试实现变得相当容易，以便进行简单的调试。

OpenCL 的一个可能的缺点是它对内存和硬件细节采用了高度抽象，这可能会对性能产生负面影响，尽管它增加了代码的可移植性。

在本章的其余部分，我们将专注于 OpenCL。

# 常见的 OpenCL 应用程序

许多程序都包含基于 OpenCL 的代码，以加速操作。这些包括旨在图形处理的程序，以及 3D 建模和 CAD，音频和视频处理。一些例子是：

+   Adobe Photoshop

+   GIMP

+   ImageMagick

+   Autodesk Maya

+   Blender

+   Handbrake

+   Vegas Pro

+   OpenCV

+   Libav

+   Final Cut Pro

+   FFmpeg

在办公应用程序中进一步加速某些操作，包括 LibreOffice Calc 和 Microsoft Excel。

也许更重要的是，OpenCL 也常用于科学计算和密码学，包括 BOINC 和 GROMACS 以及许多其他库和程序。

# OpenCL 版本

自 2008 年 12 月 8 日 OpenCL 规范发布以来，迄今已经有五次更新，将其提升到 2.2 版本。这些发布的重要变化将在下文中提到。

# OpenCL 1.0

首个公开发布是由苹果作为 macOS X Snow Leopard 发布的一部分于 2009 年 8 月 28 日发布的。

与此发布一起，AMD 宣布将支持 OpenCL 并淘汰其自己的 Close to Metal（CtM）框架。 NVIDIA，RapidMind 和 IBM 还为其自己的框架添加了对 OpenCL 的支持。

# OpenCL 1.1

OpenCL 1.1 规范于 2010 年 6 月 14 日由 Khronos Group 批准。它为并行编程和性能增加了额外功能，包括以下内容：

+   包括 3 组分向量和额外的图像格式在内的新数据类型

+   处理来自多个主机线程的命令，并在多个设备上处理缓冲区

+   对缓冲区的区域操作，包括读取、写入和复制 1D、2D 或 3D 矩形区域

+   增强事件的使用来驱动和控制命令执行

+   包括整数夹紧、洗牌和异步分步（不连续，但数据之间有间隔）复制等额外的 OpenCL 内置 C 函数

+   通过链接 OpenCL 和 OpenGL 事件，通过有效共享图像和缓冲区来改进 OpenGL 的互操作性

# OpenCL 1.2

OpenCL 1.2 版本于 2011 年 11 月 15 日发布。其最重要的功能包括以下内容：

+   设备分区：这使应用程序可以将设备分成子设备，直接控制对特定计算单元的工作分配，为高优先级/延迟敏感任务保留设备的一部分，或有效地使用共享硬件资源，如缓存。

+   对象的分离编译和链接：这提供了传统编译器的功能和灵活性，使得可以创建 OpenCL 程序的库供其他程序链接。

+   增强的图像支持：这包括对 1D 图像和 1D 和 2D 图像数组的增强支持。此外，OpenGL 共享扩展现在可以从 OpenGL 1D 纹理和 1D 和 2D 纹理数组创建 OpenCL 图像。

+   内置内核：这代表了专门的或不可编程的硬件以及相关的固件的功能，如视频编码器/解码器和数字信号处理器，使得这些定制设备可以从 OpenCL 框架中驱动并与之紧密集成。

+   DX9 媒体表面共享：这使得 OpenCL 和 DirectX 9 或 DXVA 媒体表面之间的有效共享成为可能。

+   DX11 表面共享：实现 OpenCL 和 DirectX 11 表面之间的无缝共享。

# OpenCL 2.0

OpenCL2.0 版本于 2013 年 11 月 18 日发布。此版本具有以下重大变化或增加：

+   共享虚拟内存：主机和设备内核可以直接共享复杂的、包含指针的数据结构，如树和链表，提供了显著的编程灵活性，并消除了主机和设备之间昂贵的数据传输。

+   动态并行性：设备内核可以在没有主机交互的情况下将内核排队到同一设备，从而实现灵活的工作调度范式，并避免在设备和主机之间传输执行控制和数据，通常显著减轻主机处理器瓶颈。

+   通用地址空间：函数可以在不指定参数的命名地址空间的情况下编写，特别适用于那些声明为指向类型的指针的参数，消除了为应用程序中使用的每个命名地址空间编写多个函数的需要。

+   **图像**：改进的图像支持，包括 sRGB 图像和 3D 图像写入，内核可以从图像中读取和写入相同的图像，并且可以从 mip-mapped 或多采样的 OpenGL 纹理创建 OpenCL 图像，以改进 OpenGL 互操作性。

+   **C11 原子操作**：C11 原子操作和同步操作的子集，以便使一个工作项中的赋值对于设备上执行的其他工作项或在设备上执行的工作组之间可见，或者用于在 OpenCL 设备和主机之间共享数据。

+   **管道**：管道是以 FIFO 形式存储数据的内存对象，OpenCL 2.0 提供了内建函数，用于内核读取或写入管道，从而提供了对管道数据结构的直接编程，这可以通过 OpenCL 实现者进行高度优化。

+   **Android 可安装客户端驱动扩展**：使得可以在 Android 系统上发现和加载 OpenCL 实现作为共享对象。

# OpenCL 2.1

OpenCL 2.1 对 2.0 标准的修订于 2015 年 11 月 16 日发布。这个版本最显著的是引入了 OpenCL C++内核语言，就像 OpenCL 语言最初是基于 C 的扩展一样，C++版本是基于 C++14 的子集，同时向后兼容 C 内核语言。

OpenCL API 的更新包括以下内容：

+   **子组**：这些使得对硬件线程的控制更加精细，现在已经纳入核心，还增加了额外的子组查询操作，以增加灵活性

+   **内核对象和状态的复制**：clCloneKernel 使得可以复制内核对象和状态，以安全地实现包装类中的复制构造函数

+   **低延迟设备定时器查询**：这允许在设备和主机代码之间对齐分析数据

+   **运行时的中间 SPIR-V 代码**：

+   LLVM 到 SPIR-V 之间的双向转换器，以便在工具链中灵活使用这两种中间语言。

+   一个将 OpenCL C 编译为 LLVM 的编译器，通过上述转换器生成 SPIR-V。

+   SPIR-V 汇编器和反汇编器。

标准可移植中间表示（SPIR）及其后继者 SPIR-V，是为了在 OpenCL 设备上提供设备无关的二进制文件。

# OpenCL 2.2

2017 年 5 月 16 日，当前版本的 OpenCL 发布。根据 Khronos Group 的说法，它包括以下更改：

+   OpenCL 2.2 将 OpenCL C++内核语言纳入核心规范，显著提高了并行编程的生产力

+   OpenCL C++内核语言是 C++14 标准的静态子集，包括类、模板、Lambda 表达式、函数重载和许多其他用于通用和元编程的构造

+   利用新的 Khronos SPIR-V 1.1 中间语言，完全支持 OpenCL C++内核语言

+   OpenCL 库函数现在可以利用 C++语言，以提供更高的安全性和减少未定义行为，同时访问原子操作、迭代器、图像、采样器、管道和设备队列内置类型和地址空间

+   管道存储是 OpenCL 2.2 中的一种新的设备端类型，对于 FPGA 实现非常有用，因为它可以在编译时知道连接大小和类型，并且可以在内核之间实现高效的设备范围通信

+   OpenCL 2.2 还包括用于增强生成代码优化的功能：应用程序可以在 SPIR-V 编译时提供专门化常量的值，新的查询可以检测程序范围全局对象的非平凡构造函数和析构函数，用户回调可以在程序释放时设置

+   可以在任何支持 OpenCL 2.0 的硬件上运行（只需要更新驱动程序）

# 建立开发环境

无论您使用哪个平台和 GPU，进行 OpenCL 开发的最重要部分是从制造商那里获取适用于自己 GPU 的 OpenCL 运行时。在此，AMD、Intel 和 NVidia 都为所有主流平台提供 SDK。对于 NVidia，OpenCL 支持包含在 CUDA SDK 中。

除了 GPU 供应商的 SDK 外，还可以在其网站上找到有关此 SDK 支持哪些 GPU 的详细信息。

# Linux

安装供应商的 GPGPU SDK 后，我们仍然需要下载 OpenCL 头文件。与供应商提供的共享库和运行时文件不同，这些头文件是通用的，可以与任何 OpenCL 实现一起使用。

对于基于 Debian 的发行版，只需执行以下命令行：

```cpp
    $ sudo apt-get install opencl-headers
```

对于其他发行版，该软件包可能被称为相同的名称，或者是其他名称。请查阅发行版的手册，了解如何查找软件包名称。

安装 SDK 和 OpenCL 头文件后，我们准备编译我们的第一个 OpenCL 应用程序。

# Windows

在 Windows 上，我们可以选择使用 Visual Studio（Visual C++）或 Windows 版的 GCC（MinGW）进行开发。为了与 Linux 版本保持一致，我们将使用 MinGW 以及 MSYS2。这意味着我们将拥有相同的编译器工具链、相同的 Bash shell 和实用程序，以及 Pacman 软件包管理器。

在安装供应商的 GPGPU SDK 后，如前所述，只需在 MSYS2 shell 中执行以下命令行，即可安装 OpenCL 头文件：

```cpp
    $ pacman -S mingw64/mingw-w64-x86_64-opencl-headers
```

或者，在使用 32 位 MinGW 版本时，执行以下命令行：

```cpp
    mingw32/mingw-w64-i686-opencl-headers 
```

有了这个，OpenCL 头文件已经就位。现在我们只需要确保 MinGW 链接器可以找到 OpenCL 库。使用 NVidia CUDA SDK，您可以使用`CUDA_PATH`环境变量，或者浏览 SDK 的安装位置，并将适当的 OpenCL LIB 文件从那里复制到 MinGW lib 文件夹中，确保不要混淆 32 位和 64 位文件。

现在共享库也就位了，我们可以编译 OpenCL 应用程序了。

# OS X/MacOS

从 OS X 10.7 开始，OS 中提供了 OpenCL 运行时。安装 XCode 以获取开发头文件和库后，可以立即开始 OpenCL 开发。

# 一个基本的 OpenCL 应用程序

一个常见的 GPGPU 应用示例是计算快速傅立叶变换（FFT）。这种算法通常用于音频处理等领域，允许您将例如从时域转换到频域进行分析。

它的作用是对数据集应用分而治之的方法，以计算 DFT（离散傅立叶变换）。它通过将输入序列分割成固定数量的较小子序列，计算它们的 DFT，并组装这些输出，以组成最终序列。

这是相当高级的数学，但可以说，它非常适合 GPGPU 的原因是它是一种高度并行的算法，采用数据的细分以加快 DFT 的计算，如图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/1497e9bd-b3c9-4400-9ea8-45e22a4247ef.png)

每个 OpenCL 应用程序至少由两部分组成：设置和配置 OpenCL 实例的 C++代码，以及实际的 OpenCL 代码，也称为内核，例如基于维基百科 FFT 演示示例的这个内核：

```cpp
// This kernel computes FFT of length 1024\.  
// The 1024 length FFT is decomposed into calls to a radix 16 function,  
// another radix 16 function and then a radix 4 function
 __kernel void fft1D_1024 (__global float2 *in,  
                     __global float2 *out,  
                     __local float *sMemx,  
                     __local float *sMemy) {
          int tid = get_local_id(0);
          int blockIdx = get_group_id(0) * 1024 + tid;
          float2 data[16];

          // starting index of data to/from global memory
          in = in + blockIdx;  out = out + blockIdx;

          globalLoads(data, in, 64); // coalesced global reads
          fftRadix16Pass(data);      // in-place radix-16 pass
          twiddleFactorMul(data, tid, 1024, 0);

          // local shuffle using local memory
          localShuffle(data, sMemx, sMemy, tid, (((tid & 15) * 65) + (tid >> 4)));
          fftRadix16Pass(data);               // in-place radix-16 pass
          twiddleFactorMul(data, tid, 64, 4); // twiddle factor multiplication

          localShuffle(data, sMemx, sMemy, tid, (((tid >> 4) * 64) + (tid & 15)));

          // four radix-4 function calls
          fftRadix4Pass(data);      // radix-4 function number 1
          fftRadix4Pass(data + 4);  // radix-4 function number 2
          fftRadix4Pass(data + 8);  // radix-4 function number 3
          fftRadix4Pass(data + 12); // radix-4 function number 4

          // coalesced global writes
    globalStores(data, out, 64);
 } 
```

这个 OpenCL 内核表明，与 GLSL 着色器语言一样，OpenCL 的内核语言本质上是 C 语言，具有许多扩展。虽然可以使用 OpenCL C++内核语言，但自 OpenCL 2.1（2015）以来，它只能使用，因此对它的支持和示例比 C 内核语言更少。

接下来是 C++应用程序，使用它，我们运行前面的 OpenCL 内核：

```cpp
#include <cstdio>
 #include <ctime>
 #include "CLopencl.h"

 #define NUM_ENTRIES 1024

 int main() { // (int argc, const char * argv[]) {
    const char* KernelSource = "fft1D_1024_kernel_src.cl"; 

```

正如我们在这里看到的，我们只需要包含一个头文件，以便访问 OpenCL 函数。我们还指定包含我们的 OpenCL 内核源代码的文件的名称。由于每个 OpenCL 设备可能是不同的架构，当我们加载它时，内核将被编译为目标设备：

```cpp
          const cl_uint num = 1;
    clGetDeviceIDs(0, CL_DEVICE_TYPE_GPU, 0, 0, (cl_uint*) num); 

   cl_device_id devices[1];
    clGetDeviceIDs(0, CL_DEVICE_TYPE_GPU, num, devices, 0);

```

接下来，我们必须获取我们可以使用的 OpenCL 设备列表，并通过 GPU 进行过滤：

```cpp
    cl_context context = clCreateContextFromType(0, CL_DEVICE_TYPE_GPU,  
                                                   0, 0, 0); 
```

然后，我们使用我们找到的 GPU 设备创建一个 OpenCL`context`。上下文管理一系列设备上的资源：

```cpp
    clGetDeviceIDs(0, CL_DEVICE_TYPE_DEFAULT, 1, devices, 0);
    cl_command_queue queue = clCreateCommandQueue(context, devices[0], 0, 0); 
```

最后，我们将创建包含要在 OpenCL 设备上执行的命令的命令队列：

```cpp
    cl_mem memobjs[] = { clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, sizeof(float) * 2 * NUM_ENTRIES, 0, 0),              
   clCreateBuffer(context, CL_MEM_READ_WRITE, sizeof(float) * 2 * NUM_ENTRIES, 0, 0) }; 
```

为了与设备通信，我们需要分配将包含我们要复制到它们的内存中的数据的缓冲区对象。在这里，我们将分配两个缓冲区，一个用于读取，一个用于写入：

```cpp
    cl_program program = clCreateProgramWithSource(context, 1, (const char **)& KernelSource, 0, 0); 
```

我们现在已经在设备上获得了数据，但仍然需要在设备上加载内核。为此，我们将使用我们之前查看过的 OpenCL 内核源代码创建一个内核，使用我们之前定义的文件名：

```cpp
    clBuildProgram(program, 0, 0, 0, 0, 0); 
```

接下来，我们将按以下方式编译源代码：

```cpp
   cl_kernel kernel = clCreateKernel(program, "fft1D_1024", 0); 
```

最后，我们将从我们创建的二进制文件中创建实际的内核：

```cpp
    size_t local_work_size[1] = { 256 };

    clSetKernelArg(kernel, 0, sizeof(cl_mem), (void *) &memobjs[0]);
    clSetKernelArg(kernel, 1, sizeof(cl_mem), (void *) &memobjs[1]);
    clSetKernelArg(kernel, 2, sizeof(float) * (local_work_size[0] + 1) * 16, 0);
    clSetKernelArg(kernel, 3, sizeof(float) * (local_work_size[0] + 1) * 16, 0); 
```

为了向我们的内核传递参数，我们必须在这里设置它们。在这里，我们将添加指向我们的缓冲区和工作大小维度的指针，如下所示：

```cpp
    size_t global_work_size[1] = { 256 };
          global_work_size[0] = NUM_ENTRIES;
    local_work_size[0]  =  64;  // Nvidia: 192 or 256
    clEnqueueNDRangeKernel(queue, kernel, 1, 0, global_work_size, local_work_size, 0, 0, 0); 
```

现在我们可以设置工作项维度并执行内核。在这里，我们将使用一种内核执行方法，允许我们定义工作组的大小：

```cpp
          cl_mem C = clCreateBuffer(context, CL_MEM_WRITE_ONLY, (size), 0, &ret);
                      cl_int ret = clEnqueueReadBuffer(queue, memobjs[1], CL_TRUE, 0, sizeof(float) * 2 * NUM_ENTRIES, C, 0, 0, 0); 
```

执行完内核后，我们希望读取生成的信息。为此，我们告诉 OpenCL 将我们传递为内核参数的已分配写入缓冲区复制到一个新分配的缓冲区中。我们现在可以自由地使用这个缓冲区中的数据。

然而，在这个例子中，我们将不使用这些数据：

```cpp
    clReleaseMemObject(memobjs[0]);
    clReleaseMemObject(memobjs[1]); 
   clReleaseCommandQueue(queue); 
   clReleaseKernel(kernel); 
   clReleaseProgram(program); 
   clReleaseContext(context); 
   free(C);
 } 
```

最后，我们释放我们分配的资源并退出。

# GPU 内存管理

在使用 CPU 时，必须处理多个内存层次结构，从主内存（最慢）到 CPU 缓存（更快），再到 CPU 寄存器（最快）。GPU 也是如此，必须处理一个可能会显著影响应用程序速度的内存层次结构。

GPU 上最快的也是寄存器（或私有）内存，我们拥有的比平均 CPU 多得多。之后是本地内存，这是一种由多个处理单元共享的内存。GPU 本身上最慢的是内存数据缓存，也称为纹理内存。这是卡上的一种内存，通常被称为视频 RAM（VRAM），使用高带宽，但相对高延迟的内存，如 GDDR5。

绝对最慢的是使用主机系统的内存（系统 RAM），因为这需要通过 PCIe 总线和其他各种子系统传输任何数据。相对于设备内存系统，主机设备通信最好称为“冰川”。

对于 AMD、Nvidia 和类似的专用 GPU 设备，内存架构可以像这样进行可视化：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/26a187e6-07c2-4122-87ba-9911d6f052a0.png)

由于这种内存布局，建议以大块传输任何数据，并在可能的情况下使用异步传输。理想情况下，内核将在 GPU 核心上运行，并将数据流式传输到它，以避免任何延迟。

# GPGPU 和多线程

将多线程代码与 GPGPU 结合起来要比尝试在 MPI 集群上运行并行应用程序更容易得多。这主要是由于以下工作流程：

1.  准备数据：准备我们要处理的数据，例如大量图像或单个大图像，通过将其发送到 GPU 的内存中。

1.  准备内核：加载 OpenCL 内核文件并将其编译成 OpenCL 内核。

1.  执行内核：将内核发送到 GPU 并指示它开始处理数据。

1.  读取数据：一旦我们知道处理已经完成，或者达到了特定的中间状态，我们将读取我们传递给 OpenCL 内核作为参数的缓冲区，以获取我们的结果。

由于这是一个异步过程，可以将其视为一种“发射并忘记”的操作，只需有一个专用线程来监视活动内核的过程。

在多线程和 GPGPU 应用程序方面最大的挑战不在于基于主机的应用程序，而在于运行在 GPU 上的 GPGPU 内核或着色器程序，因为它必须在本地和远程处理单元之间协调内存管理和处理，确定根据数据类型使用哪种内存系统，而不会在处理中引起其他问题。

这是一个需要大量试错、分析和优化的精细过程。一个内存复制优化或使用异步操作而不是同步操作可能将处理时间从几个小时减少到几分钟。对内存系统的良好理解对于防止数据饥饿和类似问题至关重要。

由于 GPGPU 通常用于加速持续时间显著的任务（几分钟到几小时甚至更长），因此最好从多线程的角度来看待它，尽管存在一些重要的复杂性，主要是延迟的形式。

# 延迟

正如我们在早期关于 GPU 内存管理的部分提到的，最好首先使用最接近 GPU 处理单元的内存，因为它们是最快的。这里的最快主要意味着它们具有较低的延迟，即从内存请求信息到接收响应所需的时间。

确切的延迟会因 GPU 而异，但以 Nvidia 的 Kepler（Tesla K20）架构为例，可以期望延迟为：

+   **全局**内存：450 个周期。

+   **常量**内存缓存：45-125 个周期。

+   **本地**（**共享**）内存：45 个周期。

这些测量都是在 CPU 上进行的。对于 PCIe 总线，一旦开始传输多兆字节的缓冲区，每次传输可能需要几毫秒的时间。例如，填充 GPU 内存的一个大小为 1GB 的缓冲区可能需要相当长的时间。

对于 PCIe 总线的简单往返，延迟可能在微秒级别，对于以 1+ GHz 运行的 GPU 核心来说，似乎是一个漫长的时间。这基本上定义了为什么主机和 GPU 之间的通信应该尽可能少，并且高度优化。

# 潜在问题

GPGPU 应用程序的一个常见错误是在处理完成之前读取结果缓冲区。在将缓冲区传输到设备并执行内核之后，必须插入同步点以向主机发出已完成处理的信号。这些通常应该使用异步方法实现。

正如我们在延迟部分所讨论的，重要的是要记住请求和响应之间潜在的非常大的延迟，这取决于内存子系统或总线。不这样做可能会导致奇怪的故障、冻结和崩溃，以及数据损坏和似乎永远等待的应用程序。

对 GPGPU 应用程序进行分析是至关重要的，以便了解 GPU 利用率如何，以及流程是否接近最佳状态。

# 调试 GPGPU 应用程序

GPGPU 应用程序最大的挑战在于调试内核。CUDA 带有模拟器，允许在 CPU 上运行和调试内核。OpenCL 允许在 CPU 上运行内核而无需修改，尽管这可能无法获得与在特定 GPU 设备上运行时相同的行为（和错误）。

一个稍微更高级的方法涉及使用专用调试器，比如 Nvidia 的 Nsight，它有适用于 Visual Studio（[`developer.nvidia.com/nvidia-nsight-visual-studio-edition`](https://developer.nvidia.com/nvidia-nsight-visual-studio-edition)）和 Eclipse（[`developer.nvidia.com/nsight-eclipse-edition`](https://developer.nvidia.com/nsight-eclipse-edition)）的版本。

根据 Nsight 网站上的营销宣传：

英伟达 Nsight Visual Studio Edition 将 GPU 计算引入了 Microsoft Visual Studio（包括多个 VS2017 实例）。这款用于 GPU 的应用程序开发环境允许您构建、调试、分析和跟踪使用 CUDA C/C++、OpenCL、DirectCompute、Direct3D、Vulkan API、OpenGL、OpenVR 和 Oculus SDK 构建的异构计算、图形和虚拟现实应用程序。

以下截图显示了一个活跃的 CUDA 调试会话：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/74e349e0-dec7-41a7-809f-f167a52a522f.png)

这样一个调试器工具的一个重要优势是，它允许用户通过识别瓶颈和潜在问题来监视、分析和优化自己的 GPGPU 应用程序。

# 总结

在本章中，我们看了如何将 GPGPU 处理集成到 C++应用程序中，以 OpenCL 的形式。我们还研究了 GPU 内存层次结构以及这如何影响性能，特别是在主机-设备通信方面。

现在您应该熟悉 GPGPU 的实现和概念，以及如何创建一个 OpenCL 应用程序，以及如何编译和运行它。如何避免常见错误也应该是已知的。

作为本书的最后一章，希望所有主要问题都已得到解答，并且前面的章节以及本章在某种程度上都是有益和有帮助的。

从这本书中继续，读者可能对更详细地探讨其中涉及的任何主题感兴趣，这方面有很多在线和离线资源可用。多线程和相关领域的主题非常广泛，涉及到许多应用，从商业到科学、艺术和个人应用。

读者可能想要建立自己的 Beowulf 集群，或者专注于 GPGPU，或者将两者结合起来。也许有一个复杂的应用程序他们想要写一段时间了，或者只是想玩编程。


# 第二十章：C++17 STL Cookbook

*发现函数式编程和 lambda 表达式的最新增强*


# 第二十一章：新的 C++17 功能

在本章中，我们将涵盖以下内容：

+   使用结构化绑定来解包捆绑的返回值

+   将变量范围限制为`if`和`switch`语句

+   从新的括号初始化规则中获益

+   让构造函数自动推断结果模板类类型

+   使用 constexpr-if 简化编译时决策

+   使用内联变量启用仅头文件库

+   使用折叠表达式实现方便的辅助函数

# 介绍

C++在 C++11、C++14 和最近的 C++17 中增加了很多内容。到目前为止，它与十年前完全不同。C++标准不仅标准化了语言，因为它需要被编译器理解，还标准化了 C++标准模板库（STL）。

本书将解释如何通过大量示例充分利用 STL。但首先，本章将集中讨论最重要的新语言特性。掌握它们将极大地帮助您编写可读、可维护和富有表现力的代码。

我们将看到如何使用结构化绑定舒适地访问对、元组和结构的单个成员，以及如何使用新的`if`和`switch`变量初始化功能来限制变量范围。C++11 引入了新的括号初始化语法，它看起来与初始化列表相同，引入了语法上的歧义，这些问题已经通过*新的括号初始化规则*得到解决。现在可以从实际构造函数参数中*推断*模板类实例的确切*类型*，如果模板类的不同特化将导致完全不同的代码，现在可以使用 constexpr-if 轻松表达。在许多情况下，使用新的*折叠表达式*可以使模板函数中的可变参数包处理变得更加容易。最后，使用新的内联变量声明静态全局可访问对象在仅头文件库中变得更加舒适，这在之前只对函数可行。

本章中的一些示例对库的实现者可能更有趣，而对于实现应用程序的开发人员来说可能不那么重要。虽然出于完整性的原因我们将研究这些特性，但不需要立即理解本章的所有示例就能理解本书的其余部分。

# 使用结构化绑定来解包捆绑的返回值

C++17 带来了一个新特性，结合了语法糖和自动类型推断：**结构化绑定**。这有助于将对、元组和结构的值分配给单独的变量。在其他编程语言中，这也被称为**解包**。

# 如何做...

应用结构化绑定以从一个捆绑结构中分配多个变量始终是一步。让我们首先看看 C++17 之前是如何做的。然后，我们可以看一下多个示例，展示了我们如何在 C++17 中做到这一点：

+   访问`std::pair`的单个值：假设我们有一个数学函数`divide_remainder`，它接受*被除数*和*除数*参数，并返回两者的分数以及余数。它使用`std::pair`捆绑返回这些值：

```cpp
        std::pair<int, int> divide_remainder(int dividend, int divisor);

```

考虑以下访问结果对的单个值的方式：

```cpp
        const auto result (divide_remainder(16, 3));
        std::cout << "16 / 3 is " 
                  << result.first << " with a remainder of " 
                  << result.second << 'n';
```

我们现在可以使用有表达力的名称将单个值分配给单独的变量，这样阅读起来更好：

```cpp
 auto [fraction, remainder] = divide_remainder(16, 3);
        std::cout << "16 / 3 is " 
                  << fraction << " with a remainder of "       
                  << remainder << 'n';
```

+   结构化绑定也适用于`std::tuple`：让我们看看以下示例函数，它可以获取在线股票信息：

```cpp
        std::tuple<std::string, 
                   std::chrono::system_clock::time_point, unsigned>
        stock_info(const std::string &name);
```

将其结果分配给单独的变量看起来就像前面的示例：

```cpp
 const auto [name, valid_time, price] = stock_info("INTC");
```

+   结构化绑定也适用于自定义结构：假设有以下结构：

```cpp
        struct employee {
            unsigned id;
            std::string name;
            std::string role;
            unsigned salary;
        };
```

现在，我们可以使用结构化绑定访问这些成员。假设我们有一个整个向量：

```cpp
        int main()
        {
            std::vector<employee> employees {
                /* Initialized from somewhere */};

            for (const auto &[id, name, role, salary] : employees) {
                std::cout << "Name: "   << name
                          << "Role: "   << role
                          << "Salary: " << salary << 'n';
            }
        }
```

# 它是如何工作的...

结构化绑定总是以相同的模式应用：

```cpp
auto [var1, var2, ...] = <pair, tuple, struct, or array expression>;
```

+   变量列表`var1, var2, ...`必须与被赋值的表达式包含的变量数量完全匹配。

+   `<pair, tuple, struct, or array expression>`必须是以下之一：

+   一个`std::pair`。

+   一个`std::tuple`。

+   一个`struct`。所有成员必须是*非静态*的，并且定义在*同一个基类*中。第一个声明的成员被分配给第一个变量，第二个成员被分配给第二个变量，依此类推。

+   固定大小的数组。

+   类型可以是`auto`、`const auto`、`const auto&`，甚至`auto&&`。

不仅出于*性能*的考虑，始终确保通过在适当的情况下使用引用来最小化不必要的复制。

如果我们在方括号之间写入*太多*或*太少*的变量，编译器将报错，告诉我们我们的错误：

```cpp
std::tuple<int, float, long> tup {1, 2.0, 3};
auto [a, b] = tup; // Does not work
```

这个例子显然试图将一个包含三个成员的元组变量塞入只有两个变量的情况中。编译器立即对此进行了处理，并告诉我们我们的错误：

```cpp
error: type 'std::tuple<int, float, long>' decomposes into 3 elements, but only 2 names were provided
auto [a, b] = tup;
```

# 还有更多...

STL 中的许多基本数据结构都可以立即使用结构化绑定进行访问，而无需我们改变任何内容。例如，考虑一个循环，打印出`std::map`的所有项：

```cpp
std::map<std::string, size_t> animal_population {
    {"humans",   7000000000},
    {"chickens", 17863376000},
    {"camels",   24246291},
    {"sheep",    1086881528},
    /* … */
};

for (const auto &[species, count] : animal_population) {
    std::cout << "There are " << count << " " << species 
              << " on this planet.n";
}
```

这个特定的例子之所以有效，是因为当我们遍历一个`std::map`容器时，我们在每次迭代步骤上得到`std::pair<const key_type, value_type>`节点。正是这些节点使用结构化绑定功能（`key_type`是`species`字符串，`value_type`是人口计数`size_t`）进行拆包，以便在循环体中单独访问它们。

在 C++17 之前，可以使用`std::tie`来实现类似的效果：

```cpp
int remainder;
std::tie(std::ignore, remainder) = divide_remainder(16, 5);
std::cout << "16 % 5 is " << remainder << 'n';
```

这个例子展示了如何将结果对拆分成两个变量。`std::tie`在某种意义上比结构化绑定功能弱，因为我们必须在*之前*定义我们想要绑定的所有变量。另一方面，这个例子展示了`std::tie`的一个优势，结构化绑定没有：值`std::ignore`充当一个虚拟变量。结果的小数部分被分配给它，这导致该值被丢弃，因为在这个例子中我们不需要它。

在使用结构化绑定时，我们没有`tie`虚拟变量，因此我们必须将所有的值绑定到命名变量。尽管如此，忽略其中一些是有效的，因为编译器可以轻松地优化未使用的绑定。

回到过去，`divide_remainder`函数可以以以下方式实现，使用输出参数：

```cpp
bool divide_remainder(int dividend, int divisor, 
                      int &fraction, int &remainder);

```

访问它看起来像这样：

```cpp
int fraction, remainder;
const bool success {divide_remainder(16, 3, fraction, remainder)};
if (success) {
    std::cout << "16 / 3 is " << fraction << " with a remainder of " 
              << remainder << 'n';
}
```

很多人仍然更喜欢这种方式，而不是返回像对、元组和结构这样的复杂结构，他们认为这样代码会更*快*，因为避免了这些值的中间复制。对于现代编译器来说，这*不再是真的*，因为它们会优化掉中间复制。

除了 C 语言中缺少的语言特性外，通过返回值返回复杂结构长时间被认为是慢的，因为对象必须在返回函数中初始化，然后复制到应该包含返回值的变量中。现代编译器支持**返回值优化**（RVO），可以省略中间复制。

# 将变量范围限制在 if 和 switch 语句中

尽可能限制变量的范围是一个很好的风格。然而，有时候，我们首先需要获取一些值，只有在符合某种条件的情况下，才能进一步处理。

为此，C++17 提供了带有初始化程序的`if`和`switch`语句。

# 如何做...

在这个示例中，我们在支持的上下文中都使用了初始化程序语法，以便看到它们如何整理我们的代码：

+   `if`语句：假设我们想要使用`std::map`的`find`方法在字符映射中找到一个字符：

```cpp
       if (auto itr (character_map.find(c)); itr != character_map.end()) {
           // *itr is valid. Do something with it.
       } else {
           // itr is the end-iterator. Don't dereference.
       }
       // itr is not available here at all

```

+   `switch`语句：这是从输入中获取字符并同时在`switch`语句中检查值以控制计算机游戏的样子。

```cpp
       switch (char c (getchar()); c) {
           case 'a': move_left();  break;
           case 's': move_back();  break;
           case 'w': move_fwd();   break;
           case 'd': move_right(); break;
           case 'q': quit_game();  break;

           case '0'...'9': select_tool('0' - c); break;

           default:
               std::cout << "invalid input: " << c << 'n';
       }
```

# 工作原理...

带有初始化器的`if`和`switch`语句基本上只是语法糖。以下两个示例是等效的：

*C++17 之前*：

```cpp
{
    auto var (init_value);
    if (condition) {
        // branch A. var is accessible
    } else {
        // branch B. var is accessible
    }
    // var is still accessible
}
```

*自* C++17：

```cpp
if (auto var (init_value); condition) {
    // branch A. var is accessible
} else {
    // branch B. var is accessible
}
// var is not accessible any longer
```

同样适用于`switch`语句：

在 C++17 之前：

```cpp
{
    auto var (init_value);
    switch (var) {
    case 1: ...
    case 2: ...
    ...
    }
    // var is still accessible
}
```

自 C++17 以来：

```cpp
switch (auto var (init_value); var) {
case 1: ...
case 2: ...
  ...
}
// var is not accessible any longer
```

这个特性非常有用，可以使变量的作用域尽可能短。在 C++17 之前，只能在代码周围使用额外的大括号来实现这一点，正如 C++17 之前的示例所示。短暂的生命周期减少了作用域中的变量数量，使我们的代码整洁，并且更容易重构。

# 还有更多...

另一个有趣的用例是临界区的有限作用域。考虑以下例子：

```cpp
if (std::lock_guard<std::mutex> lg {my_mutex}; some_condition) {
    // Do something
}
```

首先，创建一个`std::lock_guard`。这是一个接受互斥体参数作为构造函数参数的类。它在其构造函数中*锁定*互斥体，并且当它超出作用域时，在其析构函数中再次*解锁*它。这样，忘记解锁互斥体是不可能的。在 C++17 之前，需要一对额外的大括号来确定它再次解锁的作用域。

另一个有趣的用例是弱指针的作用域。考虑以下情况：

```cpp
if (auto shared_pointer (weak_pointer.lock()); shared_pointer != nullptr) {
    // Yes, the shared object does still exist
} else {
    // shared_pointer var is accessible, but a null pointer
}
// shared_pointer is not accessible any longer
```

这是另一个例子，我们会有一个无用的`shared_pointer`变量泄漏到当前作用域，尽管它在`if`条件块外部或有嘈杂的额外括号时可能是无用的！

带有初始化器的`if`语句在使用*遗留*API 和输出参数时特别有用：

```cpp
if (DWORD exit_code; GetExitCodeProcess(process_handle, &exit_code)) {
    std::cout << "Exit code of process was: " << exit_code << 'n';
}
// No useless exit_code variable outside the if-conditional
```

`GetExitCodeProcess`是 Windows 内核 API 函数。它返回给定进程句柄的退出代码，但只有在该句柄有效时才会返回。离开这个条件块后，变量就变得无用了，所以我们不再需要它在任何作用域中。

能够在`if`块中初始化变量在许多情况下显然非常有用，特别是在处理使用输出参数的遗留 API 时。

使用`if`和`switch`语句的初始化器来保持作用域紧凑。这样可以使您的代码更紧凑，更易于阅读，并且在代码重构会话中，移动代码会更容易。

# 从新的大括号初始化规则中获益

C++11 带来了新的大括号初始化语法`{}`。它的目的是允许*聚合*初始化，但也允许通常的构造函数调用。不幸的是，当将这个语法与`auto`变量类型结合使用时，很容易表达错误的事情。C++17 带来了增强的初始化规则。在本教程中，我们将阐明如何在 C++17 中使用哪种语法正确初始化变量。

# 如何做...

变量在一步中初始化。使用初始化语法，有两种不同的情况：

+   在不带有`auto`类型推断的大括号初始化语法中：

```cpp
       // Three identical ways to initialize an int:
       int x1 = 1;
       int x2  {1};
       int x3  (1);

       std::vector<int> v1   {1, 2, 3}; // Vector with three ints: 1, 2, 3
       std::vector<int> v2 = {1, 2, 3}; // same here
       std::vector<int> v3   (10, 20);  // Vector with 10 ints, 
                                        // each have value 20
```

+   使用带有`auto`类型推断的大括号初始化语法：

```cpp
       auto v   {1};         // v is int
       auto w   {1, 2};      // error: only single elements in direct 
                             // auto initialization allowed! (this is new)
       auto x = {1};         // x is std::initializer_list<int>
       auto y = {1, 2};      // y is std::initializer_list<int>
       auto z = {1, 2, 3.0}; // error: Cannot deduce element type
```

# 工作原理...

没有`auto`类型推断时，在使用大括号`{}`操作符初始化常规类型时，不会有太多令人惊讶的地方。当初始化容器如`std::vector`、`std::list`等时，大括号初始化将匹配该容器类的`std::initializer_list`构造函数。它以*贪婪*的方式进行匹配，这意味着不可能匹配非聚合构造函数（非聚合构造函数是通常的构造函数，与接受初始化列表的构造函数相对）。

`std::vector`，例如，提供了一个特定的非聚合构造函数，它可以用相同的值填充任意多个项目：`std::vector<int> v (N, value)`。当写成`std::vector<int> v {N, value}`时，将选择`initializer_list`构造函数，它将用两个项目`N`和`value`初始化向量。这是一个特殊的陷阱，人们应该知道。

与使用普通的`()`括号调用构造函数相比，`{}`操作符的一个好处是它们不进行隐式类型转换：`int x (1.2);` 和 `int x = 1.2;` 会将`x`初始化为值`1`，通过将浮点值四舍五入并将其转换为 int。相比之下，`int x {1.2};` 不会编译，因为它要*完全*匹配构造函数类型。

人们可以就哪种初始化样式是最好的进行有争议的讨论。

支持大括号初始化样式的人说，使用大括号使得变量被构造函数调用初始化非常明确，并且这行代码不会重新初始化任何东西。此外，使用`{}`大括号将选择唯一匹配的构造函数，而使用`()`括号的初始化行则尝试匹配最接近的构造函数，甚至进行类型转换以进行匹配。

C++17 引入的附加规则影响了使用`auto`类型推断的初始化--虽然 C++11 会正确地将变量`auto x {123};`的类型推断为只有一个元素的`std::initializer_list<int>`，但这很少是我们想要的。C++17 会将相同的变量推断为`int`。

经验法则：

+   `auto var_name {one_element};` 推断`var_name`与`one_element`的类型相同

+   `auto var_name {element1, element2, ...};` 是无效的，无法编译

+   `auto var_name = {element1, element2, ...};` 推断为一个`std::initializer_list<T>`，其中`T`与列表中所有元素的类型相同

C++17 使得意外定义初始化列表变得更加困难。

在 C++11/C++14 模式下尝试使用不同的编译器将会显示一些编译器实际上将`auto x {123};`推断为`int`，而其他编译器将其推断为`std::initializer_list<int>`。编写这样的代码可能会导致可移植性问题！

# 让构造函数自动推断出结果模板类的类型

C++中的许多类通常是专门针对类型进行特化的，这些类型可以很容易地从用户在构造函数调用中放入的变量类型中推断出来。然而，在 C++17 之前，这不是一个标准化的特性。C++17 允许编译器从构造函数调用中*自动*推断模板类型。

# 如何做...

这种情况的一个非常方便的用例是构造`std::pair`和`std::tuple`实例。这些可以在一步中进行专门化和实例化：

```cpp
std::pair  my_pair  (123, "abc");       // std::pair<int, const char*>
std::tuple my_tuple (123, 12.3, "abc"); // std::tuple<int, double,
                                        //            const char*>
```

# 它是如何工作的...

让我们定义一个示例类，其中自动模板类型推断将会有价值：

```cpp
template <typename T1, typename T2, typename T3>
class my_wrapper {
    T1 t1;
    T2 t2;
    T3 t3;

public:
    explicit my_wrapper(T1 t1_, T2 t2_, T3 t3_) 
        : t1{t1_}, t2{t2_}, t3{t3_}
    {}

    /* … */
};
```

好吧，这只是另一个模板类。以前我们必须这样写才能实例化它：

```cpp
my_wrapper<int, double, const char *> wrapper {123, 1.23, "abc"};
```

现在我们可以省略模板专门化部分：

```cpp
my_wrapper wrapper {123, 1.23, "abc"};
```

在 C++17 之前，只能通过实现*make 函数助手*来实现这一点：

```cpp
my_wrapper<T1, T2, T3> make_wrapper(T1 t1, T2 t2, T3 t3)
{
    return {t1, t2, t3};
}
```

使用这样的辅助函数，可以实现类似的效果：

```cpp
auto wrapper (make_wrapper(123, 1.23, "abc"));
```

STL 已经提供了许多类似的辅助函数，如`std::make_shared`、`std::make_unique`、`std::make_tuple`等。在 C++17 中，这些现在大多可以被视为过时。当然，它们将继续提供以确保兼容性。

# 还有更多...

我们刚刚学到的是*隐式模板类型推断*。在某些情况下，我们不能依赖隐式类型推断。考虑以下示例类：

```cpp
template <typename T>
struct sum {
    T value;

    template <typename ... Ts>
    sum(Ts&& ... values) : value{(values + ...)} {}
};
```

这个结构`sum`接受任意数量的参数，并使用折叠表达式将它们相加（稍后在本章中查看折叠表达式示例，以获取有关折叠表达式的更多详细信息）。结果的和保存在成员变量`value`中。现在的问题是，`T`是什么类型？如果我们不想明确指定它，它肯定需要依赖于构造函数中提供的值的类型。如果我们提供字符串实例，它需要是`std::string`。如果我们提供整数，它需要是`int`。如果我们提供整数、浮点数和双精度浮点数，编译器需要找出哪种类型适合所有值而不会丢失信息。为了实现这一点，我们提供了一个*显式推导指南*：

```cpp
template <typename ... Ts>
sum(Ts&& ... ts) -> sum<std::common_type_t<Ts...>>;
```

这个推导指南告诉编译器使用`std::common_type_t`特性，它能够找出适合所有值的公共类型。让我们看看如何使用它：

```cpp
sum s          {1u, 2.0, 3, 4.0f};
sum string_sum {std::string{"abc"}, "def"};

std::cout << s.value          << 'n'
          << string_sum.value << 'n';
```

在第一行中，我们使用`unsigned`，`double`，`int`和`float`类型的构造函数参数实例化了一个`sum`对象。`std::common_type_t`返回`double`作为公共类型，所以我们得到一个`sum<double>`实例。在第二行中，我们提供了一个`std::string`实例和一个 C 风格的字符串。根据我们的推导指南，编译器构造了一个`sum<std::string>`类型的实例。

运行此代码时，它将打印数字和字符串的和。

# 使用 constexpr-if 简化编译时决策

在模板化的代码中，通常需要根据模板专门化的类型来做一些不同的事情。C++17 带来了 constexpr-if 表达式，它大大简化了这种情况下的代码。

# 如何做...

在这个示例中，我们将实现一个小的辅助模板类。它可以处理不同的模板类型专门化，因为它能够根据我们为其专门化的类型在某些段落中选择完全不同的代码：

1.  编写通用部分的代码。在我们的例子中，这是一个简单的类，支持使用`add`函数将类型`U`的值添加到类型`T`的成员值中：

```cpp
       template <typename T>
       class addable
       { 
           T val;

       public:
           addable(T v) : val{v} {}

           template <typename U>
           T add(U x) const {
               return val + x;
           }
       };
```

1.  假设类型`T`是`std::vector<something>`，类型`U`只是`int`。将整数添加到整个向量意味着什么？我们说这意味着我们将整数添加到向量中的每个项目。这将在循环中完成：

```cpp
       template <typename U>
       T add(U x) 
       {
           auto copy (val); // Get a copy of the vector member
           for (auto &n : copy) { 
               n += x;
           }
           return copy;
       }
```

1.  下一步，也是最后一步是*结合*两个世界。如果`T`是`U`项的向量，则执行*循环*变体。如果不是，则只需实现*正常*的加法：

```cpp
       template <typename U>
       T add(U x) const {
           if constexpr (std::is_same_v<T, std::vector<U>>) {
               auto copy (val);
               for (auto &n : copy) { 
                   n += x;
               }
               return copy;
           } else {
               return val + x;
           }
       }

```

1.  现在可以使用该类。让我们看看它如何与完全不同的类型一起工作，例如`int`，`float`，`std::vector<int>`和`std::vector<string>`：

```cpp
       addable<int>{1}.add(2);               // is 3
       addable<float>{1.0}.add(2);           // is 3.0
       addable<std::string>{"aa"}.add("bb"); // is "aabb"

       std::vector<int> v {1, 2, 3};
       addable<std::vector<int>>{v}.add(10); 
           // is std::vector<int>{11, 12, 13}

       std::vector<std::string> sv {"a", "b", "c"};
       addable<std::vector<std::string>>{sv}.add(std::string{"z"}); 
           // is {"az", "bz", "cz"}
```

# 它是如何工作的...

新的 constexpr-if 的工作方式与通常的 if-else 结构完全相同。不同之处在于它测试的条件必须在*编译时*进行评估。编译器从我们的程序创建的所有运行时代码都不包含来自 constexpr-if 条件语句的任何分支指令。也可以说它的工作方式类似于预处理器`#if`和`#else`文本替换宏，但对于这些宏，代码甚至不需要在语法上是良好形式的。constexpr-if 结构的所有分支都需要*语法上良好形式*，但*不*采取的分支不需要*语义上有效*。

为了区分代码是否应该将值`x`添加到向量中，我们使用类型特征`std::is_same`。表达式`std::is_same<A, B>::value`在`A`和`B`是相同类型时求值为布尔值`true`。我们的条件是`std::is_same<T, std::vector<U>>::value`，如果用户将类专门化为`T = std::vector<X>`并尝试使用类型`U = X`的参数调用`add`，则求值为`true`。

当然，constexpr-if-else 块中可以有多个条件（注意`a`和`b`必须依赖于模板参数，而不仅仅是编译时常量）：

```cpp
if constexpr (a) {
    // do something
} else if constexpr (b) {
    // do something else 
} else {
    // do something completely different
}
```

使用 C++17，许多元编程情况更容易表达和阅读。

# 还有更多...

为了说明 constexpr-if 结构对 C++的改进有多大，我们可以看看在 C++17*之前*如何实现相同的事情：

```cpp
template <typename T>
class addable
{
    T val;

public:
    addable(T v) : val{v} {}

    template <typename U>
 std::enable_if_t<!std::is_same<T, std::vector<U>>::value, T>
    add(U x) const { return val + x; }

    template <typename U>
 std::enable_if_t<std::is_same<T, std::vector<U>>::value, 
                     std::vector<U>>
    add(U x) const {
        auto copy (val);
        for (auto &n : copy) { 
            n += x;
        }
        return copy;
    }
};
```

在不使用 constexpr-if 的情况下，这个类适用于我们希望的所有不同类型，但看起来非常复杂。它是如何工作的？

*两个不同*`add`函数的实现看起来很简单。它们的返回类型声明使它们看起来复杂，并且包含一个技巧--例如`std::enable_if_t<condition, type>`表达式在`condition`为`true`时评估为`type`。否则，`std::enable_if_t`表达式不会评估为任何东西。这通常被认为是一个错误，但我们将看到为什么它不是。

对于第二个`add`函数，相同的条件以*反转*的方式使用。这样，它只能同时对两个实现中的一个为`true`。

当编译器看到具有相同名称的不同模板函数并且必须选择其中一个时，一个重要的原则就会发挥作用：**SFINAE**，它代表**替换失败不是错误**。在这种情况下，这意味着如果其中一个函数的返回值无法从错误的模板表达式中推导出（如果其条件评估为`false`，则`std::enable_if`是错误的），则编译器不会报错。它将简单地继续寻找并尝试*其他*函数实现。这就是诀窍；这就是它是如何工作的。

真是麻烦。很高兴看到这在 C++17 中变得如此容易。

# 使用内联变量启用仅头文件库

虽然在 C++中一直可以声明单独的函数*内联*，但 C++17 还允许我们声明*变量*内联。这使得实现*仅头文件*库变得更加容易，这在以前只能使用变通方法实现。

# 它是如何实现的...

在这个示例中，我们创建了一个示例类，它可以作为典型的仅头文件库的成员。目标是使用`inline`关键字以静态成员的方式实例化它，并以全局可用的方式使用它，这在 C++17 之前是不可能的。

1.  `process_monitor`类应该同时包含一个静态成员并且本身应该是全局可访问的，这将在从多个翻译单元包含时产生双重定义的符号：

```cpp
       // foo_lib.hpp 

       class process_monitor { 
       public: 
           static const std::string standard_string 
               {"some static globally available string"}; 
       };

       process_monitor global_process_monitor;
```

1.  如果我们现在在多个`.cpp`文件中包含这个以便编译和链接它们，这将在链接阶段失败。为了解决这个问题，我们添加`inline`关键字：

```cpp
       // foo_lib.hpp 

       class process_monitor { 
       public: 
           static const inline std::string standard_string 
               {"some static globally available string"}; 
       };

       inline process_monitor global_process_monitor;
```

看，就是这样！

# 它是如何工作的...

C++程序通常由多个 C++源文件组成（这些文件具有`.cpp`或`.cc`后缀）。这些文件被单独编译为模块/对象文件（通常具有.o 后缀）。然后将所有模块/对象文件链接在一起成为单个可执行文件或共享/静态库是最后一步。

在链接阶段，如果链接器可以找到一个特定符号的定义*多次*，则被视为错误。例如，我们有一个带有`int foo();`签名的函数。如果两个模块定义了相同的函数，那么哪一个是正确的？链接器不能随意选择。嗯，它可以，但这很可能不是任何程序员想要发生的事情。

提供全局可用函数的传统方法是在头文件中*声明*它们，这些头文件将被任何需要调用它们的 C++模块包含。然后，这些函数的定义将被放入单独的模块文件中*一次*。然后，这些模块与希望使用这些函数的模块一起链接在一起。这也被称为**一次定义规则**（**ODR**）。查看以下插图以更好地理解：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/ee850b95-1991-4682-a5d1-1c7290509001.png)

然而，如果这是唯一的方法，那么就不可能提供仅包含头文件的库。仅包含头文件的库非常方便，因为它们只需要使用`#include`包含到任何 C++程序文件中，然后立即可用。为了使用不是仅包含头文件的库，程序员还必须调整构建脚本，以便链接器将库模块与自己的模块文件一起链接。特别是对于只有非常短函数的库，这是不必要的不舒服。

对于这种情况，`inline`关键字可以用来做一个例外，以允许在不同模块中*多次*定义相同的符号。如果链接器找到具有相同签名的多个符号，但它们被声明为内联，它将只选择第一个并相信其他符号具有相同的定义。所有相等的内联符号都完全相等的定义基本上是程序员的*承诺*。

关于我们的 reciple 示例，链接器将在每个包含`foo_lib.hpp`的模块中找到`process_monitor::standard_string`符号。没有`inline`关键字，它将不知道选择哪一个，因此它将中止并报告错误。对`global_process_monitor`符号也是一样。哪一个才是正确的？

在声明两个符号`inline`后，它将只接受每个符号的第一次出现，并*丢弃*所有其他出现。

在 C++17 之前，唯一的干净方法是通过额外的 C++模块文件提供此符号，这将迫使我们的库用户在链接步骤中包含此文件。

`inline`关键字传统上还有*另一个*功能。它告诉编译器可以通过获取其实现并直接将其放在调用它的地方来*消除*函数调用。这样，调用代码包含一个函数调用少，这通常被认为更快。如果函数非常短，生成的汇编代码也会更短（假设执行函数调用的指令数量，保存和恢复堆栈等比实际有效载荷代码更高）。如果内联函数非常长，二进制大小将增长，这有时甚至可能不会导致最终更快的代码。

因此，编译器只会将`inline`关键字作为提示，并可能通过内联来消除函数调用。但它也可以内联一些函数，*而不需要*程序员声明为内联。

# 还有更多...

在 C++17 之前的一个可能的解决方法是提供一个`static`函数，它返回一个`static`对象的引用：

```cpp
class foo {
public:
    static std::string& standard_string() {
        static std::string s {"some standard string"};
        return s;
    }
};
```

这样，将头文件包含在多个模块中是完全合法的，但仍然可以在任何地方访问到完全相同的实例。然而，对象并不是在程序开始时立即构造的，而是只有在第一次调用此 getter 函数时才会构造。对于某些用例，这确实是一个问题。想象一下，我们希望静态的全局可用对象的构造函数在*程序开始*时做一些重要的事情（就像我们的 reciple 示例库类），但由于 getter 在程序结束时被调用，这就太晚了。

另一个解决方法是将非模板类`foo`变为模板类，这样它就可以从与模板相同的规则中获益。

这两种策略在 C++17 中都可以避免。

# 使用折叠表达式实现方便的辅助函数

自 C++11 以来，有可变模板参数包，它们使得实现接受任意多个参数的函数成为可能。有时，这些参数都被合并成一个表达式，以便从中导出函数结果。这在 C++17 中变得非常容易，因为它带有折叠表达式。

# 如何做...

让我们实现一个函数，它接受任意多个参数并返回它们的总和：

1.  首先，我们定义它的签名：

```cpp
      template <typename ... Ts>
      auto sum(Ts ... ts);
```

1.  所以，现在我们有一个参数包`ts`，函数应该展开所有参数并使用折叠表达式将它们相加。如果我们使用任何操作符（在这个例子中是`+`）与`...`一起，以便将其应用于参数包的所有值，我们需要用括号括起表达式：

```cpp
      template <typename ... Ts>
      auto sum(Ts ... ts)
      {
          return (ts + ...);
      }
```

1.  我们现在可以这样调用它：

```cpp
      int the_sum {sum(1, 2, 3, 4, 5)}; // Value: 15
```

1.  它不仅适用于`int`类型；我们可以用任何实现了`+`运算符的类型来调用它，比如`std::string`：

```cpp
      std::string a {"Hello "};
      std::string b {"World"};

      std::cout << sum(a, b) << 'n'; // Output: Hello World
```

# 它是如何工作的...

我们刚刚做的是对其参数进行简单的递归应用二元运算符(`+`)。这通常被称为*折叠*。C++17 带有**折叠表达式**，它可以用更少的代码表达相同的想法。

这种类型的表达式称为**一元折叠**。C++17 支持使用以下二元操作符对参数包进行折叠：`+`、`-`、`*`、`/`、`%`、`^`、`&`、`|`、`=`、`<`、`>`、`<<`、`>>`、`+=`、`-=`、`*=`、`/=`、`%=`、`^=`、`&=`、`|=`、`<<=`、`>>=`、`==`、`!=`、`<=`、`>=`、`&&`、`||`、`,`、`.*`、`->*`。

顺便说一句，在我们的示例代码中，如果我们写`(ts + ...)`或`(… + ts)`都没有关系；两者都可以。然而，在其他情况下可能会有所不同--如果`…`点在操作符的*右侧*，则折叠称为*右*折叠。如果它们在*左侧*，则是*左*折叠。

在我们的`sum`示例中，一元左折叠展开为`1 + (2 + (3 + (4 + 5)))`，而一元右折叠将展开为`(((1 + 2) + 3) + 4) + 5`。根据使用的操作符，这可能会有所不同。当添加数字时，它并不会有所不同。

# 还有更多...

如果有人用*没有*参数调用`sum()`，则变参参数包不包含可以折叠的值。对于大多数操作符来说，这是一个错误（对于一些操作符来说不是；我们将在一分钟内看到）。然后我们需要决定这是否应该保持为错误，或者空的总和是否应该导致特定的值。显而易见的想法是，什么都没有的总和是`0`。

这就是它的实现方式：

```cpp
template <typename ... Ts>
auto sum(Ts ... ts)
{
    return (ts + ... + 0);
}
```

这样，`sum()`的结果是`0`，`sum(1, 2, 3)`的结果是`(1 + (2 + (3 + 0)))`。这种带有初始值的折叠称为**二进制折叠**。

同样，如果我们写`(ts + ... + 0)`或`(0 + ... + ts)`，它也可以工作，但这会使二进制折叠再次成为二进制*右*折叠或二进制*左*折叠。看看下面的图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/4c518bfa-0a12-435d-820f-0199ee897ce3.png)

当使用二进制折叠来实现无参数情况时，*单位*元素的概念通常很重要--在这种情况下，将`0`添加到任何数字都不会改变任何东西，这使`0`成为单位元素。由于这个属性，我们可以使用`+`或`-`运算符将`0`添加到任何折叠表达式中，这将导致在参数包中没有参数的情况下结果为`0`。从数学的角度来看，这是正确的。从实现的角度来看，我们需要根据需要定义什么是正确的。

相同的原则适用于乘法。在这里，单位元素是`1`：

```cpp
template <typename ... Ts>
auto product(Ts ... ts)
{
    return (ts * ... * 1);
}
```

`product(2, 3)`的结果是`6`，没有参数的`product()`的结果是`1`。

逻辑**和**(`&&`)和**或**(`||`)操作符带有*内置*单位元素。使用`&&`对空参数包进行折叠的结果是`true`，使用`||`对空参数包进行折叠的结果是`false`。

另一个操作符，当应用于空参数包时默认为某个表达式的逗号操作符（`,`），然后默认为`void()`。

为了激发一些灵感，让我们看看我们可以使用这个特性实现的一些更多的小助手。

# 匹配范围与单个项目

如何编写一个函数，告诉我们某个范围是否包含我们提供的变参参数中的*至少一个*值：

```cpp
template <typename R, typename ... Ts>
auto matches(const R& range, Ts ... ts)
{
    return (std::count(std::begin(range), std::end(range), ts) + ...);
}
```

帮助函数使用 STL 中的`std::count`函数。该函数接受三个参数：前两个参数是某个可迭代范围的*begin*和*end*迭代器，作为第三个参数，它接受一个*value*，该值将与范围内的所有项目进行比较。然后，`std::count`方法返回范围内等于第三个参数的所有元素的数量。

在我们的折叠表达式中，我们总是将相同参数范围的*begin*和*end*迭代器传递给`std::count`函数。然而，作为第三个参数，每次我们都将参数包中的另一个参数放入其中。最后，函数将所有结果相加并将其返回给调用者。

我们可以这样使用它：

```cpp
std::vector<int> v {1, 2, 3, 4, 5};

matches(v,         2, 5);          // returns 2
matches(v,         100, 200);      // returns 0
matches("abcdefg", 'x', 'y', 'z'); // returns 0
matches("abcdefg", 'a', 'd', 'f'); // returns 3
```

正如我们所看到的，`matches`帮助函数非常灵活--它可以直接在向量或字符串上调用。它还可以在初始化列表、`std::list`、`std::array`、`std::set`等实例上工作！

# 检查多次插入集合是否成功

让我们编写一个帮助函数，将任意数量的可变参数插入到`std::set`中，并返回所有插入是否*成功*：

```cpp
template <typename T, typename ... Ts>
bool insert_all(T &set, Ts ... ts)
{
    return (set.insert(ts).second && ...);
}
```

那么，这是如何工作的呢？`std::set`的`insert`函数具有以下签名：

```cpp
std::pair<iterator, bool> insert(const value_type& value);
```

文档表示，当我们尝试插入一个项目时，`insert`函数将返回一个对中的`iterator`和`bool`变量。如果插入成功，`bool`值为`true`。如果成功，迭代器指向集合中的*新元素*。否则，迭代器指向*现有*项目，它将与要插入的项目*冲突*。

我们的帮助函数在插入后访问`.second`字段，这只是反映成功或失败的`bool`变量。如果所有插入在所有返回对中都导致`true`，那么所有插入都成功了。折叠表达式使用`&&`运算符将所有插入结果组合在一起并返回结果。

我们可以这样使用它：

```cpp
std::set<int> my_set {1, 2, 3};

insert_all(my_set, 4, 5, 6); // Returns true
insert_all(my_set, 7, 8, 2); // Returns false, because the 2 collides
```

请注意，如果我们尝试插入三个元素，但第二个元素已经无法插入，`&& ...`折叠将会短路并停止插入所有其他元素：

```cpp
std::set<int> my_set {1, 2, 3};

insert_all(my_set, 4, 2, 5); // Returns false
// set contains {1, 2, 3, 4} now, without the 5!

```

# 检查所有参数是否在某个范围内

如果我们可以检查*一个*变量是否在某个特定范围内，我们也可以使用折叠表达式来对*多个*变量执行相同的操作。

```cpp
template <typename T, typename ... Ts>
bool within(T min, T max, Ts ...ts)
{
    return ((min <= ts && ts <= max) && ...);
}
```

表达式`(min <= ts && ts <= max)`确实告诉了参数包的每个值是否在`min`和`max`之间（*包括*`min`和`max`）。我们选择`&&`运算符将所有布尔结果减少为单个结果，只有当所有个别结果都为`true`时才为`true`。

这就是它的实际效果：

```cpp
within( 10,  20,  1, 15, 30);    // --> false
within( 10,  20,  11, 12, 13);   // --> true
within(5.0, 5.5,  5.1, 5.2, 5.3) // --> true
```

有趣的是，这个函数非常灵活，因为它对我们使用的类型的唯一要求是它们可以使用`<=`运算符进行比较。例如，`std::string`也满足这个要求：

```cpp
std::string aaa {"aaa"};
std::string bcd {"bcd"};
std::string def {"def"};
std::string zzz {"zzz"};

within(aaa, zzz,  bcd, def); // --> true
within(aaa, def,  bcd, zzz); // --> false
```

# 将多个项目推入向量

还可以编写一个不减少任何结果但处理相同类型的多个操作的帮助函数。比如将项目插入到`std::vector`中，它不返回任何结果（`std::vector::insert()`通过抛出异常来表示错误）：

```cpp
template <typename T, typename ... Ts>
void insert_all(std::vector<T> &vec, Ts ... ts)
{
    (vec.push_back(ts), ...);
}

int main()
{
    std::vector<int> v {1, 2, 3};
    insert_all(v, 4, 5, 6);
}
```

请注意，我们使用逗号（`,`）运算符来将参数包展开为单独的`vec.push_back(...)`调用，而不是折叠实际结果。这个函数也很好地处理了*空*参数包，因为逗号运算符具有隐式的单位元素`void()`，它转换为*什么也不做*。


# 第二十二章：STL 容器

在本章中，我们将介绍以下配方：

+   在`std::vector`上使用擦除-删除习惯用法

+   在*O(1)*时间内从未排序的`std::vector`中删除项目

+   以快速或安全的方式访问`std::vector`实例

+   保持`std::vector`实例排序

+   有效地和有条件地将项目插入`std::map`

+   了解`std::map::insert`的新插入提示语义

+   有效地修改`std::map`项的键

+   使用`std::unordered_map`与自定义类型

+   使用`std::set`从用户输入中过滤重复项并按字母顺序打印它们

+   使用`std::stack`实现简单的逆波兰计算器

+   使用`std::map`实现词频计数器

+   使用`std::set`实现用于在文本中查找非常长的句子的写作风格辅助工具

+   使用`std::priority_queue`实现个人待办事项列表

# 在`std::vector`上使用擦除-删除习惯用法

许多初学者 C++程序员了解`std::vector`，它基本上就像一个*自动增长的数组*，然后就停在那里。后来，他们只查找它的文档，以了解如何做非常具体的事情，例如*删除*项目。像这样使用 STL 容器只会触及它们帮助编写*清晰*、*可维护*和*快速*代码的表面。

本节重点是从向量实例中间删除项目。当一个项目从向量中消失，并且坐在其他项目的中间*之间*时，那么右边的所有项目都必须向*左*移动一个插槽（这使得这个任务的运行成本在*O(n)*内）。许多初学者程序员会使用*循环*来做到这一点，因为这也不是一件很难做的事情。不幸的是，他们在这样做的过程中可能会忽略很多优化潜力。最后，手工制作的循环既不如 STL 方式*快*，也不如*美观*，我们将在下面看到。

# 如何做...

在本节中，我们正在用一些示例整数填充`std::vector`实例，然后从中删除一些特定的项目。我们正在做的方式被认为是从向量中删除多个项目的*正确*方式。

1.  当然，在我们做任何事情之前，我们需要包括一些头文件。

```cpp
      #include <iostream>
      #include <vector>
      #include <algorithm>
```

1.  然后我们声明我们正在使用`std`命名空间，以节省一些输入。

```cpp
      using namespace std;
```

1.  现在我们创建一个整数向量，并用一些示例项目填充它。

```cpp
      int main()
      {
          vector<int> v {1, 2, 3, 2, 5, 2, 6, 2, 4, 8};
```

1.  下一步是删除项目。我们要删除什么？有多个`2`值。让我们把它们删除。

```cpp
          const auto new_end (remove(begin(v), end(v), 2));
```

1.  有趣的是，这只是两步中的一步。向量仍然具有相同的大小。下一行使它实际上更短。

```cpp
          v.erase(new_end, end(v));
```

1.  让我们在这里停下来，以便将向量的内容打印到终端，然后继续。

```cpp
          for (auto i : v) {
              cout << i << ", ";
          }
          cout << 'n';
```

1.  现在，让我们删除整个*类*的项目，而不是特定的*值*。为了做到这一点，我们首先定义一个谓词函数，它接受一个数字作为参数，并在它是*奇数*时返回`true`。

```cpp
          const auto odd ([](int i) { return i % 2 != 0; });
```

1.  现在我们使用`remove_if`函数，并将其与谓词函数一起使用。与之前的两步删除不同，我们现在只需一步。

```cpp
          v.erase(remove_if(begin(v), end(v), odd), end(v));
```

1.  现在所有奇数项都消失了，但向量的*容量*仍然是旧的 10 个元素。在最后一步中，我们还将其减少到向量的实际*当前*大小。请注意，这可能导致向量代码分配一个适合的新内存块，并将所有项目从旧内存块移动到新内存块。

```cpp
          v.shrink_to_fit();
```

1.  现在，让我们在第二次删除项目后打印内容，就这样。

```cpp
          for (auto i : v) {
              cout << i << ", ";
          }
          cout << 'n';
      }
```

1.  编译和运行程序产生了两种删除项目方法的以下两行输出。

```cpp
      $ ./main 
      1, 3, 5, 6, 4, 8, 
      6, 4, 8,
```

# 它是如何工作的...

在配方中显而易见的是，当从向量中间删除项目时，它们首先需要被*删除*，然后*擦除*。至少我们使用的函数有这样的名称。这显然令人困惑，但让我们仔细看看它，以理解这些步骤。

从向量中删除所有值为`2`的代码如下：

```cpp
const auto new_end (remove(begin(v), end(v), 2));
v.erase(new_end, end(v));
```

`std::begin`和`std::end`函数都接受一个向量实例作为参数，并返回指向*第一个*项目和*最后一个*项目之后的迭代器，就像即将出现的图表中所示的那样。

在将这些值和值`2`传递给`std::remove`函数后，它将将非`2`值向前移动，就像我们可以使用手动编程的循环来做的那样。该算法将严格保留所有非`2`值的顺序。快速查看插图可能有点令人困惑。在第 2 步中，仍然有一个值为`2`，而且向量应该变得更短，因为有四个值为`2`，它们都应该被移除。相反，初始数组中的`4`和`8`被复制了。这是怎么回事？

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/31fad71f-4671-4aae-8626-ff3f3785f7d1.png)

让我们只看看所有在范围内的项目，从插图上的`begin`迭代器到`new_end`迭代器。`new_end`迭代器指向的项目是范围之外的*第一个项目，因此不包括在内。只集中在这个区域（这些只是从`1`到包括`8`的项目），我们意识到*这*是从中删除所有`2`值的*正确*范围。

这就是`erase`调用发挥作用的地方：我们必须告诉向量，它不再应该认为从`new_end`到`end`的所有项目是向量的项目。这个顺序对于向量来说很容易遵循，因为它只需将其`end`迭代器指向`new_end`的位置，就完成了。请注意，`new_end`是`std::remove`调用的返回值，所以我们可以直接使用它。

请注意，向量所做的不仅仅是移动内部指针。如果该向量是更复杂对象的向量，它将调用所有要删除的项目的析构函数。

之后，向量看起来像图表中的第 3 步：它现在被认为是*更小*的。现在超出范围的旧项目仍然在内存中。

为了使向量只占用所需的内存，我们在最后进行`shrink_to_fit`调用。在该调用期间，它将分配所需的内存，移动所有项目并删除我们不再需要的较大块。

在第 8 步中，我们定义了一个*谓词*函数，并在一步中使用它与`std::remove_if`一起使用。这是有效的，因为无论删除函数返回什么迭代器，都可以安全地在向量的 erase 函数中使用。即使*没有找到奇数项*，`std::remove_if`函数也将*什么也不做*，并返回`end`迭代器。然后，像`v.erase(end, end);`这样的调用也不会做任何事情，因此它是无害的。

# 还有更多...

`std::remove`函数也适用于其他容器。当与`std::array`一起使用时，请注意它不支持调用`erase`的第二步，因为它们没有自动大小处理。仅仅因为`std::remove`有效地只是移动项目而不执行它们的实际删除，它也可以用于不支持调整大小的数据结构，例如数组。在数组的情况下，可以使用类似于字符串的哨兵值（例如`''`）覆盖新的结束迭代器之后的值。

# 在 O(1)时间内从未排序的 std::vector 中删除项目

从`std::vector`中间某处删除项目需要*O(n)*时间。这是因为删除项目后产生的间隙必须由将在间隙后面的所有项目向左移动一个插槽来填充。

在像这样移动项目的过程中，如果它们是复杂的和/或非常大的，并包括许多项目，这可能是昂贵的，我们保留它们的顺序。如果保留顺序不重要，我们可以优化这一点，正如本节所示。

# 如何做...

在本节中，我们将使用一些示例数字填充一个`std::vector`实例，并实现一个快速删除函数，它可以在*O(1)*时间内从向量中删除任何项目。

1.  首先，我们需要包含所需的头文件。

```cpp
      #include <iostream>
      #include <vector>
      #include <algorithm>
```

1.  然后，我们定义一个主函数，在其中实例化一个包含示例数字的向量。

```cpp
      int main()
      {
          std::vector<int> v {123, 456, 789, 100, 200};
```

1.  下一步是删除索引为`2`的值（当然是从零开始计数，所以是第三个数字`789`）。我们将使用的函数还没有实现。我们稍后再做。之后，我们打印向量的内容。

```cpp
          quick_remove_at(v, 2);

          for (int i : v) {
              std::cout << i << ", ";
          }                                           
          std::cout << 'n';
```

1.  现在，我们将删除另一个项目。它将是值为`123`，假设我们不知道它的索引。因此，我们将使用`std::find`函数，它接受一个范围（向量）和一个值，然后搜索该值的位置。然后，它会返回一个指向`123`值的*迭代器*。我们将使用相同的`quick_remove_at`函数，但这是*先前*接受*迭代器*的*重载*版本。它也还没有实现。

```cpp
          quick_remove_at(v, std::find(std::begin(v), std::end(v), 123));

          for (int i : v) {
              std::cout << i << ", ";
          }
          std::cout << 'n';
      }
```

1.  除了两个`quick_remove_at`函数，我们已经完成了。所以让我们来实现这些。（请注意，它们应该至少在主函数之前被声明。所以让我们在那里定义它们。）

这两个函数都接受一个*something*（在我们的例子中是`int`值）的向量的引用，所以我们不确定用户会使用什么样的向量。对我们来说，它是一个`T`值的向量。我们使用的第一个`quick_remove_at`函数接受*索引*值，这些值是*数字*，所以接口看起来像下面这样：

```cpp
      template <typename T>
      void quick_remove_at(std::vector<T> &v, std::size_t idx)
      {
```

1.  现在来到食谱的核心部分——我们如何快速删除项目而不移动太多其他项目？首先，我们简单地取出向量中最后一个项目的值，并用它来覆盖将要删除的项目。其次，我们切断向量的最后一个项目。这就是两个步骤。我们在这段代码周围加上了一些健全性检查。如果索引值显然超出了向量范围，我们就什么也不做。否则，例如在空向量上，代码会崩溃。

```cpp
          if (idx < v.size()) {
              v[idx] = std::move(v.back());
              v.pop_back();
          }
      }
```

1.  `quick_remove_at`的另一个实现方式类似。它不是接受一个数字索引，而是接受`std::vector<T>`的迭代器。以通用方式获取其类型并不复杂，因为 STL 容器已经定义了这样的类型。

```cpp
      template <typename T>
      void quick_remove_at(std::vector<T> &v, 
                           typename std::vector<T>::iterator it)
      {

```

1.  现在，我们将访问迭代器指向的值。就像在另一个函数中一样，我们将用向量中的最后一个元素来覆盖它。因为这次我们处理的不是数字索引，而是迭代器，所以我们需要以稍有不同的方式检查迭代器的位置是否合理。如果它指向人为结束的位置，我们就不能对其进行解引用。

```cpp
          if (it != std::end(v)) {
```

1.  在那个 if 块中，我们做的事情和之前一样——我们用最后一个位置的项目的值来覆盖要删除的项目，然后我们从向量中切断最后一个元素：

```cpp
              *it = std::move(v.back());
              v.pop_back();
          }
      }
```

1.  就是这样。编译和运行程序会产生以下输出：

```cpp
      $ ./main 
      123, 456, 200, 100,                           
      100, 456, 200,
```

# 它是如何工作的...

`quick_remove_at`函数可以快速删除项目，而不会触及太多其他项目。它以相对创造性的方式做到这一点：它在某种程度上*交换*了*实际项目*，即将被删除的项目和向量中的*最后一个*项目。尽管最后一个项目与实际选择的项目*没有关联*，但它处于*特殊位置*：删除最后一个项目是*便宜的*！向量的大小只需要减少一个位置，就完成了。在这一步中没有移动任何项目。看一下下面的图表，它有助于想象这是如何发生的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/91627e22-fdaf-41d9-a683-6c96f788f8b8.png)

食谱代码中的两个步骤看起来像这样：

```cpp
v.at(idx) = std::move(v.back());
v.pop_back();
```

这是迭代器版本，看起来几乎一样：

```cpp
*it = std::move(v.back());
v.pop_back();
```

逻辑上，我们*交换*所选项目和最后一个项目。但代码并不交换项目，而是将最后一个项目移动到第一个项目上。为什么？如果我们交换项目，那么我们将不得不将所选项目存储在一个*临时*变量中，将最后一个项目移动到所选项目上，然后再将临时值存储在最后一个位置上。这似乎是*无用*的，因为我们正要*删除*最后一个项目。

好的，交换是没有用的，一次性覆盖是更好的选择。看到这一点，我们可以说这一步也可以用简单的`*it = v.back();`来完成，对吗？是的，这完全是*正确*的，但是想象一下，我们在每个槽中存储了一些非常大的字符串，甚至是另一个向量或映射--在这种情况下，这个小赋值将导致非常昂贵的复制。中间的`std::move`调用只是一个*优化:*在*字符串*的示例情况下，字符串项内部指向*堆*中的一个大字符串。我们不需要复制它。相反，当*移动*一个字符串时，移动的目标指向另一个字符串的数据。移动源项目保持不变，但处于无用状态，这没关系，因为我们无论如何都要删除它。

# 以快速或安全的方式访问 std::vector 实例

`std::vector` 可能是 STL 中使用最广泛的容器，因为它像数组一样保存数据，并在该表示周围添加了很多便利。然而，对向量的错误访问仍然可能是危险的。如果一个向量包含 100 个元素，并且我们的代码意外地尝试访问索引 123 处的元素，这显然是不好的。这样的程序可能会崩溃，这可能是最好的情况，因为这种行为会非常明显地表明存在错误！如果它没有崩溃，我们可能会观察到程序偶尔表现得*奇怪*，这可能会比崩溃的程序带来更多的头痛。有经验的程序员可能会在任何直接索引的向量访问之前添加一些检查。这些检查不会增加代码的可读性，而且很多人不知道`std::vector`已经内置了边界检查！

# 如何做...

在本节中，我们将使用两种不同的方式来访问`std::vector`，然后看看如何利用它们来编写更安全的程序而不降低可读性。

1.  让我们包括所有需要的头文件，并用`123`的值填充一个示例向量`1000`次，这样我们就有了可以访问的东西：

```cpp
      #include <iostream>
      #include <vector>

      using namespace std;

      int main()
      {
          const size_t container_size {1000};
          vector<int> v (container_size, 123);
```

1.  现在，我们使用`[]`运算符越界访问向量：

```cpp
         cout << "Out of range element value: " 
              << v[container_size + 10] << 'n';
```

1.  接下来，我们使用`at`函数越界访问它：

```cpp
          cout << "Out of range element value: " 
               << v.at(container_size + 10) << 'n';
      }
```

1.  让我们运行程序看看会发生什么。错误消息是特定于 GCC 的。其他编译器会发出不同但类似的错误消息。第一次读取以一种奇怪的方式成功了。它没有导致程序崩溃，但它是一个完全不同的*值*，而不是`123`。我们看不到其他访问的输出行，因为它故意崩溃了整个程序。如果那个越界访问是一个意外，我们会更早地捕捉到它！

```cpp
      Out of range element value: -726629391
      terminate called after throwing an instance of 'std::out_of_range'
        what():  array::at: __n (which is 1010) >= _Nm (which is 1000)
      Aborted (core dumped)
```

# 它是如何工作的...

`std::vector`提供了`[]`运算符和`at`函数，它们基本上做的工作是一样的。然而，`at`函数执行额外的边界检查，并且如果超出向量边界，则抛出*异常*。这在我们这种情况下非常有用，但也会使程序变得稍微*慢*一些。

特别是在进行需要非常快速的索引成员的数值计算时，最好坚持使用`[]`索引访问。在任何其他情况下，`at`函数有助于发现通常可以忽略的性能损失的错误。

默认情况下使用`at`函数是一个好习惯。如果生成的代码太慢但已经被证明没有错误，那么在性能敏感的部分可以使用`[]`运算符。

# 还有更多...

当然，我们可以*处理*越界访问，而不是让整个应用程序*崩溃*。为了处理它，我们*捕获*异常，以防它被`at`函数抛出。捕获这样的异常很简单。我们只需用`try`块包围`at`调用，并在`catch`块中定义错误处理。

```cpp
try {
    std::cout << "Out of range element value: " 
              << v.at(container_size + 10) << 'n';
} catch (const std::out_of_range &e) {
     std::cout << "Ooops, out of range access detected: " 
               << e.what() << 'n';
}
```

顺便说一下，`std::array`也提供了`at`函数。

# 保持 std::vector 实例排序

数组和向量本身不会对它们的有效负载对象进行排序。但是如果我们需要这样做，并不意味着我们总是必须切换到自动执行排序的数据结构。如果`std::vector`非常适合我们的用例，那么以*排序方式*向其中添加项目仍然非常简单和实用。

# 如何做到...

在本节中，我们将用随机单词填充一个`std::vector`，对其进行排序，然后在保持向量排序单词顺序不变的同时插入更多单词。

1.  让我们首先包含我们将需要的所有头文件。

```cpp
      #include <iostream>
      #include <vector>
      #include <string>
      #include <algorithm>
      #include <iterator> 
      #include <cassert>
```

1.  我们还声明我们正在使用`std`命名空间，以避免一些`std::`前缀：

```cpp
      using namespace std;
```

1.  然后我们编写一个小的主函数，用一些随机字符串填充一个向量。

```cpp
      int main()
      {
          vector<string> v {"some", "random", "words", 
                            "without", "order", "aaa", 
                            "yyy"};
```

1.  接下来我们要做的是对该向量进行*排序*。在此之前，让我们使用 STL 的`is_sorted`函数和一些断言来检查向量在之前确实*没有*排序，但之后*已经*排序。

```cpp
          assert(false == is_sorted(begin(v), end(v)));
          sort(begin(v), end(v));
          assert(true == is_sorted(begin(v), end(v)));
```

1.  现在，我们最终使用一个新的`insert_sorted`函数将一些随机单词添加到排序后的向量中，之后我们仍然需要实现这个函数。这些单词应该放在正确的位置，以便向量在之后仍然是排序的：

```cpp
          insert_sorted(v, "foobar");
          insert_sorted(v, "zzz");
```

1.  因此，让我们现在在源文件中稍早实现`insert_sorted`。

```cpp
      void insert_sorted(vector<string> &v, const string &word)
      {
          const auto insert_pos (lower_bound(begin(v), end(v), word));
          v.insert(insert_pos, word);
      }
```

1.  现在回到我们停下的主函数中，我们现在可以继续打印向量，并看到插入过程的工作情况：

```cpp
          for (const auto &w : v) { 
              cout << w << " ";
          }
          cout << 'n';
      }
```

1.  编译和运行程序会产生以下很好排序的输出：

```cpp
      aaa foobar order random some without words yyy zzz
```

# 工作原理...

整个程序围绕`insert_sorted`函数构建，该函数执行本节所述的操作：对于任何新字符串，它定位排序向量中的位置，必须将其插入以*保持*向量中字符串的顺序。但是，我们假设向量在之前已经排序。否则，这将无法工作。

定位步骤由 STL 函数`lower_bound`完成，该函数接受三个参数。前两个参数表示底层范围的*开始*和*结束*。在这种情况下，范围是我们的单词向量。第三个参数是要插入的单词。然后函数找到范围中第一个*大于或等于*第三个参数的项目，并返回指向它的迭代器。

有了正确的位置，我们将其提供给`std::vector`成员方法`insert`，该方法只接受两个参数。第一个参数是一个迭代器，指向向量中应插入第二个参数的位置。我们可以使用刚刚从`lower_bound`函数中获得的相同迭代器，这似乎非常方便。第二个参数当然是要插入的项目。

# 还有更多...

`insert_sorted`函数非常通用。如果我们泛化其参数的类型，它也将适用于其他容器有效负载类型，甚至适用于其他容器，例如`std::set`、`std::deque`、`std::list`等等！（请注意，set 有自己的`lower_bound`成员函数，执行与`std::lower_bound`相同的操作，但效率更高，因为它专门为集合进行了优化。）

```cpp
template <typename C, typename T>
void insert_sorted(C &v, const T &item)
{
    const auto insert_pos (lower_bound(begin(v), end(v), item));
    v.insert(insert_pos, item);
}
```

当尝试从`std::vector`切换到其他类型的容器时，请注意并非所有容器都支持`std::sort`。该算法需要随机访问容器，例如`std::list`就不满足这个要求。

# 高效地和有条件地向 std::map 中插入项目

有时我们想要用键值对填充一个映射，并且在填充映射的过程中，可能会遇到两种不同的情况：

1.  关键尚不存在。创建一个*全新*的键值对。

1.  关键已经存在。获取*现有*项目并*修改*它。

我们可以简单地使用`map`的`insert`或`emplace`方法，并查看它们是否成功。如果不成功，我们就会遇到第二种情况，并修改现有的项目。在这两种情况下，insert 和 emplace 都会创建我们尝试插入的项目，而在第二种情况下，新创建的项目会被丢弃。在这两种情况下，我们都会得到一个无用的构造函数调用。

自 C++17 以来，有`try_emplace`函数，它使我们能够仅在插入时有条件地创建项目。让我们实现一个程序，该程序获取亿万富翁名单并构造一个告诉我们每个国家的亿万富翁数量的映射。除此之外，它还存储每个国家最富有的人。我们的示例不包含昂贵的创建项目，但是每当我们在现实项目中遇到这种情况时，我们都知道如何使用`try_emplace`来掌握它。

# 如何做...

在本节中，我们将实现一个应用程序，该应用程序从亿万富翁名单中创建一个映射。该映射将每个国家映射到该国最富有的人的引用以及告诉该国有多少亿万富翁的计数器。

1.  和往常一样，我们首先需要包含一些头文件，并声明我们默认使用`std`命名空间。

```cpp
      #include <iostream>
      #include <functional>
      #include <list>
      #include <map>

      using namespace std;
```

1.  让我们定义一个代表我们名单上亿万富翁物品的结构。

```cpp
      struct billionaire {
          string name;
          double dollars;
          string country;
      };
```

1.  在主函数中，我们首先定义亿万富翁名单。世界上有*很多*亿万富翁，所以让我们构建一个有限的名单，其中只包含一些国家中最富有的人。这个名单已经排序。排名实际上来自《福布斯》2017 年《世界亿万富翁》名单[`www.forbes.com/billionaires/list/:`](https://www.forbes.com/billionaires/list/)

```cpp
      int main()
      {
          list<billionaire> billionaires {
              {"Bill Gates", 86.0, "USA"},
              {"Warren Buffet", 75.6, "USA"},
              {"Jeff Bezos", 72.8, "USA"},
              {"Amancio Ortega", 71.3, "Spain"},
              {"Mark Zuckerberg", 56.0, "USA"},
              {"Carlos Slim", 54.5, "Mexico"},
              // ...
              {"Bernard Arnault", 41.5, "France"},
              // ...
              {"Liliane Bettencourt", 39.5, "France"},
              // ...
              {"Wang Jianlin", 31.3, "China"},
              {"Li Ka-shing", 31.2, "Hong Kong"}
              // ...
          };
```

1.  现在，让我们定义映射。它将国家字符串映射到一对。该对包含我们名单中每个国家的第一个亿万富翁的（`const`）副本。这自动是每个国家最富有的亿万富翁。对中的另一个变量是一个计数器，我们将为该国家的每个后续亿万富翁递增。

```cpp
          map<string, pair<const billionaire, size_t>> m;
```

1.  现在，让我们遍历列表，并尝试为每个国家插入一个新的有效负载对。该对包含我们当前正在查看的亿万富翁的引用和计数器值`1`。

```cpp
          for (const auto &b : billionaires) {
              auto [iterator, success] = m.try_emplace(b.country, b, 1);
```

1.  如果该步骤成功，那么我们就不需要做其他任何事情了。我们提供了构造函数参数`b, 1`的对已经被构造并插入到映射中。如果插入*不*成功，因为国家键已经存在，那么这对就不会被构造。如果我们的亿万富翁结构非常庞大，这将为我们节省复制它的运行时成本。

然而，在不成功的情况下，我们仍然需要递增该国家的计数器。

```cpp
              if (!success) {
                  iterator->second.second += 1;
              }
          }
```

1.  好的，就是这样。我们现在可以打印每个国家有多少亿万富翁，以及每个国家最富有的人是谁。

```cpp
          for (const auto & [key, value] : m) {
              const auto &[b, count] = value;

              cout << b.country << " : " << count 
                   << " billionaires. Richest is "
                   << b.name << " with " << b.dollars 
                   << " B$n";
          }
      }
```

1.  编译和运行程序产生以下输出。（当然，输出是有限的，因为我们限制了输入映射。）

```cpp
      $ ./efficient_insert_or_modify
      China : 1 billionaires. Richest is Wang Jianlin with 31.3 B$
      France : 2 billionaires. Richest is Bernard Arnault with 41.5 B$
      Hong Kong : 1 billionaires. Richest is Li Ka-shing with 31.2 B$
      Mexico : 1 billionaires. Richest is Carlos Slim with 54.5 B$
      Spain : 1 billionaires. Richest is Amancio Ortega with 71.3 B$
      USA : 4 billionaires. Richest is Bill Gates with 86 B$
```

# 它是如何工作的...

整个配方围绕着`std::map`的`try_emplace`函数展开，这是 C++17 的新功能。它具有以下签名：

```cpp
std::pair<iterator, bool> try_emplace(const key_type& k, Args&&... args);
```

因此，被插入的键是参数`k`，关联的值是从参数包`args`构造的。如果我们成功插入该项，那么函数将返回一个*迭代器*，该迭代器指向映射中的新节点，并与设置为`true`的布尔值*配对*。如果插入*不*成功，则返回对中的布尔值设置为`false`，并且迭代器指向新项将与之冲突的项。

这种特征在我们的情况下非常有用--当我们第一次看到来自特定国家的亿万富翁时，那么这个国家在映射中还不是一个键。在这种情况下，我们必须*插入*它，并附带将新计数器设置为`1`。如果我们已经看到来自特定国家的亿万富翁，我们必须获取对其现有计数器的引用，以便对其进行递增。这正是第 6 步发生的事情：

```cpp
if (!success) {
    iterator->second.second += 1;
}
```

请注意，`std::map`的`insert`和`emplace`函数的工作方式完全相同。一个关键的区别是，如果键已经存在，`try_emplace`将*不*构造与键关联的对象。这在类型的对象昂贵创建时提高了性能。

# 还有更多...

如果我们将地图的类型从`std::map`切换到`std::unordered_map`，整个程序仍然可以工作。这样，我们可以从一种实现简单地切换到另一种实现，它们具有不同的性能特征。在这个示例中，唯一可观察到的区别是，亿万富翁地图不再按字母顺序打印，因为哈希映射不像搜索树那样对对象进行排序。

# 了解 std::map::insert 的新插入提示语义。

在`std::map`中查找项目需要*O(log(n))*时间。对于插入新项目也是一样，因为必须查找插入它们的位置。因此，天真地插入*M*个新项目将需要*O(M * log(n))*的时间。

为了使这更有效，`std::map`插入函数接受一个可选的*插入提示*参数。插入提示基本上是一个迭代器，它指向即将插入的项目的未来位置附近。如果提示是正确的，那么我们就会得到*摊销*的*O(1)*插入时间。

# 如何做...

在本节中，我们将向`std::map`中插入多个项目，并为此使用插入提示，以减少查找次数。

1.  我们将字符串映射到数字，因此需要包含`std::map`和`std::string`的头文件。

```cpp
      #include <iostream>
      #include <map>
      #include <string>
```

1.  下一步是实例化一个地图，其中已经包含了一些示例字符。

```cpp
      int main()
      {
          std::map<std::string, size_t> m {{"b", 1}, {"c", 2}, {"d", 3}};
```

1.  现在我们将插入多个项目，并且对于每个项目，我们将使用插入提示。由于一开始我们没有提示可以使用，我们将首先插入指向地图的`end`迭代器。

```cpp
          auto insert_it (std::end(m));
```

1.  现在，我们将按字母表的顺序向地图中插入项目，始终使用我们拥有的迭代器提示，然后将其重新初始化为`insert`函数的返回值。下一个项目将被插入到提示的*前面*。

```cpp
          for (const auto &s : {"z", "y", "x", "w"}) {
              insert_it = m.insert(insert_it, {s, 1});
          }
```

1.  为了展示*不*应该这样做，我们插入一个字符串，它将被放在地图中最左边的位置，但给它一个完全*错误*的提示，它指向地图中最右边的位置——`end`。

```cpp
          m.insert(std::end(m), {"a", 1});
```

1.  最后，我们只是打印我们拥有的东西。

```cpp
          for (const auto & [key, value] : m) {
              std::cout << """ << key << "": " << value << ", ";
          }
          std::cout << 'n';
      }
```

1.  当我们编译和运行程序时，这是我们得到的输出。显然，错误的插入提示并没有造成太大的伤害，因为地图的顺序仍然是正确的。

```cpp
      "a": 1, "b": 1, "c": 2, "d": 3, "w": 1, "x": 1, "y": 1, "z": 1,
```

# 它是如何工作的...

在这个示例中，与普通地图插入的唯一区别是额外的提示迭代器。我们谈到了*正确*和*错误*的提示。

*正确*的提示将指向一个现有元素，该元素*大于*要插入的元素，以便新插入的键将刚好在提示*之前*。如果这不适用于用户在插入时提供的提示，插入函数将退回到非优化的插入，再次产生*O(log(n))*的性能。

对于第一次插入，我们得到了地图的`end`迭代器，因为我们没有更好的提示可以使用。在树中安装了一个“z”之后，我们知道安装“y”将在“z”的前面插入一个新项目，这使它成为一个正确的提示。如果在插入“y”之后将“x”放入树中，也是如此。这就是为什么可以使用由*上次*插入返回的迭代器进行*下次*插入。

重要的是要知道，在 C++11 之前，插入提示被认为是正确的，当它们指向新插入的项目的位置*之前*时。

# 还有更多...

有趣的是，错误的提示甚至不会破坏或干扰地图中项目的顺序，那么这是如何工作的，这意味着什么，插入时间是摊销*O(1)*吗？

`std::map`通常使用二叉搜索树实现。将新键插入搜索树时，将其与其他节点的键进行比较，从顶部开始。如果键比一个节点的键小或大，那么搜索算法将向左或向右分支，以进入下一个更深的节点。在这样做的同时，搜索算法将在达到当前树的最大深度的地方停止，在那里将新节点与其键放置。这一步可能破坏了树的平衡，因此之后也会使用重新平衡算法来纠正这一点，作为一项日常任务。

当我们将具有直接相邻键值的项目插入树中时（就像整数`1`是整数`2`的邻居一样，因为它们之间没有其他整数），它们通常也可以被插入到树中的相邻位置。可以轻松检查某个键和相应提示是否适用这种情况。如果适用，搜索算法步骤可以省略，这可以节省一些关键的运行时间。之后，重新平衡算法可能仍然需要运行。

当这样的优化通常可以完成，但并非总是如此时，这仍然可能导致平均性能提升。可以展示出在多次插入后稳定下来的*结果*运行时复杂度，然后称之为**摊销复杂度**。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/ba7cd62b-4541-4793-9475-24b490c8929b.png)

如果插入提示错误，插入函数将简单地放弃提示，并重新使用搜索算法开始。这样做是正确的，但显然会更慢。

# 高效地修改 std::map 项的键

由于`std::map`数据结构以一种使键始终唯一且排序的方式映射到值，因此用户无法修改已插入的地图节点的键是至关重要的。为了防止用户修改完全排序的地图节点的键项，将`const`限定符添加到键类型中。

这种限制是完全合理的，因为它使用户更难以错误使用`std::map`。但是，如果我们真的需要更改一些映射项的键，我们该怎么办呢？

在 C++17 之前，我们必须从树中删除需要更改键值的项目，然后重新插入它们。这种方法的缺点是这总是不必要地重新分配一些内存，这在性能方面听起来很糟糕。

自 C++17 以来，我们可以删除和重新插入地图节点而不进行任何内存重新分配。我们将在本教程中看到它是如何工作的。

# 如何做...

我们实现了一个小应用程序，它以`std::map`结构对虚构比赛中的驾驶员的位置进行排序。在比赛中，当驾驶员相互超越时，我们需要更改他们的位置键，这是我们以新的 C++17 方式做的。

1.  让我们首先包括必要的头文件，并声明我们使用`std`命名空间。

```cpp
      #include <iostream>
      #include <map>      

      using namespace std;
```

1.  我们将在操纵地图结构之前和之后打印比赛名次，因此让我们为此实现一个小助手函数。

```cpp
      template <typename M>
      void print(const M &m)
      {
          cout << "Race placement:n";
          for (const auto &[placement, driver] : m) {
              cout << placement << ": " << driver << 'n';
          }
      }
```

1.  在主函数中，我们实例化和初始化一个映射，将整数值映射到包含驾驶员姓名的字符串。我们还打印地图，因为我们将在接下来的步骤中对其进行修改。

```cpp
      int main()
      {
          map<int, string> race_placement {
              {1, "Mario"}, {2, "Luigi"}, {3, "Bowser"},
              {4, "Peach"}, {5, "Yoshi"}, {6, "Koopa"},
              {7, "Toad"}, {8, "Donkey Kong Jr."}
          };

          print(race_placement);
```

1.  假设在一圈比赛中，鲍泽发生了一点小事故，掉到了最后一名，唐克·孔·朱尼尔趁机从最后一名跳到第三名。在这种情况下，我们首先需要从地图中提取它们的地图节点，因为这是操纵它们的键的唯一方法。`extract`函数是 C++17 的新功能。它可以从地图中删除项目而不产生任何与分配相关的副作用。让我们为这个任务打开一个新的范围。

```cpp
          {
              auto a (race_placement.extract(3));
              auto b (race_placement.extract(8));
```

1.  现在我们可以交换 Bowser 和 Donkey Kong Jr.的键。虽然地图节点的键通常是不可变的，因为它们被声明为`const`，但我们可以修改使用`extract`方法提取的项目的键。

```cpp
              swap(a.key(), b.key());
```

1.  在 C++17 中，`std::map`的`insert`方法得到了一个新的重载，可以接受提取节点的句柄，以便在不触及分配器的情况下插入它们。

```cpp
              race_placement.insert(move(a));
              race_placement.insert(move(b));
          }
```

1.  离开作用域后，我们完成了。我们打印新的比赛排名，然后让应用程序终止。

```cpp
          print(race_placement);
      }
```

1.  编译和运行程序产生以下输出。我们首先在新的地图实例中看到了比赛排名，然后在交换 Bowser 和 Donkey Kong Jr.的位置后再次看到它。

```cpp
      $ ./mapnode_key_modification 
      Race placement:
      1: Mario
      2: Luigi
      3: Bowser
      4: Peach
      5: Yoshi
      6: Koopa
      7: Toad
      8: Donkey Kong Jr.
      Race placement:
      1: Mario
      2: Luigi
      3: Donkey Kong Jr.
      4: Peach
      5: Yoshi
      6: Koopa
      7: Toad
      8: Bowser
```

# 工作原理...

在 C++17 中，`std::map`获得了一个新的成员函数 extract。它有两种形式：

```cpp
node_type extract(const_iterator position);
node_type extract(const key_type& x);
```

在本示例中，我们使用了第二种方法，它接受一个键，然后查找并提取与键参数匹配的地图节点。第一个方法接受一个迭代器，这意味着它*更快*，因为它不需要搜索项目。

如果我们尝试使用第二种方法（使用键进行搜索）提取不存在的项目，则会返回一个*空*的`node_type`实例。`empty()`成员方法返回一个布尔值，告诉我们`node_type`实例是否为空。访问空实例上的任何其他方法会导致未定义的行为。

在提取节点之后，我们能够使用`key()`方法修改它们的键，这为我们提供了对键的非 const 访问，尽管键通常是 const 的。

请注意，为了重新将节点插入地图中，我们必须将它们*移动*到`insert`函数中。这是有道理的，因为`extract`的目的是避免不必要的复制和分配。请注意，虽然我们移动了一个`node_type`实例，但这并不会导致任何容器值的实际移动。

# 还有更多...

使用提取方法提取的地图节点实际上非常灵活。我们可以从`map`实例中提取节点并将其插入到任何其他`map`甚至`multimap`实例中。它也可以在`unordered_map`和`unordered_multimap`实例之间，以及`set`/`multiset`和相应的`unordered_set`/`unordered_multiset`之间工作。

为了在不同的地图/集合结构之间移动项目，键、值和分配器的类型需要相同。请注意，即使是这种情况，我们也不能从`map`移动节点到`unordered_map`，或者从`set`移动节点到`unordered_set`。

# 使用自定义类型的 std::unordered_map

如果我们使用`std::unordered_map`而不是`std::map`，我们可以对要使用的键类型进行不同程度的自由选择。`std::map`要求所有键项之间存在自然顺序。这样，项目可以排序。但是，如果我们想要，例如，将数学向量作为键类型呢？对于这种类型，没有*较小*`<`关系是没有*意义*的，因为向量`(0, 1)`不比`(1, 0)`*小*或*大*。它们只是指向不同的方向。这对于`std::unordered_map`来说完全没问题，因为它不会通过它们的较小/较大的顺序关系来区分项目，而是通过*哈希值*。我们唯一需要做的就是为我们自己的类型实现一个*哈希函数*，以及一个*相等*的`==`运算符实现，告诉我们两个对象是否相同。本节将通过一个示例来演示这一点。

# 如何做...

在本节中，我们将定义一个简单的`coord`结构，它没有*默认*哈希函数，因此我们需要自己定义它。然后我们通过将`coord`值映射到数字来使用它。

1.  我们首先包含了打印和使用`std::unordered_map`所需的内容。

```cpp
      #include <iostream>
      #include <unordered_map>
```

1.  然后我们定义了我们自己的自定义结构，它不是通过*现有*哈希函数轻松哈希的：

```cpp
      struct coord {
          int x;
          int y;
      };
```

1.  我们不仅需要一个哈希函数才能将结构用作哈希映射的键，它还需要一个比较运算符的实现：

```cpp
      bool operator==(const coord &l, const coord &r)
      {
          return l.x == r.x && l.y == r.y;
      }
```

1.  为了扩展 STL 自己的哈希能力，我们将打开`std`命名空间，并创建我们自己的`std::hash`模板结构专门化。它包含与其他哈希专门化相同的`using`类型别名子句。

```cpp
      namespace std
      {

      template <>
      struct hash<coord>
      {
          using argument_type = coord;
          using result_type   = size_t;
```

1.  这个`struct`的核心是`operator()`的定义。我们只是添加了`struct coord`的数值成员值，这是一种较差的哈希技术，但为了展示如何实现它，这已经足够了。一个好的哈希函数试图尽可能均匀地分布值在整个值范围内，以减少*哈希冲突*的数量。

```cpp
          result_type operator()(const argument_type &c) const
          {
              return static_cast<result_type>(c.x) 
                   + static_cast<result_type>(c.y);
          }
      };

      }
```

1.  现在我们可以实例化一个新的`std::unordered_map`实例，它接受`struct coord`实例作为键，并将其映射到任意值。由于这个方法是关于使我们自己的类型适用于`std::unordered_map`，这已经足够了。让我们用我们自己的类型实例化一个基于哈希的映射，填充它一些项目，并打印它的：

```cpp
      int main()
      {

          std::unordered_map<coord, int> m {{{0, 0}, 1}, {{0, 1}, 2}, 
                                            {{2, 1}, 3}};

          for (const auto & [key, value] : m) {
              std::cout << "{(" << key.x << ", " << key.y 
                        << "): " << value << "} ";
          }
          std::cout << 'n';
      }
```

1.  编译和运行程序产生了以下输出：

```cpp
      $ ./custom_type_unordered_map
      {(2, 1): 3} {(0, 1): 2} {(0, 0): 1}
```

# 它是如何工作的...

通常，当我们实例化一个基于哈希的映射实现，比如`std::unordered_map`时，我们会写：

```cpp
std::unordered_map<key_type, value_type> my_unordered_map;
```

当编译器创建我们的`std::unordered_map`专门化时，背后发生了很多魔法，这并不太明显。因此，让我们来看一下它的完整模板类型定义：

```cpp
template<
    class Key,
    class T,
    class Hash      = std::hash<Key>,
    class KeyEqual  = std::equal_to<Key>,
    class Allocator = std::allocator< std::pair<const Key, T> >
> class unordered_map;
```

前两个模板类型是我们用`coord`和`int`填充的，这是简单和明显的部分。另外三个模板类型是可选的，因为它们会自动填充现有的标准模板类，这些类本身采用模板类型。这些类以我们对前两个参数的选择作为默认值。

关于这个方法，`class Hash`模板参数是有趣的：当我们没有明确定义其他任何东西时，它将专门化为`std::hash<key_type>`。STL 已经包含了许多类型的`std::hash`专门化，比如`std::hash<std::string>`，`std::hash<int>`，`std::hash<unique_ptr>`等等。这些类知道如何处理这些特定类型，以计算出最佳的哈希值。

然而，STL 并不知道如何从我们的`struct coord`计算哈希值。因此，我们所做的是定义*另一个*专门化，它知道如何处理它。编译器现在可以遍历它所知道的所有`std::hash`专门化列表，并找到我们的实现来匹配我们提供的键类型。

如果我们没有添加一个新的`std::hash<coord>`专门化，并将其命名为`my_hash_type`，我们仍然可以使用以下实例化行：

```cpp
std::unordered_map<coord, value_type, my_hash_type> my_unordered_map;
```

这显然需要输入更多的内容，而且不像编译器自己找到正确的哈希实现那样容易阅读。

# 从用户输入中过滤重复项并按字母顺序打印它们与 std::set

`std::set`是一个奇怪的容器：它的工作方式有点像`std::map`，但它只包含键作为值，没有键值对。因此，它几乎不能用作将一种类型的值映射到另一种类型的值。看起来，只是因为它的用例不太明显，很多开发人员甚至不知道它的存在。然后他们开始自己实现东西，尽管`std::set`在其中的一些情况下会非常有帮助。

这一部分展示了如何在一个示例中使用`std::set`，在这个示例中，我们收集了许多不同的项目，以*过滤*它们并输出*唯一*的选择。

# 如何做...

在这一部分，我们将从标准输入中读取一系列单词。所有*唯一*的单词都被放入一个`std::set`实例中。这样我们就可以列举出流中的所有唯一单词。

1.  我们将使用多种不同的 STL 类型，因此需要包含多个头文件。

```cpp
      #include <iostream>
      #include <set>
      #include <string>
      #include <iterator>
```

1.  为了节省一些输入，我们将声明我们正在使用`std`命名空间：

```cpp
      using namespace std;
```

1.  现在我们已经开始编写实际的程序，它以`main`函数实例化一个存储字符串的`std::set`开始。

```cpp
      int main()
      {
          set<string> s;
```

1.  接下来要做的事情是获取用户输入。我们只需从标准输入读取，并使用方便的`istream_iterator`。

```cpp
          istream_iterator<string> it {cin};
          istream_iterator<string> end;
```

1.  拥有一对`begin`和`end`迭代器，代表用户输入，我们可以使用`std::inserter`从中填充集合。

```cpp
          copy(it, end, inserter(s, s.end()));
```

1.  就是这样。为了看到我们从标准输入得到的*独特*单词，我们只需打印我们集合的内容。

```cpp
          for (const auto word : s) {
              cout << word << ", ";
          }
          cout << 'n';
      }
```

1.  让我们用以下输入编译和运行我们的程序。对于前面的输入，我们得到以下输出，其中所有重复项都被剔除，而独特的单词按字母顺序排序。

```cpp
      $ echo "a a a b c foo bar foobar foo bar bar" | ./program
      a, b, bar, c, foo, foobar,
```

# 它是如何工作的...

这个程序由两个有趣的部分组成。第一部分是使用`std::istream_iterator`来访问用户输入，第二部分是将其与我们的`std::set`实例结合起来，使用`std::copy`算法，然后将其包装成`std::inserter`实例！也许令人惊讶的是，只有一行代码就可以完成*标记化*输入、将其放入按字母顺序*排序*的集合中，并*删除*所有重复项的所有工作。

# std::istream_iterator

这个类在我们想要从流中处理大量*相同*类型的数据时非常有趣，这正是这个示例的情况：我们逐个单词解析整个输入，并将其以`std::string`实例的形式放入集合中。

`std::istream_iterator`接受一个模板参数。那就是我们想要的输入类型。我们选择了`std::string`，因为我们假设是文本单词，但也可以是`float`数字，例如。基本上可以是任何可以写成`cin >> var;`的类型。构造函数接受一个`istream`实例。标准输入由全局输入流对象`std::cin`表示，在这种情况下是一个可接受的`istream`参数。

```cpp
istream_iterator<string> it {cin};
```

我们实例化的输入流迭代器`it`能够做两件事：当它被解引用(`*it`)时，它会产生当前的输入符号。由于我们通过模板参数将迭代器类型化为`std::string`，所以该符号将是一个包含一个单词的字符串。当它被增加(`++it`)时，它将跳到下一个单词，我们可以通过再次解引用来访问它。

但是等等，在我们再次解引用之前，我们需要在每次增量之后小心。如果标准输入为空，迭代器就不应该再次被解引用。相反，我们应该终止我们解引用迭代器以获取每个单词的循环。让我们知道迭代器变得无效的中止条件是与`end`迭代器的比较。如果`it == end`成立，我们就超出了输入的末尾。

我们通过使用其无参数标准构造函数创建`std::istream_iterator`实例来创建结束迭代器。它的目的是作为每次迭代中的中止条件的对应物：

```cpp
istream_iterator<string> end;
```

一旦`std::cin`为空，我们的`it`迭代器实例将*注意到*并与`end`进行比较，返回`true`。

# std::inserter

我们在`std::copy`调用中使用`it`和`end`对作为*输入*迭代器。第三个参数必须是一个*输出*迭代器。对于这一点，我们不能只取`s.begin()`或`s.end()`。在一个空集合中，两者是相同的，所以我们甚至不能*解引用*它，无论是用于从中读取还是分配给它。

这就是`std::inserter`发挥作用的地方。它是一个返回`std::insert_iterator`的函数，它的行为类似于迭代器，但做的事情与通常的迭代器不同。当我们增加它时，它什么也不做。当我们解引用它并将某物赋给它时，它将取得它所附属的容器，并将该值作为*新*项插入其中！

通过`std::inserter`实例化`std::insert_iterator`需要两个参数：

```cpp
auto insert_it = inserter(s, s.end());
```

`s`是我们的集合，`s.end()`是一个迭代器，指向新项应该插入的位置。对于我们开始的空集合，这和`s.begin()`一样有意义。当用于其他数据结构如向量或列表时，第二个参数对于定义插入迭代器应该插入新项的位置至关重要。

# 将它放在一起

最后，*所有*的操作都发生在`std::copy`调用期间：

```cpp
copy(input_iterator_begin, input_iterator_end, insert_iterator);
```

这个调用从`std::cin`中通过输入迭代器取出下一个单词标记，并将其推入我们的`std::set`中。然后，它递增两个迭代器，并检查输入迭代器是否等于输入结束迭代器的对应项。如果不相等，那么标准输入中仍然有单词，所以它将*重复*。

重复的单词会自动被丢弃。如果集合已经包含特定单词，再次添加它将*没有效果*。这在`std::multiset`中是不同的，因为它会接受重复项。

# 使用 std::stack 实现一个简单的逆波兰表示法计算器

`std::stack`是一个适配器类，它允许用户像在真正的对象堆栈上一样将对象推入它，然后再从中弹出对象。在这一部分，我们围绕这个数据结构构建了一个逆波兰表示法（RPN）计算器，以展示如何使用它。

逆波兰表示法是一种可以用来以非常简单的方式解析数学表达式的表示法。在逆波兰表示法中，`1 + 2`表示为`1 2 +`。首先是操作数，然后是操作符。另一个例子：`(1 + 2) * 3`在逆波兰表示法中是`1 2 + 3 *`，这已经显示了为什么它更容易解析，因为我们不需要使用括号来定义子表达式。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/c5365787-5e7f-4fab-afe2-ad3ae977ddb5.jpg)

# 如何做...

在这一部分，我们将从标准输入中读取一个逆波兰表示法的数学表达式，然后将其传递给一个评估函数。最后，我们将数值结果打印回给用户。

1.  我们将使用 STL 中的许多辅助函数，所以有一些包含：

```cpp
      #include <iostream>
      #include <stack>
      #include <iterator>
      #include <map>
      #include <sstream>
      #include <cassert>
      #include <vector>
      #include <stdexcept>
      #include <cmath>
```

1.  我们还声明我们使用`std`命名空间，以节省一些输入。

```cpp
      using namespace std;
```

1.  然后，我们立即开始实现我们的逆波兰表示法解析器。它将接受一个迭代器对，表示以字符串形式的数学表达式的开始和结束，这将逐个标记消耗掉。

```cpp
      template <typename IT>
      double evaluate_rpn(IT it, IT end)
      {
```

1.  当我们遍历标记时，我们需要记住一路上的所有*操作数*，直到看到一个*操作符*。这就是我们需要一个堆栈的地方。所有的数字都将被解析并保存为双精度浮点数，所以它将是一个`double`值的堆栈。

```cpp
          stack<double> val_stack;
```

1.  为了方便地访问堆栈上的元素，我们实现了一个辅助函数。它通过从堆栈中取出最高项来修改堆栈，然后返回该项。这样我们可以在以后的一个步骤中执行这个任务。

```cpp
          auto pop_stack ([&](){ 
              auto r (val_stack.top()); 
              val_stack.pop(); 
              return r; 
          });
```

1.  另一个准备工作是定义所有支持的数学运算。我们将它们保存在一个映射中，将每个操作标记与实际操作关联起来。这些操作由可调用的 lambda 表示，它们接受两个操作数，例如相加或相乘，然后返回结果。

```cpp
          map<string, double (*)(double, double)> ops {
              {"+", [](double a, double b) { return a + b; }},
              {"-", [](double a, double b) { return a - b; }},
              {"*", [](double a, double b) { return a * b; }},
              {"/", [](double a, double b) { return a / b; }},
              {"^", [](double a, double b) { return pow(a, b); }},
              {"%", [](double a, double b) { return fmod(a, b); }},
          };
```

1.  现在我们终于可以遍历输入了。假设输入迭代器给我们的是字符串，我们为每个标记提供一个新的`std::stringstream`，因为它可以解析数字。

```cpp
          for (; it != end; ++it) {
              stringstream ss {*it};
```

1.  现在对于每个标记，我们尝试从中获取一个`double`值。如果成功，我们就有了*操作数*，我们将其推入堆栈。

```cpp
              if (double val; ss >> val) {
                  val_stack.push(val);
              }
```

1.  如果它*不*成功，那么它必须是其他东西而不是操作符；在这种情况下，它只能是*操作数*。知道我们支持的所有操作都是*二元*的，我们需要从堆栈中弹出最后的*两个*操作数。

```cpp
              else {
                  const auto r {pop_stack()};
                  const auto l {pop_stack()};
```

1.  现在我们从解引用迭代器`it`中获取操作数，它已经发出了字符串。通过查询`ops`映射，我们得到一个接受两个操作数`l`和`r`作为参数的 lambda 对象。

```cpp
                  try {
                      const auto & op     (ops.at(*it));
                      const double result {op(l, r)};
                      val_stack.push(result);
                  }
```

1.  我们用`try`子句包围了数学部分的应用，这样我们就可以捕获可能发生的异常。映射的`at`调用将在用户提供我们不知道的数学操作时抛出`out_of_range`异常。在这种情况下，我们将重新抛出一个不同的异常，该异常说`invalid argument`并携带了我们不知道的操作字符串。

```cpp
                  catch (const out_of_range &) {
                      throw invalid_argument(*it);
                  }
```

1.  这就是全部。一旦循环终止，我们就在堆栈上得到了最终结果。所以我们就返回那个。 （在这一点上，我们可以断言堆栈大小是否为 1。如果不是，那么就会缺少操作。）

```cpp
              }
          }

          return val_stack.top();
      }
```

1.  现在我们可以使用我们的小 RPN 解析器。为了做到这一点，我们将标准输入包装成一个`std::istream_iterator`对，并将其传递给 RPN 解析器函数。最后，我们打印结果：

```cpp
      int main()
      {
          try {
              cout << evaluate_rpn(istream_iterator<string>{cin}, {}) 
                   << 'n';
          }
```

1.  我们再次将该行包装到`try`子句中，因为仍然有可能用户输入包含我们没有实现的操作。在这种情况下，我们必须捕获我们在这种情况下抛出的异常，并打印错误消息：

```cpp
          catch (const invalid_argument &e) {
              cout << "Invalid operator: " << e.what() << 'n';
          }
      }
```

1.  编译程序后，我们可以尝试一下。输入`"3 1 2 + * 2 /"`代表表达式`( 3 * (1 + 2) ) / 2`，并产生了正确的结果：

```cpp
      $ echo "3 1 2 + * 2 /" | ./rpn_calculator
      4.5
```

# 它是如何工作的...

整个算法围绕着将操作数推送到堆栈上直到我们在输入中看到一个操作。在这种情况下，我们再次从堆栈中弹出最后两个操作数，对它们应用操作，然后再次将结果推送到堆栈上。为了理解这个算法中的所有代码，重要的是要理解我们如何从输入中区分*操作数*和*操作*，如何处理我们的堆栈，以及如何选择和应用正确的数学操作。

# 堆栈处理

我们将项目推送到堆栈上，只需使用`std::stack`的`push`函数：

```cpp
val_stack.push(val);
```

从中弹出值看起来有点复杂，因为我们为此实现了一个 lambda，它捕获了对`val_stack`对象的引用。让我们看看相同的代码，增加一些注释：

```cpp
auto pop_stack ([&](){
    auto r (val_stack.top()); // Get top value copy
    val_stack.pop();          // Throw away top value
    return r;                 // Return copy
});
```

这个 lambda 是必要的，以便一步获取堆栈的顶部值并从中*删除*它。`std::stack`的接口设计并不允许在*单个*调用中执行此操作。但是，定义一个 lambda 很快很容易，所以我们现在可以这样获取值：

```cpp
double top_value {pop_stack()};
```

# 从用户输入中区分操作数和操作

在`evaluate_rpn`的主循环中，我们从迭代器中获取当前的字符串标记，然后查看它是否是操作数。如果字符串可以解析为`double`变量，那么它就是一个数字，因此也是一个操作数。我们认为所有不能轻松解析为数字的东西（例如`"+"`）都是*操作*。

用于这个任务的裸代码框架如下：

```cpp
stringstream ss {*it};
if (double val; ss >> val) {
    // It's a number!
} else {
    // It's something else than a number - an operation!
}
```

流操作符`>>`告诉我们它是否是一个数字。首先，我们将字符串包装到`std::stringstream`中。然后我们使用`stringstream`对象的能力从`std::string`流到`double`变量，这涉及解析。如果解析*失败*，我们知道它是因为我们要求它将某些东西解析为一个数字，而这不是一个数字。

# 选择和应用正确的数学操作

在我们意识到当前用户输入标记不是一个数字之后，我们只是假设它是一个操作，比如`+`或`*`。然后我们查询我们称为`ops`的映射，查找该操作并返回一个函数，该函数接受两个操作数，并返回总和，或乘积，或适当的其他内容。

映射本身的类型看起来相对复杂：

```cpp
map<string, double (*)(double, double)> ops { ... };
```

它从`string`映射到`double (*)(double, double)`。后者是什么意思？这种类型描述应该读作“*指向一个接受两个 double 并返回一个 double 的函数的指针*”。想象一下，`(*)`部分就是函数的名称，比如`double sum(double, double)`，这样就更容易阅读。这里的技巧是，我们的 lambda `[](double, double) { return /* some double */ }` 可以转换为实际匹配该指针描述的函数指针。通常不捕获任何内容的 lambda 都可以转换为函数指针。

这样，我们可以方便地向映射询问正确的操作：

```cpp
const auto & op     (ops.at(*it));
const double result {op(l, r)};
```

映射隐式地为我们做了另一项工作：如果我们说`ops.at("foo")`，那么`"foo"`是一个有效的键值，但我们没有存储任何名为这样的操作。在这种情况下，映射将抛出一个异常，我们在配方中捕获它。每当我们捕获它时，我们重新抛出一个不同的异常，以便提供对这种错误情况的描述性含义。用户将更清楚地知道`无效参数`异常意味着什么，而不是`超出范围`异常。请注意，`evaluate_rpn`函数的用户可能没有阅读其实现，因此可能不知道我们根本在内部使用映射。

# 还有更多...

由于`evaluate_rpn`函数接受迭代器，因此很容易用不同于标准输入流的输入来提供输入。这使得测试或适应不同的用户输入来源非常容易。

例如，通过从字符串流或字符串向量中使用迭代器进行输入，看起来像以下代码，`evaluate_rpn`根本不需要更改：

```cpp
int main()
{
    stringstream s {"3 2 1 + * 2 /"};
    cout << evaluate_rpn(istream_iterator<string>{s}, {}) << 'n';

    vector<string> v {"3", "2", "1", "+", "*", "2", "/"};
    cout << evaluate_rpn(begin(v), end(v)) << 'n';
}
```

在合适的地方使用迭代器。这样可以使您的代码非常可组合和可重用。

# 使用`std::map`实现单词频率计数器

`std::map`在对数据进行统计时非常有用。通过将可修改的有效负载对象附加到表示对象类别的每个键上，可以很容易地实现例如单词频率的直方图。这就是我们将在本节中做的事情。

# 如何做到...

在这一部分，我们将从标准输入中读取所有用户输入，例如可能是包含文章的文本文件。我们将输入标记化为单词，以便统计每个单词出现的次数。

1.  和往常一样，我们需要包括我们将要使用的数据结构的所有头文件。

```cpp
      #include <iostream>
      #include <map> 
      #include <vector> 
      #include <algorithm> 
      #include <iomanip>
```

1.  为了节省一些输入，我们声明使用`std`命名空间。

```cpp
      using namespace std;
```

1.  我们将使用一个辅助函数来裁剪可能附加的逗号、句号或冒号。

```cpp
      string filter_punctuation(const string &s)
      {
          const char *forbidden {".,:; "};
          const auto  idx_start (s.find_first_not_of(forbidden));
          const auto  idx_end   (s.find_last_not_of(forbidden));

          return s.substr(idx_start, idx_end - idx_start + 1);
      }
```

1.  现在我们开始实际的程序。我们将收集一个映射，将我们看到的每个单词与该单词频率的计数器关联起来。此外，我们还维护一个记录迄今为止我们见过的最长单词的大小的变量，这样当我们在程序结束时打印单词频率表时，我们可以很好地缩进它。

```cpp
      int main()
      {
          map<string, size_t> words;
          int max_word_len {0};
```

1.  当我们从`std::cin`流入一个`std::string`变量时，输入流会在途中去除空格。这样我们就可以逐个单词获取输入。

```cpp
          string s;
          while (cin >> s) {
```

1.  现在我们所拥有的单词，可能包含逗号、句号或冒号，因为它可能出现在句子的结尾或类似位置。我们使用之前定义的辅助函数来过滤掉这些。

```cpp
              auto filtered (filter_punctuation(s));
```

1.  如果这个单词是迄今为止最长的单词，我们需要更新`max_word_len`变量。

```cpp
              max_word_len = max<int>(max_word_len, filtered.length());
```

1.  现在我们将增加`words`映射中该单词的计数值。如果它是第一次出现，我们会在增加之前隐式地创建它。

```cpp
              ++words[filtered];
          }
```

1.  循环结束后，我们知道我们已经在`words`映射中保存了输入流中的所有唯一单词，并与表示每个单词频率的计数器配对。映射使用单词作为键，并按它们的*字母*顺序排序。我们想要的是按*频率*排序打印所有单词，因此频率最高的单词应该首先出现。为了实现这一点，我们首先实例化一个向量，将所有这些单词频率对放入其中，并将它们从映射移动到向量中。

```cpp
          vector<pair<string, size_t>> word_counts;
          word_counts.reserve(words.size());
          move(begin(words), end(words), back_inserter(word_counts));
```

1.  现在向量仍然以与`words`映射维护它们相同的顺序包含所有单词频率对。现在我们再次对其进行排序，以便将最频繁出现的单词放在开头，将最不频繁的单词放在末尾。

```cpp
          sort(begin(word_counts), end(word_counts),
              [](const auto &a, const auto &b) { 
                  return a.second > b.second; 
              });
```

1.  现在所有数据都已经排序好了，所以我们将其推送到用户终端。使用`std::setw`流操作符，我们以漂亮的缩进格式格式化数据，使其看起来有点像表格。

```cpp
          cout << "# " << setw(max_word_len) << "<WORD>" << " #<COUNT>n";
          for (const auto & [word, count] : word_counts) {
              cout << setw(max_word_len + 2) << word << " #" 
                   << count << 'n';
          }
      }
```

1.  编译程序后，我们可以将任何文本文件输入到其中以获得频率表。

```cpp
      $ cat lorem_ipsum.txt | ./word_frequency_counter
      #       <WORD> #<COUNT>
                  et #574
               dolor #302
                 sed #273
                diam #273
                 sit #259
               ipsum #259
      ...
```

# 它是如何工作的...

这个方法集中在收集所有单词到`std::map`中，然后将所有项目从映射中推出并放入`std::vector`中，然后以不同的方式进行排序，以便打印数据。为什么？

让我们来看一个例子。当我们统计字符串`"a a b c b b b d c c"`中的单词频率时，我们会得到以下的映射内容：

```cpp
a -> 2
b -> 4
c -> 3
d -> 1
```

然而，这不是我们想要向用户展示的顺序。程序应该首先打印`b`，因为它的频率最高。然后是`c`，然后是`a`，最后是`d`。不幸的是，我们无法要求映射给我们“*具有最高关联值的键*”，然后是“*具有第二高关联值的键*”，依此类推。

在这里，向量就派上用场了。我们将向量定义为包含字符串和计数器值对的对。这样它可以以与映射中的形式完全相同的形式保存项目。

```cpp
vector<pair<string, size_t>> word_counts;
```

然后我们使用`std::move`算法填充向量，使用单词频率对。这样做的好处是，保存在堆上的字符串部分不会被复制，而是从映射移动到向量中。这样我们就可以避免大量的复制。

```cpp
move(begin(words), end(words), back_inserter(word_counts));
```

一些 STL 实现使用了短字符串优化--如果字符串不太长，它将*不会*被分配到堆上，而是直接存储在字符串对象中。在这种情况下，移动并不更快。但移动也永远不会更慢！

下一个有趣的步骤是排序操作，它使用 lambda 作为自定义比较运算符：

```cpp
sort(begin(word_counts), end(word_counts),
        [](const auto &a, const auto &b) { return a.second > b.second; });
```

排序算法将成对地取出项目，并进行比较，这就是排序算法的工作原理。通过提供 lambda 函数，比较不仅仅是比较`a`是否小于`b`（这是默认实现），还比较`a.second`是否大于`b.second`。请注意，所有对象都是*字符串*和它们的计数器值的对，通过写`a.second`我们可以访问单词的计数器值。这样我们就将所有高频单词移动到向量的开头，将低频单词移动到向量的末尾。

# 实现一个写作风格辅助工具，用于在文本中查找非常长的句子，使用 std::multimap

每当需要以排序方式存储大量项目，并且它们按照键进行排序的时候，`std::multimap`是一个不错的选择。

让我们找一个例子使用情况：在德语写作中，使用非常长的句子是可以的。但在英语写作中，是*不可以*的。我们将实现一个工具，帮助德语作者分析他们的英语文本文件，重点关注所有句子的长度。为了帮助作者改进文本风格，它将根据句子的长度对句子进行分组。这样作者就可以选择最长的句子并将其拆分。

# 如何做...

在本节中，我们将从标准输入中读取所有用户输入，我们将通过整个句子而不是单词对其进行标记化。然后我们将所有句子收集到一个`std::multimap`中，并与其长度一起输出给用户。然后，我们将所有句子按其长度排序后返回给用户。

1.  像往常一样，我们需要包括所有需要的头文件。`std::multimap`来自与`std::map`相同的头文件。

```cpp
      #include <iostream>
      #include <iterator>
      #include <map>
      #include <algorithm>
```

1.  我们使用了很多来自`std`命名空间的函数，因此我们自动声明其使用。

```cpp
      using namespace std;
```

1.  当我们通过提取文本中句号之间的内容来对字符串进行标记化时，我们将得到由空格（如空格、换行符等）包围的文本句子。这些会以错误的方式增加它们的大小，因此我们使用一个辅助函数来过滤它们，现在我们定义它。

```cpp
      string filter_ws(const string &s)
      {
          const char *ws {" rnt"};
          const auto a (s.find_first_not_of(ws));
          const auto b (s.find_last_not_of(ws));
          if (a == string::npos) {
              return {};
          }
          return s.substr(a, b);
      }
```

1.  实际的句子长度计数函数应该接受一个包含所有文本的巨大字符串，然后返回一个`std::multimap`，将排序后的句子长度映射到句子。

```cpp
      multimap<size_t, string> get_sentence_stats(const string &content)
      {
```

1.  我们首先声明`multimap`结构，这是预期的返回值，以及一些迭代器。由于我们将有一个循环，我们需要一个`end`迭代器。然后我们使用两个迭代器来指向文本中连续的句号。两者之间的所有内容都是一个文本句子。

```cpp
          multimap<size_t, string> ret;

          const auto end_it (end(content));
          auto it1 (begin(content));
          auto it2 (find(it1, end_it, '.'));
```

1.  `it2`始终比`it1`多一个句号。只要`it1`没有到达文本的末尾，我们就没问题。第二个条件检查`it2`是否真的至少有一些字符。如果不是这样，它们之间就没有字符可读了。

```cpp
          while (it1 != end_it && distance(it1, it2) > 0) {
```

1.  我们从迭代器之间的所有字符创建一个字符串，并过滤掉其开头和结尾的所有空格，以便计算纯句子的长度。

```cpp
              string s {filter_ws({it1, it2})};
```

1.  可能句子中除了空格以外什么都没有。在这种情况下，我们只是丢弃它。否则，我们通过确定有多少个单词来计算其长度。这很容易，因为所有单词之间都有单个空格。然后我们将单词计数与句子一起保存在`multimap`中。

```cpp
              if (s.length() > 0) {
                  const auto words (count(begin(s), end(s), ' ') + 1);
                  ret.emplace(make_pair(words, move(s)));
              }
```

1.  对于下一个循环迭代，我们将主迭代器`it1`放在下一个句子的句号字符上。接下来的迭代器`it2`放在主迭代器的*旧*位置之后一个字符。

```cpp
              it1 = next(it2, 1);
              it2 = find(it1, end_it, '.');
          }
```

1.  循环结束后，`multimap`包含所有句子及其单词计数，并且可以返回。

```cpp
          return ret;
      }
```

1.  现在我们开始使用该函数。首先，我们告诉`std::cin`不要跳过空格，因为我们希望句子中的空格保持完整。为了读取整个文件，我们从输入流迭代器初始化一个`std::string`，它封装了`std::cin`。

```cpp
      int main()
      {
          cin.unsetf(ios::skipws);
          string content {istream_iterator<char>{cin}, {}};
```

1.  由于我们只需要`multimap`的结果进行打印，我们直接在循环中调用`get_sentence_stats`并将其与我们的字符串一起使用。在循环体中，我们逐行打印项目。

```cpp
          for (const auto & [word_count, sentence] 
                   : get_sentence_stats(content)) {
              cout << word_count << " words: " << sentence << ".n";
          }
      }
```

1.  编译代码后，我们可以从任何文本文件中输入文本到应用程序中。例如 Lorem Ipsum 文本产生以下输出。由于长文本有很多句子，输出非常长，因此它首先打印最短的句子，最后打印最长的句子。这样我们就可以先看到最长的句子，因为终端通常会自动滚动到输出的末尾。

```cpp
      $ cat lorem_ipsum.txt | ./sentence_length
      ...
      10 words: Nam quam nunc, blandit vel, luctus pulvinar, 
      hendrerit id, lorem.
      10 words: Sed consequat, leo eget bibendum sodales, 
      augue velit cursus nunc,.
      12 words: Cum sociis natoque penatibus et magnis dis 
      parturient montes, nascetur ridiculus mus.
      17 words: Maecenas tempus, tellus eget condimentum rhoncus, 
      sem quam semper libero, sit amet adipiscing sem neque sed ipsum.
```

# 它是如何工作的...

整个过程集中在将一个大字符串分解为文本句子，对其长度进行评估，然后在`multimap`中排序。因为`std::multimap`本身非常容易使用，程序的复杂部分是循环，它遍历句子：

```cpp
const auto end_it (end(content));
auto it1 (begin(content));         // (1) Beginning of string
auto it2 (find(it1, end_it, '.')); // (1) First '.' dot

while (it1 != end_it && std::distance(it1, it2) > 0) {
    string sentence {it1, it2};

    // Do something with the sentence string...

    it1 = std::next(it2, 1);      // One character past current '.' dot
    it2 = find(it1, end_it, '.'); // Next dot, or end of string
}
```

让我们在看下面的代码时，考虑以下图表，其中包含三个句子：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/18c1c74b-9f55-4b94-b150-f5f08f678583.png)

`it1`和`it2`始终一起向前移动。这样它们总是指向*一个*句子的开头和结尾。`std::find`算法在这方面帮助了我们很多，因为它的工作方式是“*从当前位置开始，然后返回到下一个句号字符的迭代器。如果没有，返回结束迭代器*。”

在提取句子字符串后，我们确定它包含多少个单词，以便将其插入`multimap`中。我们使用*单词数*作为映射节点的*键*，并将字符串本身作为与之关联的有效负载对象。很容易有多个长度相同的句子。这将使我们无法将它们全部插入一个`std::map`中。但由于我们使用`std::multimap`，这不是问题，因为它可以轻松处理相同值的多个键。它将保持它们全部*有序*，这正是我们需要通过它们的长度枚举所有句子并将它们输出给用户。

# 还有更多...

在将整个文件读入一个大字符串后，我们遍历字符串并再次创建每个句子的副本。这是不必要的，因为我们也可以使用`std::string_view`，这将在本书的后面介绍。

另一种迭代获取两个连续点之间的字符串的方法是`std::regex_iterator`，这也将在本书的后面章节中介绍。

# 使用 std::priority_queue 实现个人待办事项列表

`std::priority_queue`是另一个容器适配器类，例如`std::stack`。它是另一个数据结构（默认情况下为`std::vector`）的包装器，并为其提供了类似队列的接口。这意味着可以逐步将项目推入其中，然后逐步将其弹出。被推入其中的东西*先*被弹出。这通常也被缩写为**先进先出**（**FIFO**）队列。这与堆栈相反，堆栈中*最后*推入的项目会*先*弹出。

虽然我们刚刚描述了`std::queue`的行为，但本节展示了`std::priority_queue`的工作原理。该适配器很特别，因为它不仅考虑 FIFO 特性，还将其与优先级混合在一起。这意味着 FIFO 原则被分解为具有优先级的子 FIFO 队列。

# 如何做...

在本节中，我们将建立一个便宜的*待办事项列表组织*结构。我们不解析用户输入，以便使程序简短并集中在`std::priority_queue`上。因此，我们只是将待办事项的无序列表与优先级和描述一起填充到优先级队列中，然后像从 FIFO 队列数据结构中读取一样，但是根据各个项目的优先级进行分组。

1.  我们首先需要包含一些头文件。`std::priority_queue`在头文件`<queue>`中。

```cpp
      #include <iostream>
      #include <queue>
      #include <tuple>
      #include <string>
```

1.  我们如何将待办事项存储在优先级队列中？问题是，我们不能添加项目并额外附加优先级。优先级队列将尝试使用队列中所有项目的*自然顺序*。我们现在可以实现自己的`struct todo_item`，并给它一个优先级数字和一个待办描述字符串，然后实现比较运算符`<`以使它们可排序。或者，我们可以使用`std::pair`，它使我们能够将两个东西聚合在一个类型中，并为我们自动实现比较。

```cpp
      int main()
      {
          using item_type = std::pair<int, std::string>;
```

1.  我们现在有了一个新类型`item_type`，它由整数优先级和字符串描述组成。因此，让我们实例化一个优先级队列，其中包含这样的项目。

```cpp
          std::priority_queue<item_type> q;
```

1.  我们现在将用不同优先级的不同项目填充优先级队列。目标是提供一个*无结构*的列表，然后优先级队列告诉我们以*哪种顺序*做*什么*。如果有漫画要读，还有作业要做，当然，作业必须先做。不幸的是，`std::priority_queue`没有接受初始化列表的构造函数，我们可以用它来从一开始就填充队列。（使用向量或普通列表，它会按照这种方式工作。）所以我们首先定义列表，然后在下一步中插入它。

```cpp
          std::initializer_list<item_type> il {
              {1, "dishes"},
              {0, "watch tv"},
              {2, "do homework"},
              {0, "read comics"},
          };
```

1.  我们现在可以舒适地遍历待办事项的无序列表，并使用`push`函数逐步插入它们。

```cpp
          for (const auto &p : il) {
              q.push(p);
          }
```

1.  所有项目都被隐式排序，因此我们有一个队列，它给我们最高优先级的项目。

```cpp
          while(!q.empty()) {
              std::cout << q.top().first << ": " << q.top().second << 'n';
              q.pop();
          }
          std::cout << 'n';
      }
```

1.  让我们编译并运行我们的程序。确实，它告诉我们，首先做家庭作业，洗完碗后，我们最终可以看电视和看漫画。

```cpp
      $ ./main
      2: do homework
      1: dishes
      0: watch tv
      0: read comics
```

# 它是如何工作的...

`std::priority`列表非常容易使用。我们只使用了三个函数：

1.  `q.push(item)`将项目推入队列。

1.  `q.top()`返回队列中首先出队的项目的引用。

1.  `q.pop()`移除队列中最前面的项目。

但是项目的排序是如何工作的？我们将优先级整数和待办事项描述字符串分组到一个`std::pair`中，并获得自动排序。如果我们有一个`std::pair<int, std::string>`实例`p`，我们可以写`p.first`来访问*整数*部分，`p.second`来访问*字符串*部分。我们在循环中做到了这一点，打印出所有的待办事项。

但是，优先队列是如何推断出`{2, "做家庭作业"}`比`{0, "看电视"}`更重要的，而不是我们告诉它比较数字部分？

比较运算符`<`处理不同的情况。假设我们比较`left < right`，`left`和`right`是一对。

1.  `left.first != right.first`，然后返回`left.first < right.first`。

1.  `left.first == right.first`，然后返回`left.second < right.second`。

这样，我们可以按需订购物品。唯一重要的是，优先级是对的成员，描述是对的*第二*成员。否则，`std::priority_queue`会以一种看起来字母顺序比优先级更重要的方式对项目进行排序。（在这种情况下，*看电视*会被建议作为*第一*件事情做，*做家庭作业*稍后一些时间。这对于我们这些懒惰的人来说至少是很好的！）
