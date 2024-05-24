# 构建安卓 UI 自定义视图（三）

> 原文：[`zh.annas-archive.org/md5/DB7176CF30C0E45521FC275B41E28E14`](https://zh.annas-archive.org/md5/DB7176CF30C0E45521FC275B41E28E14)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：性能考虑

在前面的章节中，我们简要地讨论了性能问题，例如避免使用`onDraw()`方法进行某些操作。但我们还没有详细解释为什么你应该遵循这些建议，以及不遵循这些最佳实践对自定义视图和使用它的应用程序的真正影响。我们在这里解释的许多事情可能看起来是常识，实际上也应该是，但有时我们可能不会想到它们，或者我们可能不知道或不了解它们对应用程序可能产生的真实影响，无论是从性能角度还是关于电池消耗。

在本章中，我们将讨论这些问题，并更详细地了解以下主题：

+   建议和最佳实践

+   当不考虑性能时对应用的影响

+   代码优化

# 性能影响和推荐

正如我们所说，除非我们经历过性能问题，或者我们在支持低端或非常旧的设备，否则我们可能甚至不知道不遵循性能建议或最佳实践的影响是什么。如果我们使用高端设备来测试当前开发的内容，我们可能无法看到它在低端设备上的表现，而且很可能会有更多用户在中低端设备上使用它。这几乎就像是我们用良好可靠的 Wi-Fi 连接开发网络连接软件，或者拥有无限的 4G 网络。对于网络受限或按量计费的用户，尤其是仍在使用 2G 网络的用户，他们的体验可能完全不同。

在这两种情况下，重要的是要考虑我们的所有目标用户，并在多种场景下进行测试，使用不同的设备和硬件。

# 不遵循最佳实践的影响

在最近几章中，我们一直在推荐避免在`onDraw()`方法中分配对象。但如果我们开始分配对象，会发生什么呢？

让我们创建一个简单的自定义视图，并故意分配一个对象，以便我们可以在运行应用时评估结果：

```kt
package com.packt.rrafols.draw; 

import android.content.Context; 
import android.graphics.Bitmap; 
import android.graphics.BitmapFactory; 
import android.graphics.Canvas; 
import android.graphics.Paint; 
import android.graphics.Path; 
import android.graphics.Rect; 
import android.graphics.Region; 
import android.util.AttributeSet; 
import android.view.GestureDetector; 
import android.view.MotionEvent; 
import android.view.View; 
import android.widget.Scroller; 

public class PerformanceExample extends View { 
    private static final String TAG =PerformanceExample.class.
                                     getName(); 

    private static final int BLACK_COLOR = 0xff000000; 
    private static final int WHITE_COLOR = 0xffffffff; 
    private float angle; 

    public PerformanceExample(Context context, AttributeSet attributeSet)
    { 
        super(context, attributeSet); 

        angle = 0.f; 
    } 

    /** 
     * This is precisely an example of what MUST be avoided. 
     * It is just to exemplify chapter 7\. 
     * 
     * DO NOT USE. 
     * 
     * @param canvas 
     */ 
    @Override 
    protected void onDraw(Canvas canvas) { 
        Bitmap bitmap = Bitmap.createBitmap(getWidth(), getHeight(), 
                        Bitmap.Config.ARGB_8888); 
           Rect rect = new Rect(0, 0, getWidth(), getHeight()); 
           Paint paint = new Paint(); 
           paint.setColor(BLACK_COLOR); 
           paint.setStyle(Paint.Style.FILL); 
           canvas.drawRect(rect, paint); 
           canvas.save(); 

           canvas.rotate(angle, getWidth() / 2, getHeight() / 2); 
           canvas.translate((getWidth() - getWidth()/4) / 2, 
                 (getHeight() - getHeight()/4) / 2); 

           rect = new Rect(0, 0, getWidth() / 4, getHeight() / 4); 
           paint = new Paint(); 
           paint.setColor(WHITE_COLOR); 
           paint.setStyle(Paint.Style.FILL); 
           canvas.drawBitmap(bitmap, 0, 0, paint); 
           canvas.drawRect(rect, paint); 
           canvas.restore(); 
           invalidate(); 
           bitmap.recycle(); 
           angle += 0.1f; 
       } 
    } 
```

在这个快速示例中，我们在`onDraw()`方法中分配了多件事情，从`Paint`对象到`Rect`对象，再到创建一个新的`bitmap`，这会分配内部内存。

如果我们运行这段代码，我们会在屏幕中央得到一个旋转的白色的矩形，如下面的截图所示：

![图像](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/cfb6fc4b-3ea8-44da-a6a3-1fb33a15e297.png)

此外，我们不仅会得到一个类似的视图。如果我们在应用程序运行时检查 logcat 日志，我们可能会得到类似以下的行：

```kt
I art : Starting a blocking GC Explicit
I art : Explicit concurrent mark sweep GC freed 198893(13MB) AllocSpace objects, 30(656KB) LOS objects, 26% free, 43MB/59MB, paused 2.835ms total 313.353ms
I art : Background partial concurrent mark sweep GC freed 26718(2MB) AllocSpace objects, 1(20KB) LOS objects, 27% free, 43MB/59MB, paused 3.434ms total 291.430ms
```

应用程序执行期间，我们可能会多次获取它们。这是 Android 运行时（ART）的垃圾收集器介入，清理未使用的对象以释放内存。由于我们不断创建新对象，虚拟机将触发垃圾收集器来释放一些内存。

关于垃圾回收的更多信息可以在以下网址找到：

[`en.wikipedia.org/wiki/Garbage_collection_(computer_science)`](https://en.wikipedia.org/wiki/Garbage_collection_(computer_science))。

幸运的是，Android Studio 已经非常明确地告诉我们，在我们的 `onDraw()` 方法内部我们正在做错误的事情：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/086755ce-57d4-42e6-8888-aa6a6a597b59.png)

它还告诉我们，如果不遵循这个建议，可能会造成什么后果。在这种情况下，如果在滚动或绘制过程中垃圾回收器启动，我们可能会遇到一些卡顿，或者一个平滑的动画可能看起来会跳跃或不那么流畅。

请在 GitHub 存储库的 `Example30-Performance` 文件夹中查看这个示例的完整源代码，不建议遵循它。请将其作为一个应该避免的示例。

# 代码优化

在考虑自定义视图中的性能时，分配对象不是我们应该考虑的唯一事情。我们应该考虑的计算量、计算类型、我们正在绘制的原始数量、过度绘制的数量以及我们应该检查的事情列表非常庞大。最终，大多数事情都是常识：只是不要重新计算我们已经拥有的值，并最大化如果不需要更改就可以跳过的代码部分，或者基本上，尽量重复使用尽可能多的之前帧已经计算过的内容。

让我们比较两种将 YUV 像素数据转换为 RGB 的方法。这并不是自定义视图中你必须做的最典型的事情，但它完美地展示了通过尽可能多地重复使用和不重新计算不需要的内容，性能会受到怎样的影响。

在 Android 中从摄像头取景器获取帧时，它们通常是 YUV 格式而不是 RGB。关于 YUV 的更多信息可以在以下网址找到：

[YUV](https://en.wikipedia.org/wiki/YUV)的相关信息可以在以下网址找到。

我们将从直接的代码开始，并逐步对其进行优化，以评估所有优化的影响：

```kt
private static void yuv2rgb(int width, int height, byte[] yuvData,
    int[] rgbData) { 
    int uvOffset = width * height; 
    for (int i = 0; i < height; i++) { 
         int u = 0; 
         int v = 0; 
         for (int j = 0; j < width; j++) { 
           int y = yuvData[i * width + j]; 
           if (y < 0) y += 256; 

           if (j % 2 == 0) { 
               u = yuvData[uvOffset++]; 
               v = yuvData[uvOffset++]; 
            } 

            if (u < 0) u += 256; 
            if (v < 0) v += 256; 

            int nY = y - 16; 
            int nU = u - 128; 
            int nV = v - 128; 

            if (nY< 0) nY = 0; 

            int nR = (int) (1.164 * nY + 2.018 * nU); 
            int nG = (int) (1.164 * nY - 0.813 * nV - 0.391 * nU); 
            int nB = (int) (1.164 * nY + 1.596 * nV); 

            nR = min(255, max(0, nR)); 
            nG = min(255, max(0, nG)); 
            nB = min(255, max(0, nB)); 

            nR&= 0xff; 
            nG&= 0xff; 
            nB&= 0xff; 

            int color = 0xff000000 | (nR<< 16) | (nG<< 8) | nB; 
            rgbData[i * width + j] = color; 
        } 
    } 
} 
```

这个版本基于以下网址找到的 YUV 到 RGB 转换器：

[`searchcode.com/codesearch/view/2393/`](https://searchcode.com/codesearch/view/2393/) 和

[`sourceforge.jp/projects/nyartoolkit-and/`](http://sourceforge.jp/projects/nyartoolkit-and/)。

我们在这里使用了浮点数版本，以便稍后我们可以看到与固定点版本的差异。

现在，让我们创建一个小的自定义视图，它将在每一帧中将 YUV 图像转换为 RGB，将其设置为 `Bitmap`，并在屏幕上绘制：

```kt
@Override 
protected void onDraw(Canvas canvas) { 
    yuv2rgb(imageWidth, imageHeight, yuvData, rgbData); 
    bitmap.setPixels(rgbData, 0, imageWidth, 0, 0, imageWidth,
    imageHeight); 

    canvas.drawBitmap(bitmap, 0.f, 0.f, null); 

    frames++; 
    invalidate(); 
} 
```

让我们也添加一段代码来检查我们的小代码能管理的每秒帧数。我们将使用这个测量来检查我们将要进行的优化对性能的提升：

```kt
if (timeStart == -1) { 
    timeStart = SystemClock.elapsedRealtime(); 
} else { 
    long tdiff = SystemClock.elapsedRealtime() - timeStart; 
    if (tdiff != 0) { 
        float fps = ((float) frames * 1000.f) / tdiff; 
        Log.d(TAG, "FPS: " + fps); 
    } 
} 
```

如果我们就这样在我的设备上运行这段代码，它测量到的每秒帧数是 1.20。使用的演示图片是*1,000x1,500*的图像。让我们看看我们能做些什么来改进它。

首先，我们可以移除一些不必要的计算：

```kt
private static void yuv2rgb(int width, int height, byte[] yuvData,
    int[] rgbData) { 
    int uvOffset = width * height; 
    int offset = 0; 
    for (int i = 0; i < height; i++) { 
        int u = 0; 
        int v = 0; 
        for (int j = 0; j < width; j++) { 
            int y = yuvData[offset]; 
            ... 
            rgbData[offset] = color; 

            offset++; 
        } 
    } 
} 
```

在这里，我们移除了两个像素位置的计算，而是通过每个像素的单个增量来完成。在之前的情况下，无论是读取`yuvData`还是写入`rgbData`，都会进行`i * width + j`的计算。如果我们检查这个更改后的每秒帧数计数器，我们会注意到它略微增加到了 1.22。虽然提升不大，但这是一个开始。

现在，我们可以看到在原始实现中，即 Android SDK 中使用的方法，浮点运算被注释掉了，取而代之的是定点运算。浮点运算通常比整数运算成本更高。尽管这些年随着新硬件的出现，浮点运算的性能有了很大的提升，但整数运算仍然更快。我们无法获得与浮点运算相同的精度，但通过使用定点运算，我们可以得到相当好的近似值。

关于定点运算的更多信息可以在以下 URL 找到：

[定点运算](https://en.wikipedia.org/wiki/Fixed-point_arithmetic)的相关信息可以在以下链接找到。

使用定点运算时，我们必须定义一个整数值的位数，这将用作定点精度。剩余的位数将用于实际存储整数值。显然，我们用于存储的位数越多，精度就越高，但另一方面，用于存储整数值的位数就越少。想法是将所有常数和操作乘以 2 的幂次数，在完成所有操作后，将结果除以相同的数。由于它是 2 的幂，我们可以轻松地进行快速的位运算右移操作，而不是昂贵的除法。

例如，如果我们使用 10 位的定点精度，我们必须将所有值乘以*1,024*或左移 10 位，在所有计算结束时，执行 10 位的右移操作。

让我们把这些操作应用到这里：

```kt
int nR = (int) (1.164 * nY + 2.018 * nU); 
int nG = (int) (1.164 * nY - 0.813 * nV - 0.391 * nU); 
int nB = (int) (1.164 * nY + 1.596 * nV); 
```

我们将它们转换为以下形式：

```kt
int nR = (int) (1192 * nY + 2066 * nU); 
int nG = (int) (1192 * nY - 833 * nV - 400 * nU); 
int nB = (int) (1192 * nY + 1634 * nV); 
```

我们可以检查*1.164 * 1,024* 是向上取整的`1192`，其他所有常数也同样处理——我们四舍五入数字以获得最有效的近似值。

出于同样的原因，我们必须更改以下检查：

```kt
nR = min(255, max(0, nR)); 
nG = min(255, max(0, nG)); 
nB = min(255, max(0, nB)); 
```

我们必须将带有*255*255*乘以*1,024*的检查，左移`10`位：

```kt
nR = min(255 << 10, max(0, nR)); 
nG = min(255 << 10, max(0, nG)); 
nB = min(255 << 10, max(0, nB)); 
```

在输出颜色之前，先除以*1,024*或右移`10`位使用这些值：

```kt
nR>>= 10; 
nG>>= 10; 
nB>>= 10; 
```

实施这些更改后，即使与浮点版本相比我们增加了一些操作，但每秒帧数计数器提高到了*1.55*。

另一个小优化是我们可以避免计算每个分量的`亮度`因子，因为在每种情况下它都是相同的。所以让我们替换这段代码：

```kt
int nR = (int) (1192 * nY + 2066 * nU); 
int nG = (int) (1192 * nY - 833 * nV - 400 * nU); 
int nB = (int) (1192 * nY + 1634 * nV); 
```

对于这个只计算一次`亮度`的版本：

```kt
int luminance = 1192 * nY; 
int nR = (int)(luminance + 2066 * nU); 
int nG = (int)(luminance - 833 * nV - 400 * nU); 
int nB = (int)(luminance + 1634 * nV); 
```

这应该会被大多数编译器优化；我不确定新的编译器 D8 和 R8 会做什么，但使用当前的 Java/Android 工具链，它并没有被优化。通过这个小小的改动，我们将每秒帧数计数器提升到了*1.59*。

这种 YUV 文件格式的工作方式是，一对`U`和`V`色度值被两个`亮度`值共享，所以让我们尝试利用这一点同时计算两个像素，避免额外的检查和代码开销：

```kt
for(int j = 0; j < width; j += 2) {
   int y0 = yuvData[offset]; 
   if (y0 < 0) y0 += 256; 

   int y1 = yuvData[offset + 1]; 
   if (y1 < 0) y1 += 256; 

   u = yuvData[uvOffset++]; 
   v = yuvData[uvOffset++]; 
   if (u < 0) u += 256; 
   if (v < 0) v += 256; 

   int nY0 = y0 - 16; 
   int nY1 = y1 - 16; 
   int nU = u - 128; 
   int nV = v - 128; 

   if (nY0 < 0) nY0 = 0; 
   if (nY1 < 0) nY1 = 0; 

   int chromaR = 2066 * nU; 
   int chromaG = -833 * nV - 400 * nU; 
   int chromaB = 1634 * nV; 

   int luminance = 1192 * nY0; 
   int nR = (int) (luminance + chromaR); 
   int nG = (int) (luminance + chromaG); 
   int nB = (int) (luminance + chromaB); 

   nR = min(255 << 10, max(0, nR)); 
   nG = min(255 << 10, max(0, nG)); 
   nB = min(255 << 10, max(0, nB)); 

   nR>>= 10; 
   nG>>= 10; 
   nB>>= 10; 

   nR&= 0xff; 
   nG&= 0xff; 
   nB&= 0xff; 

   rgbData[offset] = 0xff000000 | (nR<< 16) | (nG<< 8) | nB; 

   luminance = 1192 * nY1; 
   nR = (int) (luminance + chromaR); 
   nG = (int) (luminance + chromaG); 
   nB = (int) (luminance + chromaB); 

   nR = min(255 << 10, max(0, nR)); 
   nG = min(255 << 10, max(0, nG)); 
   nB = min(255 << 10, max(0, nB)); 

   nR>>= 10; 
   nG>>= 10; 
   nB>>= 10; 

   nR&= 0xff; 
   nG&= 0xff; 
   nB&= 0xff; 

   rgbData[offset + 1] = 0xff000000 | (nR<< 16) | (nG<< 8) | nB; 

   offset += 2; 
} 
```

现在我们只计算一次色度分量，并且移除了检查，只在每两个像素获取新的`U`和`V`分量。进行这些更改后，我们的每秒帧数计数器提升到了*1.77*。

由于 Java 字节范围从-128 到 127，我们添加了一些对负数的检查，但我们可以通过快速进行按位与操作（`&`）来代替这些检查：

```kt
for (int i = 0; i < height; i++) { 
    for (int j = 0; j < width; j += 2) { 
      int y0 = yuvData[offset    ] & 0xff; 
      int y1 = yuvData[offset + 1] & 0xff; 

      int u = yuvData[uvOffset++] & 0xff; 
      int v = yuvData[uvOffset++] & 0xff; 

        ... 
   } 
} 
```

这个小小的改动将我们的每秒帧数计数器略微提升到了*1.83*。但我们还可以进一步优化。我们使用了`10`位固定小数点精度的算术，但在这个特定情况下，我们可能使用`8`位精度就足够了。从`10`位精度改为仅`8`位将节省我们一个操作步骤：

```kt
for (int i = 0; i < height; i++) { 
  for (int j = 0; j < width; j += 2) { 
        ... 
    int chromaR = 517 * nU; 
    int chromaG = -208 * nV - 100 * nU; 
    int chromaB = 409 * nV; 

    int lum = 298 * nY0; 

    nR = min(65280, max(0, nR)); 
    nG = min(65280, max(0, nG)); 
    nB = min(65280, max(0, nB)); 

    nR<<= 8; 
    nB>>= 8; 

    nR&= 0x00ff0000; 
    nG&= 0x0000ff00; 
    nB&= 0x000000ff; 

    rgbData[offset] = 0xff000000 | nR | nG | nB; 

        ... 

    offset += 2; 
   } 
} 
```

我们将所有常量更新为乘以`256`而不是*1,024*，并更新了检查。代码中出现的常数`65280`是`255`乘以`256`。在我们将值位移以获取实际颜色分量的代码部分，我们必须将红色分量右移`8`位，然后左移`16`位以调整到 ARGB 在颜色分量中的位置，这样我们只需进行一次`8`位左移的单一位移操作。在绿色坐标上甚至更好——我们需要将其右移`8`位然后左移`8`位，因此我们可以保持原样，不进行任何位移。我们仍然需要将蓝色分量右移`8`位。

我们还必须更新掩码，以确保每个分量保持在 0-255 的范围内，但现在掩码已经右移到了正确的位位置`0x00ff0000`，`0x0000ff00`和`0x000000ff`。

这个改变将我们的每秒帧数计数器略微提升到了*1.85*，但我们还可以做得更好。让我们尝试去掉所有的位移、检查和掩码操作。我们可以通过使用一些预先计算的表格来实现，这些表格在我们自定义视图创建时计算一次。让我们创建这个函数来预先计算我们需要的一切：

```kt
private static int[] luminance; 
private static int[] chromaR; 
private static int[] chromaGU; 
private static int[] chromaGV; 
private static int[] chromaB; 

private static int[] clipValuesR; 
private static int[] clipValuesG; 
private static int[] clipValuesB; 

private static void precalcTables() {
    luminance = new int[256];
    for (int i = 0; i <luminance.length; i++) {
        luminance[i] = ((298 * (i - 16)) >> 8) + 300;
    }
    chromaR = new int[256]; 
    chromaGU = new int[256]; 
    chromaGV = new int[256]; 
    chromaB = new int[256]; 
    for (int i = 0; i < 256; i++) {
       chromaR[i] = (517 * (i - 128)) >> 8;
       chromaGU[i] = (-100 * (i - 128)) >> 8;
       chromaGV[i] = (-208 * (i - 128)) >> 8;
       chromaB[i] = (409 * (i - 128)) >> 8;
    }

    clipValuesR = new int[1024]; 
    clipValuesG = new int[1024]; 
    clipValuesB = new int[1024]; 
    for (int i = 0; i < 1024; i++) { 
       clipValuesR[i] = 0xFF000000 | (min(max(i - 300, 0), 255) << 16); 
       clipValuesG[i] = min(max(i - 300, 0), 255) << 8; 
       clipValuesB[i] = min(max(i - 300, 0), 255); 
    } 
} 
```

我们正在计算`luminance`（亮度）的所有色度分量以及最后所有内容的剪辑、移位和遮罩值。由于`luminance`和某些色度可能是负数，我们在`luminance`值中添加了*+*`300`，因为它将加到所有值上，然后调整`clipValues`表以考虑这个`300`的偏移量。否则，我们可能会尝试用负索引来索引数组，这将导致我们的应用程序崩溃。在访问数组之前检查索引是否为负将消除所有性能优化，因为我们尽可能想要摆脱所有操作和检查。

使用这些表格，我们的 YUV 到 RGB 转换器代码减少到以下内容：

```kt
private static void yuv2rgb(int width, int height, byte[] yuvData,
    int[] rgbData) { 
    int uvOffset = width * height; 
    int offset = 0; 

    for (int i = 0; i < height; i++) { 
        for (int j = 0; j < width; j += 2) { 
        int y0 = yuvData[offset ] & 0xff; 
        int y1 = yuvData[offset + 1] & 0xff; 

        int u = yuvData[uvOffset++] & 0xff; 
        int v = yuvData[uvOffset++] & 0xff; 

        int chR = chromaR[u]; 
        int chG = chromaGV[v] + chromaGU[u]; 
        int chB = chromaB[v]; 

        int lum = luminance[y0]; 
        int nR = clipValuesR[lum + chR]; 
        int nG = clipValuesG[lum + chG]; 
        int nB = clipValuesB[lum + chB]; 

        rgbData[offset] = nR | nG | nB; 

        lum = luminance[y1]; 
        nR = clipValuesR[lum + chR]; 
        nG = clipValuesG[lum + chG]; 
        nB = clipValuesB[lum + chB]; 

        rgbData[offset + 1] = nR | nG | nB; 

        offset += 2; 
       } 
    } 
} 
```

进行这些更改后，我们获得了每秒*2.04*帧的速度计数，或者与原始方法相比性能提升了*70%*。无论如何，这只是一个代码如何优化的示例；如果你真的想要实时将 YUV 图像转换为 RGB，我建议你检查一下本地 C 或 C++ 的实现，或者采用 GPU 或渲染脚本的方法。

最后，如果我们运行这个应用程序，我们将得到一个类似于以下截图的屏幕。我们没有对图像进行缩放或应用任何额外的转换，因为我们只想测量从 YUV 图像转换为 RGB 图像所需的时间。你的屏幕图像可能会因屏幕大小和设备的不同而有所不同：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/53a62ad7-ada2-4617-be51-6c276d395892.png)

在 GitHub 仓库的`Example31-Performance`文件夹中查看整个示例源代码。

在谈论性能时，还有很多其他事情需要考虑。如果你想了解更多关于 Java 代码如何转换为 dex 字节码并在 Android VM 中执行的信息，请查看以下演示：

[字节码之谜](https://www.slideshare.net/RaimonRls/the-bytecode-mumbojumbo)。

# 模拟预览窗口

当在 Android Studio 中预览我们的自定义视图时，有时计算可能会非常复杂，或者例如我们需要初始化一些数据，但我们不能在 Android Studio 的预览窗口中显示我们的自定义视图时这样做。通过检查 `isInEditMode()` 方法，我们将能够对此进行处理。

如果我们处于 IDE 或开发工具内部，这个方法将返回 true。知道了这个信息，我们可以轻松地模拟一些数据，或者简化渲染，只显示我们想要绘制的内容的预览。

例如，在 GitHub 仓库中的`Example07-BuilderPattern`文件夹里，我们在自定义视图创建时调用这个方法来改变渐变中使用的颜色值，尽管实际上我们也可以在`onDraw()`方法中调用它，来改变视图的渲染效果：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/caf6b140-52e3-494b-8ca1-e8a86b627326.png)

# 总结

在本章中，我们已经了解了不遵循性能建议的影响，以及在我们实现自定义视图时为何有一套最佳实践和应避免的事项。我们还学习了如何改进或优化代码以提高性能，以及如何调整或自定义视图以在 Android Studio IDE 预览窗口中渲染预览。

正如我们将在下一章看到的，无论我们的自定义视图是被其他人使用还是被我们自己使用，都不应该有任何区别。它不应该因为自身的问题导致使用它的应用程序崩溃或行为异常。就像包含第三方库一样，它绝不应该让我们的应用程序崩溃，否则，我们很可能会停止使用它并用另一个库来替代。

因此，在下一章中，我们不仅将学习如何应用这些建议，还将学习如何使我们的自定义视图在多个应用中可复用，以及如何分享或开源它，以便在 Android 社区内广泛使用。


# 第八章：分享我们的自定义视图

在前面的章节中，我们已经构建了我们的自定义视图，或者其中许多。我们已经了解了如何与它们互动，如何绘制 2D 和 3D 原始图形，现在我们希望其他人也能使用它。这是一个很好的想法！这可能是为了我们自己，我们可能会在未来的项目中重用，或者可能是我们同事的一个项目。如果我们目标更高，它可能是 Android 社区的一个项目。

让 Android 社区变得出色的一件事是有大量的开源库。开发者们的所有这些贡献帮助许多其他开发者开始了 Android 开发，深入理解某些概念，或者能够首先构建他们的应用程序。

首先，发布你的自定义视图，或者一个 Android 库，是贡献给这个惊人社区的方法之一。其次，这样做是宣传自己、展示雇主的开放性以及吸引公司人才的好方法。

在本章中，我们将了解如果想要分享我们的自定义视图应该考虑什么，以及如何做到这一点。我们还将实践一些在前面章节中给出的重要建议。更重要的是，我们希望其他开发者能使用我们的自定义视图。

更详细地说，我们将涵盖以下主题：

+   建议和最佳实践

+   发布你的自定义视图

几乎所有给出的建议不仅适用于自定义视图，也适用于我们想要分享或希望让同事或其他项目可重用的任何 Android 库。

# 分享自定义视图的最佳实践

尽管我们只是在为自己或一个小型应用构建自定义视图或组件，我们也应该始终追求尽可能高的质量。然而，如果我们想要分享我们的自定义视图，让其他人也能使用它，我们需要考虑一些额外的检查和最佳实践。如果我们目标是让尽可能多的开发者在他们的应用中使用它或为它贡献，那么如果我们忽视这些建议，将很难吸引他们参与。

# 考虑事项和建议

我们应该考虑的一件事是，一旦我们分享了自定义视图，它可能会被许多 Android 应用使用。如果我们的自定义视图有错误并且崩溃了，它将导致使用它的应用崩溃。应用的用户不会认为是自定义视图的问题，而是应用本身的问题。应用开发者可能会尝试提出问题，甚至提交一个 pull 请求来修复它，但如果自定义视图给他们带来太多麻烦，他们只会替换它。

这也适用于你自己的应用程序；你不想使用一个不稳定的组件或自定义视图，因为你可能最终要重写它或修补它。正如我们刚刚提到的，我们应始终追求最高质量。如果我们的自定义视图只在一个应用程序中使用，那么在生产阶段或应用程序发布到商店时发现一个关键问题的影响只影响一个应用程序。但是，如果它在多个应用程序中使用，维护的影响和成本就会增加。你可以想象，在开源组件中发现一个高度关键的问题，并不得不为所有使用它的应用程序发布新版本的影响。

此外，你应该尽量保持代码干净、组织有序、测试充分且文档合理。这对于你以及如果你在公司分享自定义视图的同事来说，将更容易维护自定义视图。如果它是开源的，这将鼓励贡献，并且实际上不会吓跑外部贡献者。与其他许多事情一样，常识适用。不要过度文档化你的自定义视图，因为基本上没人会去读它；尽量保持简单明了，直击要点。

在以下截图中，我们可以看到`retrofit`库的开放问题，这是一个在许多应用程序中广泛使用的开源 Android 库：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/4bb8375c-bb14-4472-85f1-04a41e1a0ff6.png)

同时，我们可以看到有几位开发者提交了许多拉取请求，他们要么在修复问题，要么在添加功能或特性。以下截图是提交给`retrofit`库的一个拉取请求示例：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/bb39c47e-3b26-478e-87ff-987e1559c293.png)

我们之前已经提到过，但自定义视图的行为正确也很重要。它不仅必须保证不崩溃，还必须在多种设备和分辨率下正常工作，并且具有良好的性能。

我们可以用以下要点总结建议列表：

+   稳定

+   在多种设备和分辨率下工作

+   性能优良

+   应用最佳代码实践和标准风格开发

+   文档齐全且易于使用

# 可配置

在第二章，*实现你的第一个自定义视图*中，我们解释了如何参数化自定义视图。我们创建它是因为它可能服务于一个非常具体的目的，但一般来说，它配置得越灵活，就越有可能在其他地方被使用。

想象一下我们正在构建一个进度条。如果我们的自定义视图总是绘制一个水平红色条，它会有其用途，但不会太多，因为它太具体了。如果我们允许使用这个自定义视图的应用程序的开发者自定义条的颜色，我们就会为它增加几个其他用例。此外，如果我们还允许开发者配置背景颜色或者绘制水平条之外的哪种原始图形，我们的自定义视图将涵盖更多不同的场景。

我们也需要注意；添加太多选项也会增加代码和组件本身的复杂性。配置颜色是直接的，影响并不大，但例如能够更改绘图原语可能稍微有点复杂。增加复杂性可能会影响性能、稳定性，以及我们在发布或制作新版本时测试和验证所有场景是否正常工作的能力。

# 发布我们的自定义视图

一旦我们对自定义视图及其现状感到满意，我们就可以准备分享了。如果我们也遵循了最佳实践和推荐，我们可能会更有信心。即使没有，最好的学习方式就是尽快从社区获得反馈。不要害怕犯错误；你会在过程中学到东西的。

发布自定义视图的方法有很多：我们可以选择开源，例如，或者我们可以只发布编译后的二进制文件作为 SDK 或 Android 库。以上大多数建议针对的是开源方法或内部重用，无论是为了自己还是同事，但其中许多（并非全部）也适用于你的目标是发布一个封闭的 SDK 或只作为库发布编译后的二进制文件。

# 开源我们自定义的视图

开源一个自定义视图或者，作为替代，一个 Android 库，是相当简单和直接的。你需要确保你执行了一些额外的步骤，但整个过程非常简单。

我们一直在使用 GitHub 分享本书示例的源代码。这并非巧合。GitHub 是分享源代码、开源库和项目最广泛使用的工具之一。它也是我们将在本章推荐并使用的工具，来解释如何发布我们的自定义视图。

首要任务是，如果我们还没有 GitHub 账户，就需要注册并创建一个。只要我们只想托管公开的仓库或公开可访问的代码，创建账户是免费的。如果我们想要用它来存储私有代码仓库，就有付费选项。就本书的范围而言，免费选项已经足够了。

我们可以直接从主页注册：[`www.github.com`](https://www.github.com) 或者从以下链接：

[加入 GitHub](https://github.com/join)

创建账户后，我们创建一个代码仓库来存储代码。我们可以在以下位置进行操作：

[新建 GitHub 仓库](https://github.com/new)。如下截图所示：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/e9830572-a781-4551-8d37-b69f139b3e88.png)（图片无需翻译，直接复制原文）

我们必须选择一个仓库名称。强烈建议添加描述，这样其他人更容易理解我们的组件或库的功能。我们还可以选择添加一个 `.gitignore` 文件和许可证。

`.gitignore`是一个非常有用的文件。这里提到的所有文件都不会上传到 GitHub。例如，没有必要上传所有临时文件、构建文件、中间构建文件或 Android Studio 的配置文件，这些文件包含有关项目的特定信息，仅保存在我们的本地计算机上。例如，知道我们将项目存储在`\Users\raimon\development\AndroidCustomView`没有任何用。

添加许可证对于确定我们授予使用源代码者的权利非常重要。开源项目中最常见的许可证有 Apache 2.0、MIT 和 GPLv3 许可证：

+   MIT 是最少限制和最宽容的许可证。只要其他方在使用源代码时包含许可证和版权声明，就可以以任何方式使用源代码。

+   Apache 2.0 许可证同样非常宽容。与 MIT 许可证一样，只要其他方在使用源代码时包含许可证和版权声明，并说明对原始文件的更改，就可以以任何方式使用源代码。

+   GPLv3 稍微严格一些，因为它要求任何使用你源代码的人必须按照相同的许可证发布使用该源代码的应用程序源代码。这对于一些希望保留源代码知识产权的公司来说可能是一种限制。

这三种许可证都限制了原始开发者的责任，并不提供任何担保。它们都是将软件或源代码“按现状”提供。

许多 Android 库使用 MIT 或 Apache 2.0 许可证，我们建议您的自定义视图也使用这两个许可证之一。

仓库创建并初始化后，我们可以上传代码。我们可以使用任何偏好的 Git 客户端，或者直接使用命令行界面。

首先，我们克隆刚才创建的仓库——仅作为参考，并非真实的仓库：

```kt
raimon$ git clone https://github.com/rrafols/androidcustomview.git 
Cloning into 'androidcustomview'... 
remote: Counting objects: 5, done. 
remote: Compressing objects: 100% (4/4), done. 
remote: Total 5 (delta 0), reused 0 (delta 0), pack-reused 0 
Unpacking objects: 100% (5/5), done. 
```

检查连接。完成。

如果我们已经有了一个包含源代码的目录，Git 会报错，无法创建目录：

```kt
raimon$ git clone https://github.com/rrafols/androidcustomview.git 
```

fatal: destination path `androidcustomview` already exists and is not an empty directory.

在这种情况下，我们必须使用不同的方法。首先，我们必须初始化本地仓库：

```kt
androidcustomview raimon$ gitinit 
Initialized empty Git repository in /Users/raimon/dev/androidcustomview/.git/ 
```

然后添加远程仓库：

```kt
androidcustomview raimon$ git remote add origin https://github.com/rrafols/androidcustomview.git 
```

最后，从主分支拉取内容：

```kt
androidcustomview raimon$ git pull origin master 
remote: Counting objects: 5, done. 
remote: Compressing objects: 100% (4/4), done. 
remote: Total 5 (delta 0), reused 0 (delta 0), pack-reused 0 
Unpacking objects: 100% (5/5), done. 
From https://github.com/rrafols/androidcustomview 
 * branch            master     -> FETCH_HEAD 
 * [new branch]      master     -> origin/master 
```

现在我们可以添加所有希望添加到 GitHub 仓库的文件。在这个例子中，我们将添加所有内容，Git 会自动忽略与`.gitignore`文件中模式匹配的文件：

```kt
androidcustomview raimon$ git add *
```

现在我们可以将改动提交到本地仓库。一定要使用有意义的提交信息或描述，因为这将有助于以后了解都更改了什么。

```kt
androidcustomview raimon$ git commit -m "Adding initial files" 
[master bc690c7] Adding initial files 
 6 files changed, 741 insertions(+) 
```

完成这些操作后，我们就可以将提交推送到远程仓库，本例中的远程仓库位于[`github.com/`](https://github.com/)：

```kt
androidcustomview raimon$ git push origin master 
Username for 'https://github.com': rrafols 
Password for 'https://rrafols@github.com':  
Counting objects: 9, done. 
Delta compression using up to 4 threads. 
Compressing objects: 100% (8/8), done. 
Writing objects: 100% (8/8), 6.06 KiB | 0 bytes/s, done. 
Total 8 (delta 3), reused 0 (delta 0) 
remote: Resolving deltas: 100% (3/3), done. 
To https://github.com/rrafols/androidcustomview.git 
343509f..bc690c7 master -> master
```

若要了解更多关于 Git 的信息，请访问：

[`en.wikipedia.org/wiki/Git`](https://en.wikipedia.org/wiki/Git).

创建仓库时，GitHub 会询问我们是否要创建一个`README.md`文件。这个`README.md`文件将显示在仓库页面上作为文档。它使用 markdown 格式，这就是扩展名为`.md`的原因，并且重要的是要将其与项目信息保持同步，包括如何使用、一个快速示例、以及关于许可和作者的信息。这里最重要的部分是，任何想要使用你的自定义视图的人都可以快速查看如何操作，许可是否合适，以及如何联系你寻求支持和帮助。这部分是可选的，因为他们总是可以在 GitHub 上提出问题，但这样更好。我们甚至可以直接从以下位置编辑和预览更改：

[`github.com/`](https://github.com/)。

不仅要保持文档更新，保持库的维护和更新也很重要。有一些需要解决的错误，需要添加的新功能，新的 Android 版本可能会破坏、弃用、改进或添加新的方法，以及其他开发者提出问题或询问。当寻找自定义视图或 Android 库时，如果没有最近的更新，或者至少在过去的几个月内没有，它看起来像是被遗弃了，这大大降低了其他人使用它的机会。

# 创建二进制工件

我们一直在谈论共享自定义视图和 Android 库，好像它们是同一回事。分享自定义视图最合适的方式是作为 Android 库。Android 应用程序和 Android 库之间的主要区别在于，后者不能在设备或模拟器上独立运行，并且只会生成一个`.aar`文件。这个`.aar`文件稍后可以作为依赖项添加到 Android 应用程序项目或其他库中。我们还可以在同一个项目内拥有子模块，并且它们之间可以有依赖关系。为了了解这是如何工作的，我们将把自定义视图项目转换成 Android 库，并且将添加一个测试应用程序项目以快速测试它。

首先，一旦我们有了 Android 应用程序，我们可以通过执行两个简单的步骤将其转换为库：

1.  在 app 模块的`build.gradle`文件中删除提到`applicationId`的行。

1.  将应用的插件从`com.android.application`更改为`com.android.library`。

基本上更改以下内容：

```kt
apply plugin: 'com.android.application'

android {
   compileSdkVersion 25
   buildToolsVersion"25.0.2"

   defaultConfig {
       applicationId"com.rrafols.packt.customview"
       minSdkVersion 21
       targetSdkVersion 25
       versionCode 1
       versionName"1.0"
```

更改为以下内容：

```kt
apply plugin: 'com.android.library'

android {
   compileSdkVersion 25
   buildToolsVersion"25.0.2"

    defaultConfig {
       minSdkVersion 21
       targetSdkVersion 25
       versionCode 1
       versionName"1.0"
```

在我们的示例中，还将应用模块名称重构为 lib。

关于如何将 Android 应用程序转换为 Android 库的更多信息可以在开发者 Android 文档页面找到：

[`developer.android.com/studio/projects/android-library.html`](https://developer.android.com/studio/projects/android-library.html)。

如果我们正在开发或扩展这个库，我们建议在项目中添加一个新的模块作为测试应用程序。这将大大加快自定义视图的开发和测试速度。

我们可以使用 Android Studio 文件菜单添加一个新模块：文件 | 新建 | 新模块：

![图片](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/98fafcf5-8182-4ee6-82b8-f3f24f3c6d6c.png)

添加测试应用模块后，我们向库添加一个依赖项。在新模块的`build.gradle`文件中，添加对本地库模块的依赖：

```kt

dependencies {
    compile project(":lib")
    compile fileTree(dir: 'libs', include: ['*.jar'])
    androidTestCompile('com.android.support.test.espresso:espresso-core:2.2.2',
    {
        exclude group: 'com.android.support', module: 'support-annotations'
    })

    compile 'com.android.support:appcompat-v7:25.3.1'
    compile 'com.android.support.constraint:constraint-layout:1.0.2'
    testCompile'junit:junit:4.12'
}
```

现在，你可以将自定义视图添加到这个新的测试应用布局中并测试它。此外，我们还可以生成一个库二进制文件以供分发。它只包含库或 lib 模块。我们可以通过在 gradle 上执行`lib:assembleRelease`任务来实现：

```kt
Example32-Library raimon$ ./gradlew lib:assembleRelease 
```

我们可以在项目的`lib/build/outputs/aar/lib-release.aar`文件夹中获取`.aar`文件。使用`lib:assembleDebug`任务，我们将生成调试库，或者简单地使用`lib:assembleDebug`来获取调试和发布版本。

你可以以任何你喜欢的方式发布二进制文件，但一个建议是上传到构件平台。许多公司都在使用内部构件或软件仓库来存储企业库和一般的构件，但如果你想要向更广泛的公众开放，你可以上传到例如`JCenter`。如果我们检查任何 Android 项目中的最顶层的`build.gradle`文件，我们会看到有一个依赖于`JCenter`来查找库的依赖项：

```kt
... 
repositories {
    jcenter()
}
```

我们可以通过 Bintray 轻松完成此操作，例如：[`bintray.com`](https://bintray.com)。注册后，我们可以创建项目，从 GitHub 导入它们，创建发布和版本，如果我们的项目被接受，甚至可以发布到`JCenter`。

要获取有关 Bintray gradle 插件的更多信息，请访问：

[关于 bintray 的 gradle 插件更多信息](https://github.com/bintray/gradle-bintray-plugin#readme)。

为了简化我们的工作，有一些开源示例和代码可以使这个过程变得简单得多。但首先，让我们在 Bintray 上创建一个仓库。

我们将其命名为`AndroidCustomView`，将其设置为 Maven 仓库，并添加默认的 Apache 2.0 许可证：

![图片](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/4395fe16-075f-408a-82c0-4399e53c9837.png)

拥有了它之后，我们可以创建版本，或者直接从我们的 gradle 构建脚本中添加。为此，我们必须向最顶层的`build.gradle`添加一些依赖项：

```kt
buildscript {
    repositories {
        jcenter()
    }

    dependencies {
        classpath'com.android.tools.build:gradle:2.3.0'
        classpath'com.jfrog.bintray.gradle:gradle-bintrayplugin:1.4'classpath'com.github.dcendents:android-maven-gradleplugin:1.4.1'
    }
}
```

现在我们可以利用一些已经创建的开源 gradle 构建脚本。我们不需要复制粘贴或向我们的构建脚本中添加更多代码，可以直接从 GitHub 应用它。让我们在库`build.gradle`文件的最后添加这两行：

```kt
... 
apply from: 'https://raw.githubusercontent.com/nuuneoi/JCenter/master/installv1.gra
 dle' 
apply from: 'https://raw.githubusercontent.com/nuuneoi/JCenter/master/bintrayv1.gra
 dle' 

```

应用了这两个 gradle 构建脚本之后，我们最终会得到一个额外的任务：`bintrayUpload`。我们需要首先添加构件配置，所以在库模块`build.gradle`文件的 apply 库行后面最前面添加它：

```kt
apply plugin: 'com.android.library'

ext {
    bintrayRepo = 'AndroidCustomView'
    bintrayName = 'androidcustomview'
    publishedGroupId = 'com.rrafols.packt'
    libraryName = 'AndroidCustomView'
    artifact = 'androidcustomview'
    libraryDescription = 'Uploading libraries example.'
    siteUrl = 'https://github.com/rrafols/AndroidCustomView'
    gitUrl = 'https://github.com/rrafols/androidcustomview.git'
    libraryVersion = '1.0.0'
    developerId = 'rrafols'
    developerName = 'Raimon Ràfols'
    developerEmail = ''
    licenseName = 'The Apache Software License, Version 2.0'
    licenseUrl = 'http://www.apache.org/licenses/LICENSE-2.0.txt'
    allLicenses = ["Apache-2.0"]
}
```

我们需要将 Bintray 用户和 API 密钥信息添加到我们的`local.properties`文件中：

```kt
bintray.user=rrafols 
bintray.apikey=<key - can be retrieved from the edit profile option on bintray.com> 
```

`bintrayRepo`变量必须与我们要存储二进制文件的仓库相匹配，否则构建脚本将失败。

现在我们已经完成了所有配置，我们可以使用`./gradlew` install 构建库的新版本，并使用`./gradlew bintrayUpload`上传到 Bintray。

请记住，版本一旦被上传后就是只读的，因此我们将无法覆盖它们，除非我们更新版本号并上传不同的版本，否则在执行我们的 gradle 脚本时将会出现错误。

一旦我们上传了一个版本，我们将看到类似下面的屏幕：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/7cdbb2cd-2346-4235-b885-0407f7fcecb4.png)

我们还可以检查已上传版本中的文件，以了解已上传了哪些内容。如果我们进入某个版本，并点击文件菜单，我们会看到`.aar`的 Android 库文件以及脚本为我们上传的所有其他文件。

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/f3eb44c2-92da-4150-b9ad-e965e72d1f53.png)

如我们所见，它还打包并上传了源代码、`Javadoc`并创建了一个`.pom`文件，因为它是作为 Maven 仓库托管的。

完成所有这些步骤后，我们可以直接从构件仓库页面通过点击添加到 JCenter 将库上传到`JCenter`。一旦获得批准，任何想要使用我们库的人只需在`com.rrafols.packt.androidcustomview`上定义一个依赖项，就可以直接从`JCenter`获取。

要了解关于这个过程以及这些 gradle 构建脚本的作者更多信息，请访问：

[`inthecheesefactory.com/blog/how-to-upload-library-to-jcenter-maven-central-as-dependency/en`](https://inthecheesefactory.com/blog/how-to-upload-library-to-jcenter-maven-central-as-dependency/en)。

我们还没有提到但同样重要的是，如何对我们的库进行版本控制。每当我们创建一个新的发布版本时，都会创建一个版本号。强烈建议在为自定义视图版本控制时使用语义版本`MAJOR.MINOR.PATCH`。这样我们可以轻松地指示一个版本中的更改是否引入了不兼容性。例如，使用语义版本控制，如果我们更改了主要版本号，就表示我们引入了与先前版本的不兼容性；或者通过更改次要版本号，表示我们添加了新功能但没有引入任何不兼容性。这对于使用我们库的第三方或其他开发人员来说非常重要，这样他们可以知道从一个版本到下一个版本应该期待什么。

若要了解更多关于语义版本控制的信息，请访问：

[`semver.org/`](http://semver.org/)。

也请查看此示例的完整源代码，位于 GitHub 仓库中的`Example32-Library`文件夹。

# 摘要

在本章中，我们了解了分享我们的自定义视图的建议以及如何实际操作。开源我们的自定义视图或在公司内部分享它们有很多好处。我们不仅会更关注质量和细节，而且还将促进合作并丰富 Android 开发者社区。

在接下来的章节中，我们将学习如何把我们最近几章所涵盖的所有信息综合起来，构建一些更复杂的自定义视图，以便在我们的应用程序中直接使用和包含。


# 第九章：实现你自己的电子节目指南（EPG）

到目前为止，我们一直在构建一些非常基础的示例，以展示 Android 为我们提供的实现和绘制自定义视图的功能和方法。在本章中，我们将看到一个更复杂的自定义视图示例。我们将构建一个**电子节目指南**（**EPG**）。

EPG 是一个相当复杂的组件，如果构建不当，可能会影响用户体验。例如，如果它性能不佳，使用起来会感觉迟缓和繁琐。

我们将使用我们在前面章节中已经介绍过的几件事情。所有这些可能会有些多，但我们会一步一步地构建它，并且会更详细地介绍：

+   如何构建一个基本的 EPG 自定义视图

+   如何添加基本的动画和交互

+   如何允许缩放

+   使其可配置

# 构建 EPG

如果我们想让我们的 EPG 更有用，它应该能同时显示多个频道，以及当前和未来的电视节目。同时，清晰地看到当前正在播放的内容，并有明确的指示其他电视节目的开始和结束时间会很好。

在这个特定的组件中，我们将选择一种涵盖这些点的渲染方法。你可以把它作为一个例子，但还有许多其他方式来渲染同类的信息。同时，它不会连接到一个提供 EPG 数据的后端服务。所有的 EPG 数据都将被模拟，但可以轻松连接到任何服务，尽管可能需要进行一些更改。

# EPG 基础和动画设置

我们将从创建一个扩展视图的类开始。在其`onDraw()`方法中，我们将绘制以下部分：

+   视图背景

+   包含所有频道和电视节目的 EPG 主体

+   一个顶部的时间条提示时间

+   一条垂直线表示当前时间

如果我们有一些变量动画，我们还需要触发重绘周期。

所以，让我们开始实现这个`onDraw()`方法，并且一步一步地按照方法进行：

```kt
@Override 
protected void onDraw(Canvas canvas) { 
   animateLogic(); 

   long currentTime = System.currentTimeMillis(); 

   drawBackground(canvas); 
   drawEPGBody(canvas, currentTime, frScrollY); 
   drawTimeBar(canvas, currentTime); 
   drawCurrentTime(canvas, currentTime); 

   if (missingAnimations()) invalidate(); 
} 

```

最容易实现的方法将是`drawBackground()`：

```kt
private static final int BACKGROUND_COLOR = 0xFF333333; 
private void drawBackground(Canvas canvas) { 
    canvas.drawARGB(BACKGROUND_COLOR >> 24,  
            (BACKGROUND_COLOR >> 16) & 0xff, 
            (BACKGROUND_COLOR >> 8) & 0xff,  
            BACKGROUND_COLOR & 0xff); 
} 
```

在这个例子中，我们定义了一个背景颜色为`0xFF333333`，这是一种深灰色，我们只是用`drawARGB()`调用填充整个屏幕，遮罩和移动颜色组件。

现在，让我们来看看`drawTimeBar()`方法：

```kt
private void drawTimeBar(Canvas canvas, long currentTime) { 
    calendar.setTimeInMillis(initialTimeValue - 120 * 60 * 1000); 
    calendar.set(Calendar.MINUTE, 0); 
    calendar.set(Calendar.SECOND, 0); 
    calendar.set(Calendar.MILLISECOND, 0); 

    long time = calendar.getTimeInMillis(); 
    float x = getTimeHorizontalPosition(time) - frScrollX + getWidth()
             / 4.f; 

    while (x < getWidth()) { 
        if (x > 0) { 
            canvas.drawLine(x, 0, x, timebarHeight, paintTimeBar); 
        } 

        if (x + timeBarTextBoundaries.width() > 0) { 
            SimpleDateFormat dateFormatter = 
                    new SimpleDateFormat("HH:mm", Locale.US); 

            String date = dateFormatter.format(new Date(time)); 
            canvas.drawText(date, 
                    x + programMargin, 
                    (timebarHeight - timeBarTextBoundaries.height()) /
                    2.f + timeBarTextBoundaries.height(),paintTimeBar); 
        } 

        time += 30 * 60 * 1000; 
        x = getTimeHorizontalPosition(time) - frScrollX + getWidth() /
            4.f; 
    } 

    canvas.drawLine(0, 
            timebarHeight, 
            getWidth(), 
            timebarHeight, 
            paintTimeBar); 
} 
```

让我们解释一下这个方法的作用：

1.  首先，我们得到了我们想要开始绘制时间标记的初始时间：

```kt
calendar.setTimeInMillis(initialTimeValue - 120 * 60 * 1000); 
calendar.set(Calendar.MINUTE, 0); 
calendar.set(Calendar.SECOND, 0); 
calendar.set(Calendar.MILLISECOND, 0); 

long time = calendar.getTimeInMillis();  
```

我们在我们的类构造函数中定义了`initialTimeValue`，设置为当前时间后半小时。我们还移除了分钟、秒和毫秒，因为我们要指示每个小时的整点和半小时，例如：9.00, 9.30, 10.00, 10.30，等等。

然后，我们创建了一个辅助方法，根据时间戳获取屏幕位置，这将在代码中的许多其他地方使用：

```kt
private float getTimeHorizontalPosition(long ts) { 
    long timeDifference = (ts - initialTimeValue); 
    return timeDifference * timeScale; 
} 
```

1.  此外，我们需要根据设备屏幕密度计算一个时间刻度。为了计算它，我们定义了一个默认的时间刻度：

```kt
private static final float DEFAULT_TIME_SCALE = 0.0001f;  
```

1.  在类构造函数中，我们根据屏幕密度调整了时间刻度：

```kt
final float screenDensity = getResources().getDisplayMetrics().density; 
timeScale = DEFAULT_TIME_SCALE * screenDensity;  
```

我们知道有许多不同屏幕大小和密度的 Android 设备。这种方式，而不是硬编码像素尺寸，使得渲染在所有设备上尽可能接近。

在此方法的帮助下，我们可以轻松地循环处理半小时的块，直到达到屏幕末端。

```kt
float x = getTimeHorizontalPosition(time) - frScrollX + getWidth() / 4.f; 
while (x < getWidth()) { 

    ... 

    time += 30 * 60 * 1000; // 30 minutes 
    x = getTimeHorizontalPosition(time) - frScrollX + getWidth() / 4.f; 
} 

```

通过将 `30` 分钟（转换为毫秒）加到时间变量上，我们可以以 `30` 分钟的块来递增水平标记。

我们也考虑了 `frScrollX` 的位置。当我们添加允许滚动的交互时，这个变量将被更新，但我们在本章后面会看到这一点。

渲染非常直接：只要 `x` 坐标在屏幕内，我们就绘制一条垂直线：

```kt
if (x > 0) { 
    canvas.drawLine(x, 0, x, timebarHeight, paintTimeBar); 
} 

```

我们以 `HH:mm` 格式绘制时间，就在旁边：

```kt
SimpleDateFormat dateFormatter = new SimpleDateFormat("HH:mm", Locale.US); 
String date = dateFormatter.format(new Date(time)); 
canvas.drawText(date, 
        x + programMargin, 
        (timebarHeight - timeBarTextBoundaries.height()) / 2.f 
                + timeBarTextBoundaries.height(), paintTimeBar); 

```

我们可以做的性能改进之一是存储字符串，这样我们就无需一次又一次地调用格式化方法，避免昂贵的对象创建。我们可以通过创建一个以长整型变量作为键并返回字符串的 **HashMap** 来实现这一点：

```kt
String date = null; 
if (dateFormatted.containsKey(time)) { 
    date = dateFormatted.get(time); 
} else { 
    date = dateFormatter.format(new Date(time)); 
    dateFormatted.put(time, date); 
} 

```

如果我们已经有了格式化的日期，我们就使用它；如果这是第一次，我们先格式化并将其存储在 HashMap 中。

现在我们可以继续绘制当前时间指示器。这非常简单；它只是一个比单条线稍宽的垂直框，因此我们使用 `drawRect()` 而不是 `drawLine()`：

```kt
private void drawCurrentTime(Canvas canvas, long currentTime) { 
    float currentTimePos = frChNameWidth +
    getTimeHorizontalPosition(currentTime) - frScrollX; 
    canvas.drawRect(currentTimePos - programMargin/2, 
            0, 
            currentTimePos + programMargin/2, 
            timebarHeight, 
            paintCurrentTime); 

    canvas.clipRect(frChNameWidth, 0, getWidth(), getHeight()); 
    canvas.drawRect(currentTimePos - programMargin/2, 
            timebarHeight, 
            currentTimePos + programMargin/2, 
            getHeight(), 
            paintCurrentTime); 
} 

```

由于我们已经有了 `getTimeHorizontalPosition` 方法，我们可以轻松地确定绘制当前时间指示器的位置。由于我们将滚动浏览电视节目，因此我们将绘制分为两部分：一部分在时间条上绘制线条，不进行任何剪辑；另一部分从时间条末端到屏幕底部绘制线条。在后者中，我们应用剪辑，使其只绘制在电视节目上方。

为了更清楚地理解这一点，让我们看一下结果的截图：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/34906304-fb28-4b26-8542-22944465d9ae.png)

在左侧，我们有表示频道的图标，顶部是时间条，其余部分是包含不同电视节目的电子节目指南（EPG）主体。我们希望避免当前时间线（红色）覆盖频道图标，因此我们应用了刚才提到的剪辑。

最后，我们可以实现整个 EPG 主体绘制。这比其他方法要复杂一些，因此让我们一步一步来。首先，我们需要计算要绘制的频道数量，以避免进行不必要的计算和试图在屏幕外绘制：

```kt
int startChannel = (int) (frScrollY / channelHeight); 
verticalOffset -= startChannel * channelHeight; 
int endChannel = startChannel + (int) ((getHeight() -  timebarHeight) / channelHeight) + 1; 
if (endChannel >= channelList.length) endChannel = channelList.length - 1; 
```

与时间刻度一样，我们也定义了一个默认的频道高度，并根据屏幕密度来计算它：

```kt
private static final int CHANNEL_HEIGHT = 80; 
... 
channelHeight = CHANNEL_HEIGHT * screenDensity; 

```

现在我们知道了需要绘制的初始频道和结束频道，我们可以概述绘制循环：

```kt
canvas.save(); 
canvas.clipRect(0, timebarHeight, getWidth(), getHeight()); 

for (int i = startChannel; i <= endChannel; i++) { 
    float channelTop = (i - startChannel) * channelHeight -
    verticalOffset +
    timebarHeight; 
    float channelBottom = channelTop + channelHeight; 

    ... 

} 

canvas.drawLine(frChNameWidth, timebarHeight, frChNameWidth, getHeight(), paintChannelText); 
canvas.restore(); 

```

我们将多次修改`canvas`的剪辑区域，因此让我们在方法开始时保存它，在结束时恢复它。这样我们就不会影响在此之后完成的任何其他绘图方法。在循环内，对于每个频道，我们还需要计算`channelTop`和`channelBottom`值，因为稍后在绘制时会很有用。这些值表示我们正在绘制的频道的顶部和底部的垂直坐标。

现在让我们为每个频道绘制图标，如果我们没有图标，首先从互联网上请求。我们将使用`Picasso`来管理互联网请求，但我们也可以使用任何其他库：

```kt
if (channelList[i].getIcon() != null) { 
    float iconMargin = (channelHeight -
    channelList[i].getIcon().getHeight()) / 2;

    canvas.drawBitmap(channelList[i].getIcon(), iconMargin, channelTop
    + iconMargin, null); 

} else { 
    if (channelTargets[i] == null) { 
        channelTargets[i] = new ChannelIconTarget(channelList[i]); 
    } 

    Picasso.with(context) 
            .load(channelList[i] 
            .getIconUrl()) 
            .into(channelTargets[i]); 
} 
```

关于毕加索的信息可以在以下链接找到：

[`square.github.io/picasso/`](http://square.github.io/picasso/)。

同时，对于每个频道，我们需要绘制屏幕内的电视节目。再次，让我们使用之前创建的方法将时间戳转换为屏幕坐标：

```kt
for (int j = 0; j < programs.size(); j++) { 
    Program program = programs.get(j); 

    long st = program.getStartTime(); 
    long et = program.getEndTime(); 

    float programStartX = getTimeHorizontalPosition(st); 
    float programEndX = getTimeHorizontalPosition(et); 

    if (programStartX - frScrollX > getWidth()) break; 
    if (programEndX - frScrollX >= 0) { 

        ... 

    } 
} 
```

在这里，我们从程序的开始和结束时间获取程序的开始和结束位置。如果开始位置超出了屏幕宽度，我们可以停止检查更多的电视节目，因为它们都将位于屏幕外，假设电视节目是按时间升序排序的。同样，如果结束位置小于 0，我们可以跳过这个特定的电视节目，因为它也将被绘制在屏幕外。

实际的绘制相当简单；我们使用`drawRoundRect`来绘制电视节目的背景，并在其上居中绘制节目名称。我们还剪辑了该区域，以防名称比电视节目框长：

```kt
canvas.drawRoundRect(horizontalOffset + programMargin + programStartX, 
       channelTop + programMargin, 
       horizontalOffset - programMargin + programEndX, 
       channelBottom - programMargin, 
       programMargin, 
       programMargin, 
       paintProgram); 

canvas.save(); 
canvas.clipRect(horizontalOffset + programMargin * 2 + programStartX, 
       channelTop + programMargin, 
       horizontalOffset - programMargin * 2 + programEndX, 
       channelBottom - programMargin); 

paintProgramText.getTextBounds(program.getName(), 0, program.getName().length(), textBoundaries); 
float textPosition = channelTop + textBoundaries.height() + ((channelHeight - programMargin * 2) - textBoundaries.height()) / 2; 
canvas.drawText(program.getName(), 
           horizontalOffset + programMargin * 2 + programStartX, 
           textPosition, 
           paintProgramText); 
canvas.restore(); 

```

我们还增加了一个小检查，以确定电视节目是否正在播放。如果当前时间大于或等于节目开始时间，并且小于结束时间，我们可以得出结论，电视节目目前正在播放，并用高亮颜色渲染它。

```kt
if (st <= currentTime && et > currentTime) { 
    paintProgram.setColor(HIGHLIGHTED_PROGRAM_COLOR); 
    paintProgramText.setColor(Color.BLACK); 
} else { 
    paintProgram.setColor(PROGRAM_COLOR); 
    paintProgramText.setColor(Color.WHITE); 
} 

```

现在让我们添加动画周期。在这个例子中，我们选择了固定时间步长机制。我们只对滚动变量进行动画处理，包括水平和垂直的滚动以及屏幕中频道部分的运动：

```kt
private void animateLogic() { 
    long currentTime = SystemClock.elapsedRealtime(); 
    accTime += currentTime - timeStart; 
    timeStart = currentTime; 

    while (accTime > TIME_THRESHOLD) { 
        scrollX += (scrollXTarget - scrollX) / 4.f; 
        scrollY += (scrollYTarget - scrollY) / 4.f; 
        chNameWidth += (chNameWidthTarget - chNameWidth) / 4.f; 
        accTime -= TIME_THRESHOLD; 
    } 

    float factor = ((float) accTime) / TIME_THRESHOLD; 
    float nextScrollX = scrollX + (scrollXTarget - scrollX) / 4.f; 
    float nextScrollY = scrollY + (scrollYTarget - scrollY) / 4.f; 
    float nextChNameWidth = chNameWidth + (chNameWidthTarget -
                            chNameWidth) / 4.f; 

    frScrollX = scrollX * (1.f - factor) + nextScrollX * factor; 
    frScrollY = scrollY * (1.f - factor) + nextScrollY * factor; 
    frChNameWidth = chNameWidth * (1.f - factor) + nextChNameWidth *
    factor; 
} 

```

在我们后面的渲染和计算中，我们将使用`frScrollX`、`frScrollY`和`frChNameWidth`变量，它们包含了当前逻辑刻度与下一个逻辑刻度之间的分数部分。

我们将在下一节讨论向电子节目指南添加交互时看到如何滚动，但我们刚刚引入了频道部分的移动。现在，我们只是将每个频道渲染为一个图标，但是为了获取更多信息，我们添加了一个切换功能，使当前有图标的频道框变得更大，并在图标旁边绘制频道标题。

我们创建了一个布尔开关来跟踪我们正在渲染的状态，并在需要时绘制频道名称：

```kt
if (!shortChannelMode) { 
    paintChannelText.getTextBounds(channelList[i].getName(), 
            0, 
            channelList[i].getName().length(), 
            textBoundaries); 

    canvas.drawText(channelList[i].getName(), 
            channelHeight - programMargin * 2, 
            (channelHeight - textBoundaries.height()) / 2 +
             textBoundaries.height() + channelTop, 
            paintChannelText); 
} 

```

切换非常简单，因为它只是将频道框宽度目标更改为`channelHeight`，这样它就会有正方形的尺寸，或者在绘制文本时是`channelHeight`的两倍。动画周期将负责动画化这个变量：

```kt
if (shortChannelMode) { 
    chNameWidthTarget = channelHeight * 2; 
    shortChannelMode = false; 
} else { 
    chNameWidthTarget = channelHeight; 
    shortChannelMode = true; 
}  
```

# 交互

到目前为止，这并不是很有用，因为我们不能与它互动。要添加交互，我们需要从 View 中重写`onTouchEvent()`方法，正如我们在前面的章节中看到的。

在我们自己的`onTouchEvent`实现中，我们主要对`ACTION_DOWN`、`ACTION_UP`和`ACTION_MOVE`事件感兴趣。让我们看看我们已经完成的实现：

```kt
private float dragX; 
private float dragY; 
private boolean dragged; 

... 

@Override 
public boolean onTouchEvent(MotionEvent event) { 

    switch(event.getAction()) { 
        case MotionEvent.ACTION_DOWN: 
            dragX = event.getX(); 
            dragY = event.getY(); 

            getParent().requestDisallowInterceptTouchEvent(true); 
            dragged = false; 
            return true; 

        case MotionEvent.ACTION_UP: 
            if (!dragged) { 
                // touching inside the channel area, will toggle
                   large/short channels 
                if (event.getX() < frChNameWidth) { 
                    switchNameWidth = true; 
                    invalidate(); 
                } 
            } 

            getParent().requestDisallowInterceptTouchEvent(false); 
            return true; 

        case MotionEvent.ACTION_MOVE: 
            float newX = event.getX(); 
            float newY = event.getY(); 

            scrollScreen(dragX - newX, dragY - newY); 

            dragX = newX; 
            dragY = newY; 
            dragged = true; 
            return true; 
        default: 
            return false; 
    } 
} 

```

这个方法并没有太多逻辑；它只是在检查我们是否在屏幕上拖动，用上一次事件的拖动量差值来调用`scrollScreen`方法，并且，在只是点击频道框而没有拖动的情况下，触发切换以使频道框变大或变小。

`scrollScreen`方法简单地更新`scrollXTarget`和`scrollYTarget`并检查其边界：

```kt
private void scrollScreen(float dx, float dy) { 
    scrollXTarget += dx; 
    scrollYTarget += dy; 

    if (scrollXTarget < -chNameWidth) scrollXTarget = -chNameWidth; 
    if (scrollYTarget < 0) scrollYTarget = 0; 

    float maxHeight = channelList.length * channelHeight - getHeight()
    + 1 + timebarHeight; 
    if (scrollYTarget > maxHeight) scrollYTarget = maxHeight; 

    invalidate(); 
} 
```

同时，调用`invalidate`以触发重绘事件非常重要。在`onDraw()`事件本身中，我们检查所有动画是否完成，如果需要，则触发更多的重绘事件：

```kt
if (missingAnimations()) invalidate(); 
```

`missingAnimations`的实际实现非常直接：

```kt
private static final float ANIM_THRESHOLD = 0.01f; 

private boolean missingAnimations() { 
    if (Math.abs(scrollXTarget - scrollX) > ANIM_THRESHOLD) 
    return true;

if (Math.abs(scrollYTarget - scrollY) > ANIM_THRESHOLD)
    return true;

if (Math.abs(chNameWidthTarget - chNameWidth) > ANIM_THRESHOLD)
    return true;

return false;
} 
```

我们只是检查所有可以动画的属性，如果它们与目标值的差小于预定义的阈值。如果只有一个大于这个阈值，我们需要触发更多的重绘事件和动画周期。

# 缩放

由于我们为每个电视节目渲染一个盒子，其大小直接由电视节目持续时间决定，可能会出现电视节目标题比其渲染的盒子大的情况。在这些情况下，我们可能想要阅读标题的更多部分，或者在其它时候，我们可能想要稍微压缩一下，以便我们可以了解那天稍后电视上会有什么节目。

为了解决这个问题，我们可以在我们的 EPG 小部件上通过在设备屏幕上捏合来实现缩放机制。我们可以将这种缩放直接应用到`timeScale`变量上，并且由于我们在所有计算中都使用了它，它将保持一切同步：

```kt
scaleDetector = new ScaleGestureDetector(context,  
    new ScaleGestureDetector.SimpleOnScaleGestureListener() {  

    ... 

    }); 

```

为了简化，我们使用`SimpleOnScaleGestureListener`，它允许我们只重写我们想要使用的方法。

现在，我们需要修改`onTouchEvent`，让`scaleDetector`实例也处理这个事件：

```kt
@Override 
public boolean onTouchEvent(MotionEvent event) { 
    scaleDetector.onTouchEvent(event); 

    if (zooming) { 
        zooming = false; 
        return true; 
    } 

    ... 

} 

```

我们还添加了一个检查，看看我们是否正在缩放。我们将在`ScaleDetector`实现中更新这个变量，但概念是避免在正在缩放时滚动视图或处理拖动事件。

现在让我们实现`ScaleDetector`：

```kt
scaleDetector = new ScaleGestureDetector(context, new ScaleGestureDetector.SimpleOnScaleGestureListener() { 
    private long focusTime; 
    private float scrollCorrection = 0.f; 
    @Override 
    public boolean onScaleBegin(ScaleGestureDetector detector) { 
        zooming = true; 
        focusTime = getHorizontalPositionTime(scrollXTarget +
        detector.getFocusX() - frChNameWidth); 
        scrollCorrection = getTimeHorizontalPosition((focusTime)) -
        scrollXTarget; 
        return true; 
    } 

    public boolean onScale(ScaleGestureDetector detector) { 
        timeScale *= detector.getScaleFactor(); 
        timeScale = Math.max(DEFAULT_TIME_SCALE * screenDensity / 2,  
                        Math.min(timeScale, DEFAULT_TIME_SCALE *
                        screenDensity * 4)); 

        // correct scroll position otherwise will move too much when
           zooming 
        float current = getTimeHorizontalPosition((focusTime)) -
        scrollXTarget; 
        float scrollDifference = current - scrollCorrection; 
        scrollXTarget += scrollDifference; 
        zooming = true; 

        invalidate(); 
        return true; 
    } 

    @Override 
    public void onScaleEnd(ScaleGestureDetector detector) { 
        zooming = true; 
    } 
}); 

```

我们基本上在做两件事情。首先，我们将`timeScale`变量从默认值的一半调整到默认值的四倍：

```kt
timeScale *= detector.getScaleFactor(); 
timeScale = Math.max(DEFAULT_TIME_SCALE * screenDensity / 2,  
                Math.min(timeScale, DEFAULT_TIME_SCALE * screenDensity
                * 4)); 
```

同时，我们调整滚动位置以避免缩放时的不良效果。通过调整滚动位置，我们试图保持捏合焦点的位置不变，即使放大或缩小后也是如此。

```kt
float current = getTimeHorizontalPosition((focusTime)) - scrollXTarget; 
float scrollDifference = current - scrollCorrection; 
scrollXTarget += scrollDifference; 

```

有关`ScaleDetector`和手势的更多信息，请查看官方 Android 文档。

# 配置和扩展

如果你想创建一个可供多人使用的自定义视图，它需要是可定制的。电子节目指南（EPG）也不例外。在我们的初步实现中，我们硬编码了一些颜色和值，但让我们看看如何扩展这些功能，使我们的 EPG 可自定义。

# 使其可配置

在本书的初始章节中，我们介绍了如何添加参数，这样就可以轻松自定义我们的自定义视图。遵循同样的原则，我们创建了一个`attrs.xml`文件，其中包含了所有可自定义的参数：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<resources> 
    <declare-styleable name="EPG"> 
        <attr name="backgroundColor" format="color"/> 
        <attr name="programColor" format="color"/> 
        <attr name="highlightedProgramColor" format="color"/> 
        <attr name="currentTimeColor" format="color"/> 
        <attr name="channelTextColor" format="color"/> 
        <attr name="programTextColor" format="color"/> 
        <attr name="highlightedProgramTextColor" format="color"/> 
        <attr name="timeBarColor" format="color"/> 

        <attr name="channelHeight" format="float"/> 
        <attr name="programMargin" format="float"/> 
        <attr name="timebarHeight" format="float"/> 
    </declare-styleable> 
</resources> 
```

可以添加许多其他变量作为参数，但从自定义视图的外观和感觉角度来看，这些是主要的自定义功能。

在我们的类构造函数中，我们还添加了读取和解析这些参数的代码。在它们不存在的情况下，我们会默认使用我们之前硬编码的值。

```kt
TypedArray ta = context.getTheme().obtainStyledAttributes(attrs, R.styleable.EPG, 0, 0); 
try { 
    backgroundColor = ta.getColor(R.styleable.EPG_backgroundColor,
    BACKGROUND_COLOR); 
    paintChannelText.setColor(ta.getColor(R.styleable.EPG_channelTextColor
                          Color.WHITE)); 
    paintCurrentTime.setColor(ta.getColor(R.styleable.EPG_currentTimeColor,
                          CURRENT_TIME_COLOR)); 
    paintTimeBar.setColor(ta.getColor(R.styleable.EPG_timeBarColor,
                          Color.WHITE)); 

    highlightedProgramColor =
    ta.getColor(R.styleable.EPG_highlightedProgramColor,
        HIGHLIGHTED_PROGRAM_COLOR);

    programColor = ta.getColor(R.styleable.EPG_programColor,
    PROGRAM_COLOR);

    channelHeight = ta.getFloat(R.styleable.EPG_channelHeight,
    CHANNEL_HEIGHT) * screenDensity;

    programMargin = ta.getFloat(R.styleable.EPG_programMargin,
    PROGRAM_MARGIN) * screenDensity;

    timebarHeight = ta.getFloat(R.styleable.EPG_timebarHeight,
    TIMEBAR_HEIGHT) * screenDensity;

    programTextColor = ta.getColor(R.styleable.EPG_programTextColor,
    Color.WHITE);

    highlightedProgramTextColor =
    ta.getColor(R.styleable.EPG_highlightedProgramTextColor,
        Color.BLACK);
} finally { 
    ta.recycle(); 
} 
```

为了让任何尝试自定义它的人更简单、更清晰，我们可以进行一个小改动。让我们将直接映射到像素大小的参数重新定义为尺寸，而不是浮点数：

```kt
<attr name="channelHeight" format="dimension"/> 
<attr name="programMargin" format="dimension"/> 
<attr name="timebarHeight" format="dimension"/> 
```

将解析代码更新为以下内容：

```kt
channelHeight = ta.getDimension(R.styleable.EPG_channelHeight, 
        CHANNEL_HEIGHT * screenDensity); 

programMargin = ta.getDimension(R.styleable.EPG_programMargin, 
        PROGRAM_MARGIN * screenDensity); 

timebarHeight = ta.getDimension(R.styleable.EPG_timebarHeight, 
        TIMEBAR_HEIGHT * screenDensity); 
```

使用`getDimension`而不是`getFloat`，它会自动将设置为密度像素的尺寸转换为实际像素。它不会对默认值进行这种转换，因此我们仍然需要自己乘以`screenDensity`。

最后，我们需要在`activity_main.xml`布局文件中添加这些配置：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<LinearLayout  

    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
tools:context="com.rrafols.packt.epg.MainActivity"> 

    <com.rrafols.packt.epg.EPG 
        android:id="@+id/epg_view" 
        android:layout_width="match_parent" 
        android:layout_height="match_parent" 
        app:channelHeight="80dp"
        app:highlightedProgramColor="#ffffdd20"
        app:highlightedProgramTextColor="#ff000000"/>
</LinearLayout>  
```

我们可以在以下屏幕截图中看到这些更改的结果：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/522de8ec-8446-4814-a103-40d84612f4ba.png)

# 实现回调

我们还没有介绍 EPG 的另一个关键功能，即点击电视节目时实际执行某些操作的能力。如果我们想用我们的 EPG 做一些有用的事情，而不仅仅是展示即将到来的标题，我们必须实现这个功能。

这个实现相当直接，将处理逻辑传递给外部监听器或回调。修改源代码以在 EPG 本身上实现一些自定义行为也相对容易。

首先，我们在 EPG 类中创建一个新的接口，带有一个单一的方法：

```kt
interface EPGCallback { 
    void programClicked(Channel channel, Program program); 
} 

```

每当我们点击电视节目时，都会调用这个方法，实现这个回调的任何人都会同时获得`Channel`和电视`Program`。

现在，让我们修改`onTouchEvent()`方法以处理这个新功能：

```kt
if (event.getX() < frChNameWidth) { 

    ... 

} else { 
    clickProgram(event.getX(), event.getY()); 
} 

```

在我们之前的代码中，我们只检查是否点击了屏幕的频道区域。现在我们可以使用另一个区域来检测我们是否点击了电视节目内部。

现在让我们实现`clickProgram()`方法：

```kt
private void clickProgram(float x, float y) { 
    long ts = getHorizontalPositionTime(scrollXTarget + x -
    frChNameWidth); 
    int channel = (int) ((y + frScrollY - timebarHeight) / 
    channelHeight); 

    ArrayList<Program> programs = channelList[channel].getPrograms(); 
    for (int i = 0; i < programs.size(); i++) { 
        Program pr = programs.get(i); 
        if (ts >= pr.getStartTime() && ts < pr.getEndTime()) { 
            if (callback != null) { 
                callback.programClicked(channelList[channel], pr); 
            } 
            break; 
        } 
    } 
}  
```

我们首先将用户点击的水平位置转换成时间戳，结合触摸事件的垂直位置，我们可以确定频道。有了频道和时间戳，我们就可以检查用户点击了哪个节目，并带着这些信息调用回调函数。

在 GitHub 示例中，我们添加了一个虚拟的监听器，它只记录被点击的频道和节目：

```kt
@Override 
protected void onCreate(Bundle savedInstanceState) { 
    super.onCreate(savedInstanceState); 
    setContentView(R.layout.activity_main); 

    EPG epg = (EPG) findViewById(R.id.epg_view); 
    epg.setCallback(new EPG.EPGCallback() { 
        @Override 
        public void programClicked(Channel channel, Program program) { 
            Log.d("EPG", "program clicked: " + program.getName() + "
            channel: " + channel.getName()); 
        } 
    }); 

    populateDummyChannelList(epg); 
} 

```

在这个 Activity 的`onCreate`中还有一个`populateDummyChannelList()`方法。这个方法只会填充随机的频道和电视节目数据，如果与真实的电子节目指南（EPG）数据提供者连接，应该移除这个方法。

整个示例可以在 GitHub 仓库的`Example33-EPG`文件夹中找到。

# 总结

在本章中，我们了解了如何构建一个具有许多功能的简单 EPG，但我们可能还留下许多其他功能没有实现。例如，我们的电视节目渲染相当简单，我们可以在电视节目框中添加更多信息，比如持续时间、开始时间和结束时间，甚至可以直接显示电视节目描述。

请随意使用 GitHub 仓库中的内容，进行操作、添加新的自定义或功能，并根据您的需要进行调整。

我们并没有特别讨论性能问题，但我们尽可能减少了`onDraw`方法及其调用方法中的内存分配数量，并尽可能减少了屏幕上的绘制内容，甚至不处理那些将落在屏幕边界之外的元素。

如果我们希望自定义视图（在这个案例中是 EPG）能够快速响应、伸缩以适应更多频道和电视节目，那么考虑这些细节是至关重要的。

在下一章中，我们将构建另一个复杂的自定义视图，可以用它在我们的 Android 应用程序上绘制图表。


# 第十章：构建图表组件

在上一章中，我们了解到如何构建一个复杂的自定义视图，它融合了本书所介绍的所有内容。它包括一些渲染代码，使用第三方库，具有触摸交互和动画效果，并且我们简要讨论了性能考量。这是一个相当完整自定义视图的例子，但它并非唯一。在本章中，我们将构建另一个复杂自定义视图。逐步地，我们将构建一个图表自定义视图，用以绘制可以嵌入到我们的 Android 应用程序中的图形。我们将从构建一个非常基础的实施开始，并在途中添加额外的功能和功能性。更详细地说，我们将了解以下内容：

+   构建一个基础图表组件

+   如何考虑边距和填充

+   使用路径改善渲染

+   更新和扩展我们的数据集

+   增加额外的特性和自定义

# 构建一个基础的图表自定义视图

在 Android 应用程序中，我们可能需要在某个时刻绘制一些图表。它可以是静态图表，这并不那么有趣，因为它可以被简单地替换为图像，也可以是动态图表，允许用户交互和对数据变化的反应。最后一种情况是我们可以使用自定义视图来绘制实时图表，添加多个数据源，甚至为其添加动画。让我们从构建一个非常简单的自定义视图开始，稍后我们会添加更多功能。

# 边距和填充

与任何普通视图一样，我们的自定义视图将受到布局管理器的边距和视图填充的影响。我们不应该太担心边距值，因为布局管理器将直接处理它们，并且会透明地修改我们的自定义视图可用的尺寸。我们需要考虑的是填充值。正如在下图中所看到的，边距是布局管理器在我们自定义视图前后添加的空间，而填充则是视图边界与内容之间的内部空间：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/740959ca-d93e-41d5-834b-06ba78b731ca.png)

我们的视图需要适当管理这个填充。为此，我们可以直接使用`canvas`中的不同`getPadding`方法，如`getPaddingTop()`、`getPaddingBottom()`、`getPaddingStart()`等。使用填充值，我们应该在`onDraw()`方法中相应地调整渲染区域：

```kt
protected void onDraw(Canvas canvas) {
    int startPadding = getPaddingStart();
    int topPadding = getPaddingTop();

    int width = canvas.getWidth() - startPadding - getPaddingEnd();
    int height = canvas.getHeight() - topPadding - getPaddingBottom();
}
```

在这段代码中，我们存储了 `Canvas` 的左侧和顶部点，分别是起始填充和顶部填充值。我们必须小心这句话，因为起始填充可能不是左侧填充。如果我们查看文档，我们会发现既有 `getPaddingStart()`，`getPaddingEnd()`，也有 `getPaddingLeft()` 和 `getPaddingRight()`。例如，如果我们的设备配置为**从右到左**（**RTL**）模式，则起始填充可能是右侧填充。如果我们想要支持 LTR 和 RTL 设备，我们必须注意这些细节。在这个特定示例中，我们将通过使用视图上可用的 `getLayoutDirection()` 方法检测布局方向来构建支持 RTL 的版本。但首先，让我们专注于一个非常简单的实现。

# 基本实现

我们的基本实现将非常直接。首先创建类及其构造函数：

```kt
public class Chart extends View {
    private Paint linePaint;

    public Chart(Context context, AttributeSet attrs) {
        super(context, attrs);
        linePaint = new Paint();
        linePaint.setAntiAlias(true);
        linePaint.setColor(0xffffffff);
        linePaint.setStrokeWidth(8.f);
        linePaint.setStyle(Paint.Style.STROKE);
    }
}
```

在我们的构造函数中初始化了一个 `Paint` 对象，但这次我们将样式设置为 `Paint.Style.STROKE`，因为我们只关心绘制线条。现在让我们添加一个方法，这样无论谁使用自定义视图都可以设置要渲染的数据：

```kt
private float[] dataPoints;
private float minValue;
private float maxValue;
private float verticalDelta;

public void setDataPoints(float[] originalData) {
    dataPoints = new float[originalData.length];
    minValue = Float.MAX_VALUE;
    maxValue = Float.MIN_VALUE;
    for (int i = 0; i< dataPoints.length; i++) {
        dataPoints[i] = originalData[i];
        if (dataPoints[i] <minValue) minValue = dataPoints[i];
        if (dataPoints[i] >maxValue) maxValue = dataPoints[i];
    }

    verticalDelta = maxValue - minValue;
    postInvalidate();
}
```

我们正在复制原始数据数组，因为我们无法控制它，它可能会在没有任何预警的情况下发生变化。稍后，我们将看到如何改进这种行为并适应数据集的变化。

我们还在数组上计算最大值和最小值以及它们之间的差值。这将使我们能够得到这些数字的相对比例，并将它们缩小或按需放大到 0 到 1 的比例，这将非常方便调整渲染以适应我们的视图高度。

现在我们有了数据，可以实现我们的 `onDraw()` 方法：

```kt
@Override
protected void onDraw(Canvas canvas) {
    canvas.drawARGB(255,0 ,0 ,0);

    float leftPadding = getPaddingLeft();
    float topPadding = getPaddingTop();

    float width = canvas.getWidth() - leftPadding - getPaddingRight();
    float height = canvas.getHeight() - topPadding -
    getPaddingBottom();

    float lastX = getPaddingStart();
    float lastY = height * ((dataPoints[0] - minValue) / verticalDelta)
    + topPadding;

    for (int i = 1; i < dataPoints.length; i++) {
        float y = height * ((dataPoints[i] - minValue) / verticalDelta)
        + topPadding;
        float x = width * (((float) i + 1) / dataPoints.length) +
        leftPadding;

        canvas.drawLine(lastX, lastY, x, y, linePaint);
        lastX = x;
        lastY = y;
    }
}
```

为了尽可能简单，目前我们使用 `canvas.drawARGB(255, 0, 0, 0)` 绘制黑色背景，然后通过从总宽度和高度中减去填充来计算 `Canvas` 上的可用大小。

我们还将在所有点之间平均分配水平空间，并垂直缩放它们以使用所有可用空间。由于我们计算了数据集中最小值和最大值之间的差，我们可以通过减去数值的最小值然后除以差值（或这里我们使用的 `verticalDelta` 变量）来将这些数字缩放到 `0` 到 `1` 的范围。

通过这些计算，我们只需跟踪之前的值，以便能够从旧点画到新点。这里，我们将最后的 `x` 和 `y` 坐标分别存储在 `lastX` 和 `lastY` 变量中，并在每次循环结束时更新它们。

# 使用路径进行优化和改进

实际上，我们可以在`onDraw()`方法中预先计算这些操作，因为每次在屏幕上绘制图表时都没有必要这样做。我们可以在`setDataPoints()`中执行，这是我们自定义视图中唯一可以更改或替换数据集的点：

```kt
public void setDataPoints(float[] originalData) {
    dataPoints = new float[originalData.length];

    float minValue = Float.MAX_VALUE;
    float maxValue = Float.MIN_VALUE;
    for (int i = 0; i < dataPoints.length; i++) {
        dataPoints[i] = originalData[i];
        if (dataPoints[i] < minValue) minValue = dataPoints[i];
        if (dataPoints[i] > maxValue) maxValue = dataPoints[i];
    }

    float verticalDelta = maxValue - minValue;

    for (int i = 0; i < dataPoints.length; i++) {
        dataPoints[i] = (dataPoints[i] - minValue) / verticalDelta;
    }

    postInvalidate();
}
```

现在，我们可以简化`onDraw()`方法，因为我们完全可以假设我们的数据集将始终在`0`和`1`之间变化：

```kt
@Override
protected void onDraw(Canvas canvas) {
    canvas.drawARGB(255,0 ,0 ,0);

    float leftPadding = getPaddingLeft();
    float topPadding = getPaddingTop();

    float width = canvas.getWidth() - leftPadding - getPaddingRight();
    float height = canvas.getHeight() - topPadding -
    getPaddingBottom();

    float lastX = getPaddingStart();
    float lastY = height * dataPoints[0] + topPadding;
    for (int i = 1; i < dataPoints.length; i++) {
        float y = height * dataPoints[i] + topPadding;
        float x = width * (((float) i) / dataPoints.length) +
        leftPadding;

        canvas.drawLine(lastX, lastY, x, y, linePaint);

        lastX = x;
        lastY = y;
    }
}
```

但我们可以更进一步，将线条图转换成一条`Path`：

```kt
private Path graphPath; 

@Override
protected void onDraw(Canvas canvas) {
    canvas.drawARGB(255,0 ,0 ,0);

    float leftPadding = getPaddingLeft();
    float topPadding = getPaddingTop();

    float width = canvas.getWidth() - leftPadding - getPaddingRight();
    float height = canvas.getHeight() - topPadding - 
    getPaddingBottom();

    if (graphPath == null) {
        graphPath = new Path();

        graphPath.moveTo(leftPadding, height * dataPoints[0] +
        topPadding);

        for (int i = 1; i < dataPoints.length; i++) {
            float y = height * dataPoints[i] + topPadding;
            float x = width * (((float) i + 1) / dataPoints.length) +
            leftPadding;

            graphPath.lineTo(x, y);
        }
    }

    canvas.drawPath(graphPath, linePaint);
}

```

它将在第一次调用`onDraw()`方法时生成一条从一点到另一点的`Path`。图表还将根据`canvas`的尺寸进行缩放。我们现在唯一的问题将是它不会自动调整以适应`canvas`大小的变化或我们的图表数据更新。让我们看看如何修复它。

首先，我们必须声明一个`boolean`类型的标志，以确定是否需要重新生成`Path`，以及两个变量来保存我们自定义视图的最后宽度和高度：

```kt
private boolean regenerate; 
private float lastWidth; 
private float lastHeight; 
```

在类的构造函数中，我们必须创建一个`Path`的实例。稍后，我们不是通过检查 null 来创建新实例，而是调用 reset 方法来生成新的`Path`，但重用这个对象实例：

```kt
graphPath = new Path(); 
lastWidth = -1; 
lastHeight = -1; 
```

在`setDataPoints()`中，我们只需在调用`postInvalidate`之前将`regenerate`设置为 true。在我们的`onDraw()`方法中，我们必须添加额外的检查以检测`canvas`大小何时发生变化：

```kt
if (lastWidth != width || lastHeight != height) {
    regenerate = true;

    lastWidth = width;
    lastHeight = height;
}
```

正如我们刚才提到的，我们将检查`boolean`标志的值而不是检查 null，以重新生成`Path`：

```kt
if (regenerate) {
    graphPath.reset();
    graphPath.moveTo(leftPadding, height * dataPoints[0] + topPadding);

    for (int i = 1; i < dataPoints.length; i++) {
        float y = height * dataPoints[i] + topPadding;
        float x = width * (((float) i + 1) / dataPoints.length) +
        leftPadding;

        graphPath.lineTo(x, y);
    }

    regenerate = false;
}
```

# 背景线条和细节

让我们将其添加到 Android 项目中以查看结果。首先创建一个非常简单的布局文件：

```kt
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout 

    android:layout_width="match_parent"
    android:layout_height="match_parent"

    tools:context="com.rrafols.packt.chart.MainActivity">

    <com.rrafols.packt.chart.Chart
        android:layout_margin="16dp"
        android:padding="10dp"
        android:id="@+id/chart_view"
        android:layout_width="match_parent"
        android:layout_height="match_parent" />

</LinearLayout>
```

让我们也创建一个空的活动，这个活动将仅将此布局文件设置为内容视图，并为我们的图表组件生成一些随机数据以进行渲染：

```kt

@Override
protected void onCreate(Bundle savedInstanceState) {
   super.onCreate(savedInstanceState);
   setContentView(R.layout.activity_main);

   Chart chart = (Chart) findViewById(R.id.chart_view);

   float[] data = new float[20];
   for (int i = 0; i < data.length; i++) {
       data[i] = (float) Math.random() * 10.f;
   }

   chart.setDataPoints(data);
}
```

如果我们运行这个例子，我们将得到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/49ab7a3d-7bc3-42b9-a4d9-38111f1f0f83.png)

好的，我们已经完成了一个简单的实现，但让我们添加一些细节。首先，在每个数据点上添加一个小点以提高清晰度。让我们在类构造函数中创建一个新的`Paint`对象：

```kt
circlePaint = new Paint(); 
circlePaint.setAntiAlias(true); 
circlePaint.setColor(0xffff2020); 
circlePaint.setStyle(Paint.Style.FILL); 
```

一种实现方法是在每个数据点上绘制小圆圈。我们将在类构造函数中创建一个`circlePath`实例，并在需要重新生成时重置它。由于我们正在计算线条的坐标，因此可以直接将它们用作圆圈的位置：

```kt
@Override
protected void onDraw(Canvas canvas) {
    canvas.drawARGB(255,0 ,0 ,0);

    float leftPadding = getPaddingLeft();
    float topPadding = getPaddingTop();

    float width = canvas.getWidth() - leftPadding - getPaddingRight();
    float height = canvas.getHeight() - topPadding -
    getPaddingBottom();

    if (lastWidth != width || lastHeight != height) {

        regenerate = true;

        lastWidth = width;
        lastHeight = height;
    }

    if (regenerate) {
        circlePath.reset();
        graphPath.reset();

        float x = leftPadding;
        float y = height * dataPoints[0] + topPadding;

        graphPath.moveTo(x, y);
        circlePath.addCircle(x, y, 10, Path.Direction.CW);

        for (int i = 1; i < dataPoints.length; i++) {
            y = height * dataPoints[i] + topPadding;
            x = width * (((float) i + 1) / dataPoints.length) +
            leftPadding;

            graphPath.lineTo(x, y);
            circlePath.addCircle(x, y, 10, Path.Direction.CW);
        }

        regenerate = false;
    }

    canvas.drawPath(graphPath, linePaint);
    canvas.drawPath(circlePath, circlePaint);
}
```

在这个例子中，我们将圆的半径硬编码为`10`，仅比线条的厚度`8`稍大一点，但稍后我们将在本章中讨论自定义选项。

如果我们现在运行这个例子，我们将看到与之前版本的区别：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/87c0fde5-51bc-41a7-b699-0cea16f43ca7.png)

为了添加更直观的参考，我们还可以添加一些背景线条。由于它将使用不同的设置来绘制，首先我们创建一个新的`Paint`对象：

```kt
backgroundPaint = new Paint(); 
backgroundPaint.setColor(0xffBBBB40); 
backgroundPaint.setStyle(Paint.Style.STROKE); 
backgroundPaint.setPathEffect(new DashPathEffect(new float[] {5, 5}, 0)); 
```

现在，让我们修改`onDraw()`方法，以生成带有背景线条的新`Path`：

```kt
@Override
protected void onDraw(Canvas canvas) {
    canvas.drawARGB(255,0 ,0 ,0);

    float leftPadding = getPaddingLeft();
    float topPadding = getPaddingTop();

    float width = canvas.getWidth() - leftPadding - getPaddingRight();
    float height = canvas.getHeight() - topPadding -
    getPaddingBottom();

    if (lastWidth != width || lastHeight != height) {
        regenerate = true;

        lastWidth = width;
        lastHeight = height;
    }

    if (regenerate) {
        circlePath.reset();
        graphPath.reset();
        backgroundPath.reset();

 for (int i = 0; i <= dataPoints.length; i++) {
 float xl = width * (((float) i) / dataPoints.length) +
 leftPadding;
 backgroundPath.moveTo(xl, topPadding);
 backgroundPath.lineTo(xl, topPadding + height);
 }

 for (int i = 0; i <= 10; i++) {
 float yl = ((float) i / 10.f) * height + topPadding;
 backgroundPath.moveTo(leftPadding, yl);
 backgroundPath.lineTo(leftPadding + width, yl);
 }

        float x = leftPadding;
        float y = height * dataPoints[0] + topPadding;

        graphPath.moveTo(x, y);
        circlePath.addCircle(x, y, 10, Path.Direction.CW);

        for (int i = 1; i < dataPoints.length; i++) {
            x = width * (((float) i + 1) / dataPoints.length) + 
           leftPadding;
            y = height * dataPoints[i] + topPadding;

            graphPath.lineTo(x, y);
            circlePath.addCircle(x, y, 10, Path.Direction.CW);
        }

        regenerate = false;
    }

    canvas.drawPath(backgroundPath, backgroundPaint);
    canvas.drawPath(graphPath, linePaint);
    canvas.drawPath(circlePath, circlePaint);
}
```

在这里，我们创建水平和垂直的线条。水平线条将在有数据点的确切位置创建。对于垂直线条，我们不会遵循相同的原理，我们只需在`Canvas`的顶部和底部之间均匀绘制 10 条垂直线条。执行我们的示例，现在我们会得到类似于以下屏幕的内容：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/e76fd2c5-61a9-43b3-b16a-d15141d34b73.png)

这样可以，但我们仍然缺少一些参考点。让我们绘制一些水平和垂直的标签。

首先，让我们创建一个标签数组，并创建一个方法，让使用此自定义视图的任何人都可以设置它们：

```kt
private String[] labels; 

public void setLabels(String[] labels) {
    this.labels = labels;
}

```

如果它们没有被设置，我们可以选择不绘制任何内容，或者自己生成它们。在这个例子中，我们将自动使用数组索引生成它们：

```kt
if (labels == null) {
     labels = new String[dataPoints.length + 1];
     for (int i = 0; i < labels.length; i++) {
         labels[i] = "" + i;
     }
 }
```

为了测量文本，以便我们可以居中它，我们将复用`Rect`对象。让我们创建并实例化它：

```kt
private Rect textBoundaries = new Rect(); 
```

现在，我们可以将以下代码添加到`onDraw()`方法中，以绘制底部的标签，我们的数据集中的每个点都有一个：

```kt
for (int i = 0; i <= dataPoints.length; i++) {
    float xl = width * (((float) i) / dataPoints.length) + leftPadding;
    backgroundPaint.getTextBounds(labels[i], 0, labels[i].length(),
    textBoundaries);
    canvas.drawText(labels[i], 
        xl - (textBoundaries.width() / 2), 
        height + topPadding + backgroundPaint.getTextSize() * 1.5f, 
        backgroundPaint);
}
```

我们还调整了图表的总高度，以添加一些标签的空间：

```kt
float height = canvas.getHeight() - topPadding - getPaddingBottom() 
        - backgroundPaint.getTextSize() + 0.5f; 
```

让我们也绘制一个侧边图例，指示点的值和刻度。由于我们绘制的是预定义的一组垂直线条，我们只需计算这些值。我们需要将这些值从 0 到 1 的范围转换回它们的原始范围和特定值。

我们需要根据标签大小调整图表的宽度和初始左侧点。因此，让我们计算侧标签的最大宽度：

```kt
float maxLabelWidth = 0.f;

for (int i = 0; i <= 10; i++) {
    float step = ((float) i / 10.f);
    float value = step * verticalDelta + minValue;
    verticalLabels[i] = decimalFormat.format(value);
    backgroundPaint.getTextBounds(verticalLabels[i], 0,
    verticalLabels[i].length(), textBoundaries);
    if (textBoundaries.width() > maxLabelWidth) {
        maxLabelWidth = textBoundaries.width();
    }
}
```

我们还使用了一个`DecimalFormat`实例来格式化浮点数值。我们使用以下模式创建了此`DecimalFormat`：

```kt
decimalFormat = new DecimalFormat("#.##"); 
```

此外，我们将标签存储在数组中，以避免每次绘制视图时都重新生成它们。在`maxLabelWidth`变量中存储最大标签宽度后，我们可以调整填充：

```kt
float labelLeftPadding = getPaddingLeft() + maxLabelWidth * 0.25f; 
float leftPadding = getPaddingLeft() + maxLabelWidth * 1.5f; 
```

我们仍然使用`leftPadding`来渲染所有对象，并使用`labelLeftPadding`来渲染标签。我们已经添加了最大标签的大小以及绘制标签前后分布的额外*50%*填充。因此，标签将具有额外的*25%*`maxLabelWidth`填充，这样标签末尾和图表开始之间将有另外*25%*的空间。

我们只需遍历数组并计算正确的垂直位置，就可以轻松绘制垂直标签：

```kt
for (int i = 0; i <= 10; i++) {
    float step = ((float) i / 10.f);
    float yl = step * height + topPadding- (backgroundPaint.ascent() +
    backgroundPaint.descent()) * 0.5f;
    canvas.drawText(verticalLabels[i],
        labelLeftPadding, 
        yl, 
        backgroundPaint);
}
```

为了在垂直坐标上居中文本，我们使用了当前字体上升和下降之间的平均值。

如果我们现在运行这个示例，我们将更详细地查看我们的图表：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/c35a24d3-be7f-4bb4-98dd-8b62d9b3c11e.png)

我们在本章开头提到，我们将支持 RTL 和 LTR 设备。如果设备布局配置为 RTL，那么在图表视图中，图例在屏幕右侧会感觉更自然。让我们快速实现这个变化：

```kt
float labelLeftPadding = getPaddingLeft() + maxLabelWidth * 0.25f; 
float leftPadding = getPaddingLeft() + maxLabelWidth * 1.5f; 
float rightPadding = getPaddingRight(); 
float topPadding = getPaddingTop(); 

float width = canvas.getWidth() - leftPadding - rightPadding; 
float height = canvas.getHeight() - topPadding - getPaddingBottom() 
        - backgroundPaint.getTextSize() + 0.5f; 

if (getLayoutDirection() == LAYOUT_DIRECTION_RTL) { 
    leftPadding = getPaddingEnd(); 
    labelLeftPadding = leftPadding + width + maxLabelWidth * 0.25f; 
} 
```

我们唯一需要做的改变是检查布局方向是否为`LAYOUT_DIRECTION_RTL`，并更改`leftPadding`和`labelLeftPadding`，以更新绘制图表和标签的位置。

# 自定义

在上一章我们已经看到了如何向自定义视图添加参数。在本章中我们构建的图表自定义视图，我们可以配置例如颜色、线条粗细、点的大小等等，但相反，我们将关注其他类型的自定义，例如，反转垂直轴，以及启用或禁用底部和侧标签或图表图例的渲染。与之前的配置相比，这些将需要一些额外的代码调整和特定实现。

我们先从允许反转垂直轴开始。我们的默认实现将在顶部渲染较小的值，在图表底部渲染较大的值。这可能不是预期的结果，所以让我们添加一种方法来反转轴：

```kt
private boolean invertVerticalAxis;

public void setInvertVerticalAxis(boolean invertVerticalAxis) {
    this.invertVerticalAxis = invertVerticalAxis;
    regenerate = true;
    postInvalidate();
}
```

然后，我们只需改变标签生成的步骤，并在适用的情况下反转数据点的值。要更改标签的生成，我们可以通过简单地更新步骤的顺序来实现。我们不是从`0`到`1`获取一个数字，而是反转这个过程，从`1`到`0`获取一个数字：

```kt
float maxLabelWidth = 0.f;
if (regenerate) {
    for (int i = 0; i <= 10; i++) {
        float step;

        if (!invertVerticalAxis) {
 step = ((float) i / 10.f);
 } else {
 step = ((float) (10 - i)) / 10.f;
 }

        float value = step * verticalDelta + minValue;
        verticalLabels[i] = decimalFormat.format(value);
        backgroundPaint.getTextBounds(verticalLabels[i], 0,
        verticalLabels[i].length(), textBoundaries);
        if (textBoundaries.width() > maxLabelWidth) {
            maxLabelWidth = textBoundaries.width();
        }
    }
}
```

如果需要，根据标志位的值获取数据点的反转值，让我们添加一个新方法来实现：

```kt
private float getDataPoint(int i) { 
    float data = dataPoints[i]; 
    return invertVerticalAxis ? 1.f - data : data; 
} 
```

现在，我们不是直接从数组获取数据点，而应该使用这个方法，因为它会在需要时透明地反转数字。

如我们之前提到的，我们还添加了一个`setLabels()`方法，因此标签也可以在外部进行自定义。

我们还可以添加一个`boolean`类型的标志，以允许或阻止绘制图例和背景线条：

```kt
private boolean drawLegend;

public void setDrawLegend(boolean drawLegend) {
    this.drawLegend = drawLegend;
    regenerate = true;
    postInvalidate();
}
```

在绘制背景线条和标签之前，只需检查此标志的状态。

在 GitHub 仓库的`Example34-Charts`文件夹中查看完整的示例。

# 添加高级功能

我们一直在构建一个简单的图表自定义视图实现。但是，我们的自定义视图可能需要一些更多的功能，否则可能会显得有些静态或不太有用。我们无法构建我们可能想到或可能需要的所有功能。同时，我们也应该注意不要构建一个瑞士军刀式的自定义视图，因为它可能难以维护，并且可能对自定义视图性能产生影响。

# 实时更新

在我们自定义视图的首次简单实现中，我们创建了一个设置数据点的方法，但无法修改或更新数据。让我们进行一些快速更改，以便能够动态添加点。在这个实现中，我们在`setDataPoints()`方法中直接将值调整到了 0 到 1 的刻度。由于我们将提供一个添加新数据值的方法，我们可能会得到超出原有最小值和最大值的值，这将使之前计算的刻度无效。

首先，让我们用集合而不是数组来存储数据，这样我们可以轻松添加新值：

```kt
private ArrayList<Float> dataPoints;

public void setDataPoints(float[] originalData) {
    ArrayList<Float> array = new ArrayList<>();
    for (float data : originalData) {
        array.add(data);
    }

    setDataPoints(array);
}

public void setDataPoints(ArrayList<Float> originalData) {
    dataPoints = new ArrayList<Float>();
    dataPoints.addAll(originalData);

    adjustDataRange();
}
```

我们将数据存储在`ArrayList`中，并修改了`setDataPoints()`方法以便能够这样做。同时，我们创建了`adjustDataRange()`方法来重新计算数据的范围，并触发数据重新生成和视图的重新绘制：

```kt
private void adjustDataRange() {
    minValue = Float.MAX_VALUE;
    maxValue = Float.MIN_VALUE;
    for (int i = 0; i < dataPoints.size(); i++) {
        if (dataPoints.get(i) < minValue) minValue = dataPoints.get(i);
        if (dataPoints.get(i) > maxValue) maxValue = dataPoints.get(i);
    }

    verticalDelta = maxValue - minValue;

    regenerate = true;
    postInvalidate();
}
```

`addValue()`方法的实现相当简单。我们将新数据添加到`ArrayList`中，如果它在当前范围内，我们只需触发图形的重新生成和视图的重新绘制。如果它超出了当前范围，我们调用`adjustDataRange()`方法来调整所有数据到新范围：

```kt
public void addValue(float data) {
    dataPoints.add(data);

    if (data < minValue || data > maxValue) {
        adjustDataRange();
    } else {
        regenerate = true;
        postInvalidate();
    }
}
```

我们只需修改`getDataPoint()`方法，将数据调整到`0`到`1`的范围：

```kt
private float getDataPoint(int i) { 
    float data = (dataPoints.get(i) - minValue) / verticalDelta; 
    return invertVerticalAxis ? 1.f - data : data; 
} 
```

如果我们运行示例，可以看到可以向图中添加新点，它会自动调整。要完全更改或更新数据，必须调用`setDataPoints()`方法。

# 多个数据集

有时，我们希望显示多个图表以进行比较，或者简单地同时显示多个数据集。让我们进行一些修改，以允许在我们的图表自定义视图中同时显示两个图表。它可以进一步扩展以支持更多的图表，但在这个示例中，我们将限制为两个以简化逻辑。

首先，我们需要为每个图表创建不同的 Paint 和 Path 对象。我们将创建数组来存储它们，这样稍后迭代和渲染它们会更容易。例如，我们可以为每个图表创建具有不同颜色的多个 Paint 对象：

```kt
linePaint = new Paint[2]; 
linePaint[0] = new Paint(); 
linePaint[0].setAntiAlias(true); 
linePaint[0].setColor(0xffffffff); 
linePaint[0].setStrokeWidth(8.f); 
linePaint[0].setStyle(Paint.Style.STROKE); 

linePaint[1] = new Paint(); 
linePaint[1].setAntiAlias(true); 
linePaint[1].setColor(0xff4040ff); 
linePaint[1].setStrokeWidth(8.f); 
linePaint[1].setStyle(Paint.Style.STROKE); 
circlePaint = new Paint[2]; 
circlePaint[0] = new Paint(); 
circlePaint[0].setAntiAlias(true); 
circlePaint[0].setColor(0xffff2020); 
circlePaint[0].setStyle(Paint.Style.FILL);  
circlePaint[1] = new Paint(); 
circlePaint[1].setAntiAlias(true); 
circlePaint[1].setColor(0xff20ff20); 
circlePaint[1].setStyle(Paint.Style.FILL); 
```

实际上，一次又一次地设置相同的参数是一项相当多的工作，因此我们可以使用`Paint`的另一个构造函数，它从一个已存在的`Paint`对象复制属性：

```kt
linePaint = new Paint[2]; 
linePaint[0] = new Paint(); 
linePaint[0].setAntiAlias(true); 
linePaint[0].setColor(0xffffffff); 
linePaint[0].setStrokeWidth(8.f); 
linePaint[0].setStyle(Paint.Style.STROKE);

linePaint[1] = new Paint(linePaint[0]); 
linePaint[1].setColor(0xff4040ff); 

circlePaint = new Paint[2]; 
circlePaint[0] = new Paint(); 
circlePaint[0].setAntiAlias(true); 
circlePaint[0].setColor(0xffff2020); 
circlePaint[0].setStyle(Paint.Style.FILL); 

circlePaint[1] = new Paint(circlePaint[0]); 
circlePaint[1].setColor(0xff20ff20); 
```

还有`Path`对象和数据存储：

```kt
graphPath = new Path[2]; 
graphPath[0] = new Path(); 
graphPath[1] = new Path(); 

circlePath = new Path[2]; 
circlePath[0] = new Path(); 
circlePath[1] = new Path(); 

dataPoints = (ArrayList<Float>[]) new ArrayList[2]; 
```

我们还需要一个机制来将数据添加到特定的数据集：

```kt
public void setDataPoints(ArrayList<Float> originalData, int index) {
    dataPoints[index] = new ArrayList<Float>();
    dataPoints[index].addAll(originalData);

    adjustDataRange();
}
```

由于我们将拥有不同的数据集，我们必须计算所有数据集的最小值和最大值。我们将每个图使用相同的刻度，这样比较起来更容易：

```kt
private void adjustDataRange() {
    minValue = Float.MAX_VALUE;
    maxValue = Float.MIN_VALUE;
    for (int j = 0; j < dataPoints.length; j++) {
        for (int i = 0; dataPoints[j] != null && i <
        dataPoints[j].size(); i++) {
            if (dataPoints[j].get(i) < minValue) minValue =
            dataPoints[j].get(i);
            if (dataPoints[j].get(i) > maxValue) maxValue =
            dataPoints[j].get(i);
        }
    }

    verticalDelta = maxValue - minValue;

    regenerate = true;
    postInvalidate();
}
```

最后，我们需要更新`getDataPoint()`方法，以允许我们从不同的数据集中获取数据：

```kt
private float getDataPoint(int i, int index) { 
    float data = (dataPoints[index].get(i) - minValue) / verticalDelta; 
    return invertVerticalAxis ? 1.f - data : data; 
} 
```

使用这些方法，我们可以更新路径生成代码以生成多个`Path`。如果该图的 数据集未定义，它将不会生成`Path`。

```kt
for (int j = 0; j < 2; j++) {
    if (dataPoints[j] != null) {
        float x = leftPadding;
        float y = height * getDataPoint(0, j) + topPadding;

        graphPath[j].moveTo(x, y);
        circlePath[j].addCircle(x, y, 10, Path.Direction.CW);

        for (int i = 1; i < dataPoints[j].size(); i++) {
            x = width * (((float) i + 1) / dataPoints[j].size()) + 
            leftPadding;
            y = height * getDataPoint(i, j) + topPadding;

            graphPath[j].lineTo(x, y);
            circlePath[j].addCircle(x, y, 10, Path.Direction.CW);
        }
    }
}
```

渲染代码，只是遍历所有生成的`Path`并使用相应的`Paint`对象进行绘制：

```kt
for (int j = 0; j < graphPath.length; j++) {
    canvas.drawPath(graphPath[j], linePaint[j]);
    canvas.drawPath(circlePath[j], circlePaint[j]);
}
```

如果我们用两组随机数据运行这个示例，我们将看到类似于以下屏幕的内容：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/c9060b21-9612-4d3b-9cc7-f4205e370f02.png)

# 放大和滚动

我们可以实现的另一个有趣功能是自定义视图的放大和滚动能力。就像我们在上一章中所做的那样，我们将使用 Android 的`ScaleDetector`类来检测捏合手势并在自定义视图中更新放大。

实现将与上一章有很大不同。在这种情况下，我们会以更简单的方式来做。由于我们希望放大所有内容，我们将应用`canvas`转换，而不是再次重新生成缩放的`Path`对象，但首先，让我们实现手势检测器并添加滚动和动画属性的能力。

我们几乎可以复制之前在自定义 EPG 视图中使用的相同方法，用于动画变量逻辑的检查，以及我们是否还有未完成的动画：

```kt
private boolean missingAnimations() {
    if (Math.abs(scrollXTarget - scrollX) > ANIM_THRESHOLD) 
        return true;

    if (Math.abs(scrollYTarget - scrollY) > ANIM_THRESHOLD)
        return true;

    return false;
}

private void animateLogic() {
    long currentTime = SystemClock.elapsedRealtime();
    accTime += currentTime - timeStart;
    timeStart = currentTime;

    while (accTime > TIME_THRESHOLD) {
        scrollX += (scrollXTarget - scrollX) / 4.f;
        scrollY += (scrollYTarget - scrollY) / 4.f;
        accTime -= TIME_THRESHOLD;
    }

    float factor = ((float) accTime) / TIME_THRESHOLD;
    float nextScrollX = scrollX + (scrollXTarget - scrollX) / 4.f;
    float nextScrollY = scrollY + (scrollYTarget - scrollY) / 4.f;

    frScrollX = scrollX * (1.f - factor) + nextScrollX * factor;
    frScrollY = scrollY * (1.f - factor) + nextScrollY * factor;
}
```

我们还可以几乎原封不动地添加检查拖动事件、将触摸事件发送到缩放检测器并根据拖动量滚动屏幕的代码：

```kt
@Override
public boolean onTouchEvent(MotionEvent event) {
    scaleDetector.onTouchEvent(event);

    if (zooming) {
        invalidate();
        zooming = false;
        return true;
    }

    switch(event.getAction()) {
        case MotionEvent.ACTION_DOWN:
            dragX = event.getX();
            dragY = event.getY();

            getParent().requestDisallowInterceptTouchEvent(true);
            dragged = false;
            return true;

        case MotionEvent.ACTION_UP:
            getParent().requestDisallowInterceptTouchEvent(false);
            return true;

        case MotionEvent.ACTION_MOVE:
            float newX = event.getX();
            float newY = event.getY();

            scrollScreen(dragX - newX, dragY - newY);

            dragX = newX;
            dragY = newY;
            dragged = true;
            return true;
        default:
            return false;
    }
}

private void scrollScreen(float dx, float dy) {
    scrollXTarget += dx;
    scrollYTarget += dy;

    if (scrollXTarget < 0) scrollXTarget = 0;
    if (scrollYTarget < 0) scrollYTarget = 0;

    if (scrollXTarget > getWidth() * scale - getWidth()) {
        scrollXTarget = getWidth() * scale - getWidth();
    }

    if (scrollYTarget > getHeight() * scale - getHeight()) {
        scrollYTarget = getHeight() * scale - getHeight();
    }

    invalidate();
}
```

我们定义了一个名为 scale 的变量，它将控制我们对图表自定义视图的放大（或缩放）量。现在，让我们编写`scaleDetector`的实现：

```kt
scaleDetector = new ScaleGestureDetector(context, new ScaleGestureDetector.SimpleOnScaleGestureListener() {
    private float focusX;
    private float focusY;
    private float scrollCorrectionX = 0.f;
    private float scrollCorrectionY = 0.f;

    @Override
    public boolean onScaleBegin(ScaleGestureDetector detector) {
        zooming = true;
        focusX = detector.getFocusX();
        focusY = detector.getFocusY();
        scrollCorrectionX = focusX * scale - scrollXTarget;
        scrollCorrectionY = focusY * scale - scrollYTarget;
        return true;
    }

    public boolean onScale(ScaleGestureDetector detector) {
        scale *= detector.getScaleFactor();
        scale = Math.max(1.f, Math.min(scale, 2.f));

        float currentX = focusX * scale - scrollXTarget;
        float currentY = focusY * scale - scrollYTarget;

        scrollXTarget += currentX - scrollCorrectionX;
        scrollYTarget += currentY - scrollCorrectionY;

        invalidate();
        return true;
    }

    @Override
    public void onScaleEnd(ScaleGestureDetector detector) {
        zooming = true;
    }
});
```

我们还实现了一个滚动校正机制，以尽可能保持放大时的居中。在这种情况下，我们必须在水平和垂直轴上实现它。算法背后的主要思想是计算手势关注点的水平和垂直位置，并在改变缩放时调整滚动位置，以保持其位置不变。

现在，我们的`onDraw()`方法将简单地从以下内容开始：

```kt
animateLogic(); 

canvas.save(); 

canvas.translate(-frScrollX, -frScrollY); 
canvas.scale(scale, scale); 
```

我们需要通过调用`animateLogic()`来检查和处理动画周期，然后正确地表现并保存我们的`canvas`状态，应用由滚动值`frScrollX`和`frScrollY`确定的平移，以及通过`scale`变量缩放整个`canvas`。

我们要渲染的所有内容都将被滚动位置偏移并由 scale 变量的值进行缩放。在结束方法之前，我们必须恢复我们的`canvas`，并在不是所有的属性动画都完成时触发新的重绘周期：

```kt
canvas.restore(); 
if (missingAnimations()) invalidate(); 
```

在 GitHub 仓库的`Example35-Charts`文件夹中查看完整的示例源代码。

# 总结

在本章中，我们了解了如何在 Android 应用程序中构建图表的自定义视图。我们还快速介绍了如何管理内边距、RTL / LTR 支持，最后通过支持多个数据集或添加放大和滚动的功能，为我们的自定义视图增加了复杂性。

我们实现这个自定义视图的方式；使用独立的数据范围并动态适应屏幕，意味着它将自动调整以适应任何屏幕分辨率，或者例如，适应屏幕方向的改变。这通常是一个好习惯，可以防止在多种设备上测试自定义视图时出现许多问题。此外，像我们在上一个示例中所做的那样，使屏幕上绘制的一切大小依赖于屏幕密度，将使可移植性更加容易。

在下一章中，我们将展示如何利用前几章中介绍的三维渲染功能来构建自定义视图。 
