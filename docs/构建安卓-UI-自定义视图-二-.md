# 构建安卓 UI 自定义视图（二）

> 原文：[`zh.annas-archive.org/md5/DB7176CF30C0E45521FC275B41E28E14`](https://zh.annas-archive.org/md5/DB7176CF30C0E45521FC275B41E28E14)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：高级 2D 渲染

能够绘制更复杂的原始图形或使用它们的组合对于使我们的自定义视图的用户体验变得出色、实用和特别至关重要。到目前为止，我们在自定义视图中使用了一些绘制和渲染操作，但如果我们仔细查看 Android 文档，这只是 Android 为开发者提供的一小部分功能。我们已经绘制了一些原始图形，保存和恢复了我们的`canvas`状态，并应用了一些剪辑操作，但这只是冰山一角。在本章中，我们将再次看到这些操作，但我们将看到一些新的绘制操作以及如何将它们一起使用。我们将更详细地介绍以下主题：

+   绘图操作

+   蒙版和剪辑

+   渐变

+   把它们放在一起

# 绘图操作

正如我们刚才提到的，我们已经看到并使用了一些绘图操作，但这只是冰山一角。我们将看到新的绘图操作以及如何将它们结合使用。

# 位图

让我们从绘制位图或图像开始。我们不是使用白色背景，而是将图像作为我们自定义视图的背景。使用我们之前示例的源代码，我们可以做一些非常简单的修改来绘制图像：

首先，定义一个`Bitmap`对象来保存对图像的引用：

```kt
private Bitmap backgroundBitmap; 
```

首先，让我们用已有的应用程序图标来初始化它：

```kt
public CircularActivityIndicator(Context context, AttributeSet attributeSet) { 
    super(context, attributeSet); 

    backgroundBitmap = BitmapFactory.decodeResource(getResources(),
    R.mipmap.ic_launcher); 
```

`BitmapFactory`为我们提供了多种加载和解码图像的方法。

当我们加载了图像之后，可以在`onDraw()`方法中通过调用`drawBitmap(Bitmap bitmap, float left, float top, Paint paint)`方法来绘制图像：

```kt
@Override 
protected void onDraw(Canvas canvas) { 
    if (backgroundBitmap != null) { 
        canvas.drawBitmap(backgroundBitmap, 0, 0, null); 
    } 
```

因为我们不需要从`Paint`对象中得到任何特别的东西，所以我们将其设置为`null`；我们将在本书稍后使用它，但现在，只需忽略它。

如果`backgroundBitmap`为`null`，这意味着它无法加载图像；因此，为了安全起见，我们应始终检查。这段代码只会在我们自定义视图的左上角绘制图标，尽管我们可以通过设置不同的坐标（这里我们使用了`0`，`0`）或对我们的`canvas`应用之前做过的变换来改变其位置。例如，我们可以根据用户选择的角度来旋转图像：

```kt
@Override 
protected void onDraw(Canvas canvas) { 
    // apply a rotation of the bitmap based on the selectedAngle 
    if (backgroundBitmap != null) { 
        canvas.save(); 
        canvas.rotate(selectedAngle, backgroundBitmap.getWidth() / 2,
        backgroundBitmap.getHeight() / 2); 
        canvas.drawBitmap(backgroundBitmap, 0, 0, null); 
        canvas.restore(); 
    } 
```

注意，我们已经将图像的中心作为轴心点，否则将以其左上角为中心旋转。

有其他方法可以绘制图像；Android 提供了另一种方法，可以从源`Rect`绘制到目标`Rect`。`Rect`对象允许我们存储四个坐标并将其用作矩形。

`drawBitmap(Bitmap bitmap, Rect source, Rect dest, Paint paint)`方法非常适用于将图像的一部分绘制成我们想要的任何其他大小。这个方法会处理缩放选定部分的图像以填充目标矩形。例如，如果我们想绘制图像的右半部分并缩放到整个自定义视图的大小，我们可以使用以下代码。

首先，让我们定义背景 `Bitmap` 和两个 `Rect`；一个用于保存源尺寸，另一个用于目标尺寸：

```kt
private Bitmap backgroundBitmap; 
private Rect bitmapSource; 
private Rect bitmapDest; 
```

然后，让我们在类构造函数中实例化它们。在 `onDraw()` 方法中这样做不是一个好习惯，因为我们应该避免为每次帧调用或每次绘制自定义视图的方法分配内存。这样做会触发额外的垃圾收集周期，影响性能。

```kt
public CircularActivityIndicator(Context context, AttributeSet attributeSet) { 
    super(context, attributeSet); 

    backgroundBitmap = BitmapFactory.decodeResource(getResources(),
    R.mipmap.ic_launcher); 
    bitmapSource = new Rect(); 

    bitmapSource.top = 0; 
    bitmapSource.left = 0; 
    if(backgroundBitmap != null) { 
        bitmapSource.left = backgroundBitmap.getWidth() / 2; 
        bitmapSource.right = backgroundBitmap.getWidth(); 
        bitmapSource.botto 
        m = backgroundBitmap.getHeight(); 
    } 
    bitmapDest = new Rect(); 
```

默认情况下，`Rect` 会将四个坐标初始化为 0，但在这里，为了清晰起见，我们将顶部和左侧坐标设置为 0。如果图像加载成功，我们将右侧和底部分别设置为图像的宽度和高度。由于我们只想绘制图像的右半部分，因此我们将左侧边界更新为图像宽度的一半。

在 `onDraw()` 方法中，我们将目标 `Rect` 的右侧和底部坐标设置为自定义视图的宽度和高度，然后我们绘制图像：

```kt
@Override 
protected void onDraw(Canvas canvas) { 
    if (backgroundBitmap != null) { 
        bitmapDest.right = getWidth(); 
        bitmapDest.bottom = getHeight(); 

        canvas.drawBitmap(backgroundBitmap, bitmapSource, bitmapDest,
        null); 
    } 
```

让我们检查一下结果：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/0da5787f-9638-4cf0-846e-56f9a313f84e.png)

我们可以看到它并不遵循图像的宽高比，但我们可以通过计算较小维度（水平或垂直）的比例并以此比例进行缩放来解决它。然后，将这个比例应用到另一个维度上。计算图像比例后，我们将看到以下代码：

```kt
@Override 
protected void onDraw(Canvas canvas) { 
    if (backgroundBitmap != null) { 
        if ((bitmapSource.width() > bitmapSource.height() && getHeight() >
        getWidth()) || 
            (bitmapSource.width() <= bitmapSource.height() && getWidth() >=
            getHeight())) { 

            double ratio = ((double) getHeight()) / ((double)
            bitmapSource.height()); 
            int scaledWidth = (int) (bitmapSource.width() * ratio); 
            bitmapDest.top = 0; 
            bitmapDest.bottom = getHeight(); 
            bitmapDest.left = (getWidth() - scaledWidth) / 2; 
            bitmapDest.right = bitmapDest.left + scaledWidth; 
        } else { 
            double ratio = ((double) getWidth()) / ((double)
            bitmapSource.width()); 
            int scaledHeight = (int) (bitmapSource.height() * ratio); 
            bitmapDest.left = 0; 
            bitmapDest.right = getWidth(); 
            bitmapDest.top = 0; 
            bitmapDest.bottom = scaledHeight; 
        } 

        canvas.drawBitmap(backgroundBitmap, bitmapSource, bitmapDest,
        null); 
    } 
```

我们还可以使用变换 `Matrix` 绘制 `Bitmap`。为此，我们可以创建 `Matrix` 的新实例并应用变换：

```kt
private Matrix matrix; 
```

在构造函数中创建实例。不要在 `onDraw()` 实例中创建实例，因为这将污染内存并触发不必要的垃圾收集，如前所述：

```kt
matrix = new Matrix(); 
matrix.postScale(0.2f, 0.2f); 
matrix.postTranslate(0, 200); 
```

请注意矩阵操作顺序；也有后操作和前操作。更多信息请查看矩阵类文档。

在 `onDraw()` 方法中，只需使用 `drawBitmap (Bitmap bitmap, Matrix matrix, Paint paint)` 方法绘制 `Bitmap`，并使用我们在类构造函数中初始化的 `matrix`。在这个例子中，我们还使用了 `null Paint` 对象以简化，因为在这里我们不需要从 `Paint` 对象获取任何特定内容。

```kt
canvas.drawBitmap(backgroundBitmap, matrix, null); 
```

尽管这些是将 `Bitmap` 绘制到 `Canvas` 上最常见的方法，但还有更多方法。

此外，请查看 GitHub 存储库中的 `Example12-Drawing` 文件夹，以查看此示例的完整源代码。

# 使用 Paint 类

到现在为止我们一直在绘制一些基本图形，但 `Canvas` 为我们提供了更多基本渲染方法。我们将简要介绍其中一些，但首先，让我们正式介绍一下 `Paint` 类，因为我们还没有完全介绍它。

根据官方定义，`Paint`类保存了关于如何绘制基本图形、文本和位图的风格和颜色信息。如果我们检查我们一直在构建的示例，我们在类构造函数中或在`onCreate`方法中创建了一个`Paint`对象，并在后面的`onDraw()`方法中使用它来绘制基本图形。例如，如果我们把背景`Paint`实例的`Style`设置为`Paint.Style.FILL`，它会填充基本图形，但如果我们只想绘制边框或轮廓的笔触，我们可以将其更改为`Paint.Style.STROKE`。我们可以同时使用`Paint.Style.FILL_AND_STROKE`来绘制两者。

为了看到`Paint.Style.STROKE`的效果，我们将在自定义视图中的选定彩色栏上方绘制一个黑色边框。首先，在类构造函数中定义一个新的`Paint`对象，名为`indicatorBorderPaint`，并初始化它：

```kt
indicatorBorderPaint = new Paint(); 
indicatorBorderPaint.setAntiAlias(false); 
indicatorBorderPaint.setColor(BLACK_COLOR); 
indicatorBorderPaint.setStyle(Paint.Style.STROKE); 
indicatorBorderPaint.setStrokeWidth(BORDER_SIZE); 
indicatorBorderPaint.setStrokeCap(Paint.Cap.BUTT); 
```

我们还定义了一个常量来设置边框线的尺寸，并将笔触宽度设置为这个尺寸。如果我们把宽度设置为`0`，Android 保证会使用一个像素来绘制线条。由于我们现在想要绘制一条粗黑的边框，所以这不是我们的情况。此外，我们将笔触线帽设置为`Paint.Cap.BUTT`，以避免笔触溢出路径。还有两种线帽可以使用，`Paint.Cap.SQUARE`和`Paint.Cap.ROUND`。最后这两种线帽会分别以圆形（使笔触变圆）或方形结束笔触。

让我们快速了解三种线帽之间的区别，并介绍`drawLine`这个基本图形绘制方法。

首先，我们创建一个包含所有三种线帽的数组，这样我们可以轻松地在它们之间迭代，并编写更紧凑的代码：

```kt
private static final Paint.Cap[] caps = new Paint.Cap[] { 
        Paint.Cap.BUTT, 
        Paint.Cap.ROUND, 
        Paint.Cap.SQUARE 
}; 
```

现在，在我们的`onDraw()`方法中，让我们使用`drawLine(float startX, float startY, float stopX, float stopY, Paint paint)`方法，用每种线帽绘制一条线：

```kt
int xPos = (getWidth() - 100) / 2; 
int yPos = getHeight() / 2 - BORDER_SIZE * CAPS.length / 2; 
for(int i = 0; i < CAPS.length; i++) { 
    indicatorBorderPaint.setStrokeCap(CAPS[i]); 
    canvas.drawLine(xPos, yPos, xPos + 100, yPos,
    indicatorBorderPaint); 
    yPos += BORDER_SIZE * 2; 
} 
indicatorBorderPaint.setStrokeCap(Paint.Cap.BUTT); 
```

我们将得到类似以下图像的结果。如我们所见，当使用`Paint.Cap.BUTT`作为笔触线帽时，线条会稍微短一些：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/3682b626-e67f-48b8-aa8b-536408294391.png)

同样，正如我们之前所看到的，我们在`Paint`对象上设置了`AntiAlias`标志为 true。如果启用了这个标志，所有支持它的操作都会平滑它们正在绘制的图形的角。让我们比较一下启用和禁用这个标志时的差异：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/d379d55a-4833-4c1d-b931-374de6124d95.png)

在左边，我们启用了`AntiAlias`标志的三条线，在右边，我们禁用了`AntiAlias`标志的同样三条线。我们只能在圆角上看到差异，但结果更平滑、更美观。并非所有的操作和基本图形都支持这个标志，并且可能会影响性能，因此在使用这个标志时需要小心。

我们还可以使用另一个名为`drawLine(float[] points, int offset, int count, Paint paint)`的方法或其简化形式`drawLine(float[] points, Paint paint)`来绘制多条线。

这个方法将为数组中的每组四个条目绘制一条线；这就像调用`drawLine(array[index], array[index + 1], array[index + 2], array[index +3], paint)`，将索引增加`4`，并重复此过程直到数组末尾。

在第一个方法中，我们还可以指定要绘制的线条数量以及从数组内部哪个偏移量开始。

现在，让我们来完成我们之前的任务并绘制边框：

```kt
canvas.drawArc( 
       horMargin + BORDER_SIZE / 4, 
       verMargin + BORDER_SIZE / 4, 
       horMargin + circleSize - BORDER_SIZE /2, 
       verMargin + circleSize - BORDER_SIZE /2, 
       0, selectedAngle, true, indicatorBorderPaint); 
```

它只是用这个新的`Paint`绘制相同的圆弧。一个小细节：由于边框宽度从绘制笔划的位置中心向外增长，我们需要将圆弧的大小减少`BORDER_SIZE / 2`。让我们看看结果：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/3f04c547-60cf-4301-b7d6-a3eade43e39f.png)

我们缺少内部边框，但这很正常，因为如果我们从之前的章节中记得，这部分存在是因为我们将其裁剪掉了，而不是因为`drawArc`以这种方式绘制。我们可以用一个小技巧来绘制这个内部边框。我们将绘制一个与裁剪区域大小相同的圆弧，但只绘制边框：

```kt
canvas.drawArc( 
       clipX - BORDER_SIZE / 4, 
       clipY - BORDER_SIZE / 4, 
       clipX + clipWidth + BORDER_SIZE / 2, 
       clipY + clipWidth + BORDER_SIZE / 2, 
       0, selectedAngle, true, indicatorBorderPaint); 
```

在这里，我们对边框大小应用了相同的逻辑，但反过来：我们绘制稍微大一点的圆弧，而不是小一点的。

让我们看看结果：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/be9fb693-b67d-4b2d-a9e1-855d5230794b.png)

我们在这本书的一开始提到过，但重要的是不要在`onDraw()`方法中或基本上在任何每次绘制帧时都会被调用的方法中创建新的`Paint`对象。在某些情况下，我们可能觉得这样做很方便；然而，抵制诱惑，在类构造函数中创建对象或仅仅复用对象。我们可以更改`Paint`类实例属性并复用它来绘制不同的颜色或样式。

在 GitHub 仓库的`Example13-Paint`文件夹中找到这个例子的完整源代码。

我们将更多地玩转`Paint`对象及其属性，但现在，让我们开始绘制更多的基础图形。

# 绘制更多的基础图形

让我们从最简单的绘图操作开始：`drawColor(int color)`，`drawARGB(int a, int r, int g, int b)`，`drawRGB(int r, int g, int b)`，以及`drawPaint(Paint paint)`。这些将填充整个`canvas`，考虑到裁剪区域。

现在让我们来看看`drawRect()`和`drawRoundRect()`。这两个方法也非常简单，`drawRect()`将绘制一个矩形，而`drawRoundRect()`将绘制具有圆角边框的矩形。

我们可以直接使用这两种方法，指定坐标或使用`Rect`。让我们创建一个简单的例子，它将在每次绘制视图或调用其`onDraw()`方法时绘制一个新的随机圆角矩形。

首先，定义两个`ArrayLists`；一个将保存矩形的坐标，另一个将保存矩形的颜色信息：

```kt
private Paint paint; 
private ArrayList<Float> rects; 
private ArrayList<Integer> colors; 
```

我们还声明了一个`Paint`对象，用于绘制所有圆角矩形。现在让我们来初始化它们：

```kt
public PrimitiveDrawer(Context context, AttributeSet attributeSet) { 
    super(context, attributeSet); 

    rects = new ArrayList<>(); 
    colors = new ArrayList<>(); 

    paint = new Paint(); 
    paint.setStyle(Paint.Style.FILL); 
    paint.setAntiAlias(true); 
} 
```

我们将 paint 对象的样式设置为 `Paint.Style.FILL` 并设置了 `AntiAlias` 标志，但我们还没有设置颜色。我们将在绘制每个矩形之前这样做。

现在让我们实现我们的 `onDraw()` 方法。首先，我们将添加四个新的随机坐标。由于 `Math.random()` 返回从 `0` 到 `1` 的值，我们将其乘以当前视图的宽度和高度以获得适当的视图坐标。我们还生成了一个具有完全不透明度的新随机颜色：

```kt
@Override 
protected void onDraw(Canvas canvas) { 
    canvas.drawColor(BACKGROUND_COLOR); 

    int width = getWidth(); 
    int height = getHeight(); 

    for (int i = 0; i < 2; i++) { 
        rects.add((float) Math.random() * width); 
        rects.add((float) Math.random() * height); 
    } 
    colors.add(0xff000000 | (int) (0xffffff * Math.random())); 

    for (int i = 0; i < rects.size() / 4; i++) { 
        paint.setColor(colors.get(i)); 
        canvas.drawRoundRect( 
                rects.get(i * 4    ), 
                rects.get(i * 4 + 1), 
                rects.get(i * 4 + 2), 
                rects.get(i * 4 + 3), 
                40, 40, paint); 
    } 

    if (rects.size() < 400) postInvalidateDelayed(20); 
} 
```

然后，我们将遍历我们添加的所有随机点，并一次取 `4` 个，假设前两个将是矩形的起始 X 和 Y，后两个将是矩形的结束 X 和 Y 坐标。我们将圆角的角度硬编码为 `40`。我们可以调整这个值来改变圆角的大小。

我们已经介绍了颜色上的位运算。我们知道可以将颜色存储在 32 位整数值中，通常是以 ARGB 格式。这样每个分量就有 8 位。通过位运算，我们可以轻松地操作颜色。关于位运算的更多信息，请参考：

[位运算](https://en.wikipedia.org/wiki/Bitwise_operation)。

最后，如果我们数组中的矩形少于 `100` 个或坐标少于 `400` 个，我们会发送一个延迟 `20` 毫秒的 `Invalidate` 事件。这只是为了演示目的，并显示它正在添加和绘制更多的矩形。通过仅移除两个硬编码的 `40` 作为圆角的角度，`drawRoundRect()` 方法可以很容易地更改为 `drawRect()`。

让我们看看结果：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/bd7c0838-689e-4951-b557-940f215def1a.png)

要查看完整源代码，请检查 GitHub 仓库中的 `Example14-Primitives-Rect` 文件夹。

让我们继续讨论其他原语，例如 `drawPoints`。`drawPoints(float[] points, Paint paint)` 方法将简单地绘制一系列点。它将使用 `paint` 对象的笔触宽度和笔触 `Cap`。例如，一个快速示例，绘制几条随机线，并在每条线的开始和结束处都绘制一个点：

```kt
@Override 
protected void onDraw(Canvas canvas) { 
    canvas.drawColor(BACKGROUND_COLOR); 

    if (points == null) { 
        points = new float[POINTS * 2]; 
        for(int i = 0; i < POINTS; i++) { 
            points[i * 2    ] = (float) Math.random() * getWidth(); 
            points[i * 2 + 1] = (float) Math.random() * getHeight(); 
        } 
    } 

    paint.setColor(0xffa0a0a0); 
    paint.setStrokeWidth(4.f); 
    paint.setStrokeCap(Paint.Cap.BUTT); 
    canvas.drawLines(points, paint); 

    paint.setColor(0xffffffff); 
    paint.setStrokeWidth(10.f); 
    paint.setStrokeCap(Paint.Cap.ROUND); 
    canvas.drawPoints(points, paint); 
} 
```

让我们看看结果：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/c54012c6-98f1-4eff-b43d-ce100ae7acf6.png)

我们在这里的 `onDraw()` 方法中创建 points 数组，但这只做一次。

在 GitHub 仓库的 `Example15-Primitives-Points` 文件夹中查看这个例子的完整源代码。

在上一个示例的基础上，我们可以轻松引入 `drawCircle` 原语。不过，让我们稍微改一下代码；不是只生成随机值对，而是生成三个随机值。前两个将是圆的 `X` 和 `Y` 坐标，第三个是圆的半径。此外，为了清晰起见，我们删除了线条：

```kt
@Override 
protected void onDraw(Canvas canvas) { 
    canvas.drawColor(BACKGROUND_COLOR); 

    if (points == null) { 
        points = new float[POINTS * 3]; 
        for(int i = 0; i < POINTS; i++) { 
            points[i * 3    ] = (float) Math.random() * getWidth(); 
            points[i * 3 + 1] = (float) Math.random() * getHeight(); 
            points[i * 3 + 2] = (float) Math.random() * (getWidth()/4); 
        } 
    } 

    for (int i = 0; i < points.length / 3; i++) { 
        canvas.drawCircle( 
                points[i * 3    ], 
                points[i * 3 + 1], 
                points[i * 3 + 2], 
                paint); 
    } 
} 
```

我们还在类构造函数中初始化了 `paint` 对象：

```kt
paint = new Paint(); 
paint.setStyle(Paint.Style.FILL); 
paint.setAntiAlias(true); 
paint.setColor(0xffffffff); 
```

让我们看看结果：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/cb2b47d2-cd97-4573-b4aa-3a21886b8c4e.png)

在 GitHub 仓库的 `Example16-Primitives-Circles` 文件夹中查看这个例子的完整源代码。

要了解有关在`Canvas`上绘制所有基本图形、模式和方法的详细信息，请查看 Android 文档。

可以将 Path 视为包含基本图形、线条、曲线以及其他几何形状的容器，正如我们已经看到的，它们可以用作裁剪区域、绘制或在其上绘制文本。

首先，让我们修改之前的示例，并将所有圆转换为`Path`：

```kt
@Override 
protected void onDraw(Canvas canvas) { 
    if (path == null) { 
        float[] points = new float[POINTS * 3]; 
        for(int i = 0; i < POINTS; i++) { 
            points[i * 3    ] = (float) Math.random() * getWidth(); 
            points[i * 3 + 1] = (float) Math.random() * getHeight(); 
            points[i * 3 + 2] = (float) Math.random() * (getWidth()/4); 
        } 

        path = new Path(); 

        for (int i = 0; i < points.length / 3; i++) { 
            path.addCircle( 
                    points[i * 3    ], 
                    points[i * 3 + 1], 
                    points[i * 3 + 2], 
                    Path.Direction.CW); 
        } 

        path.close(); 
    } 
```

我们不需要存储点，因此将其声明为局部变量。我们创建了一个`Path`对象。现在我们有了这个包含所有圆的`Path`，可以通过调用`drawPath(Path path, Paint paint)`方法绘制它，或者用作裁剪遮罩。

我们向项目中添加了一张图片，并将其作为背景图像绘制，但我们将应用由我们的`Path`定义的裁剪遮罩以增加趣味：

```kt
    canvas.save(); 

    if (!touching) canvas.clipPath(path); 
    if(background != null) { 
        backgroundTranformation.reset(); 
        float scale = ((float) getWidth()) / background.getWidth(); 
        backgroundTranformation.postScale(scale, scale); 
        canvas.drawBitmap(background, backgroundTranformation, null); 
    } 
    canvas.restore(); 
} 
```

让我们看看结果：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/3d2481dd-8a7f-49c3-b050-5f7b4929fa05.png)

要查看此示例的完整源代码，请检查 GitHub 仓库中的`Example17-Paths`文件夹。

查看有关 Paths 的 Android 文档，我们可以看到有很多方法可以向`Path`添加基本图形，例如：

+   `addCircle()`

+   `addRect()`

+   `addRoundRect()`

+   `addPath()`

然而，我们不仅限于这些方法，我们还可以使用`lineTo`或`moveTo`方法添加线条或位移我们 path 的下一个元素的起始位置。如果我们想使用相对坐标，`Path`类为我们提供了`rLineTo`和`rMoveTo`方法，这些方法假设给定的坐标相对于`Path`的最后一个点。

有关`Path`及其方法的更多信息，请查看 Android 文档网站。我们可以使用`cubicTo`和`quadTo`方法来实现。贝塞尔曲线由控制点组成，这些控制点控制平滑曲线的形状。让我们构建一个快速示例，通过在用户每次点击屏幕时添加控制点。

首先，让我们定义两个`Paint`对象，一个用于贝塞尔线，另一个用于绘制控制点以供参考：

```kt
pathPaint = new Paint(); 
pathPaint.setStyle(Paint.Style.STROKE); 
pathPaint.setAntiAlias(true); 
pathPaint.setColor(0xffffffff); 
pathPaint.setStrokeWidth(5.f); 

pointsPaint = new Paint(); 
pointsPaint.setStyle(Paint.Style.STROKE); 
pointsPaint.setAntiAlias(true); 
pointsPaint.setColor(0xffff0000); 
pointsPaint.setStrokeCap(Paint.Cap.ROUND); 
pointsPaint.setStrokeWidth(40.f); 
```

控制点将以红色的圆点绘制，而贝塞尔线将以较细的白色线条绘制。在我们初始化对象时，也定义一个空的`Path`和浮点数数组来存储点：

```kt
points = new ArrayList<>(); 
path = new Path(); 
```

现在，让我们重写`onTouchEvent()`，以添加用户点击屏幕的位置，并通过调用 invalidate 方法触发我们自定义视图的重绘。

```kt
@Override 
public boolean onTouchEvent(MotionEvent event) { 
    if (event.getAction() == MotionEvent.ACTION_DOWN) { 
        points.add(event.getX()); 
        points.add(event.getY()); 

        invalidate(); 
    } 

    return super.onTouchEvent(event); 
} 
```

在我们的`onDraw()`方法中，首先检查是否已经有三个点。如果是这样，让我们向`Path`添加一个三次贝塞尔曲线：

```kt
while(points.size() - currentIndex >= 6) { 
    float x1 = points.get(currentIndex); 
    float y1 = points.get(currentIndex + 1); 

    float x2 = points.get(currentIndex + 2); 
    float y2 = points.get(currentIndex + 3); 

    float x3 = points.get(currentIndex + 4); 
    float y3 = points.get(currentIndex + 5); 

    if (currentIndex == 0) path.moveTo(x1, y1); 
    path.cubicTo(x1, y1, x2, y2, x3, y3); 
    currentIndex += 6; 
} 
```

`currentIndex`保持已插入到`Path`的点数组最后一个索引。

现在，让我们绘制`Path`和点：

```kt
canvas.drawColor(BACKGROUND_COLOR); 
canvas.drawPath(path, pathPaint); 

for (int i = 0; i < points.size() / 2; i++) { 
    float x = points.get(i * 2    ); 
    float y = points.get(i * 2 + 1); 
    canvas.drawPoint(x, y, pointsPaint); 
} 
```

让我们看看结果：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/7f6bcce8-2242-4eba-887b-629a65ee7777.png)

在 GitHub 仓库的`Example18-Paths`文件夹中查看此示例的完整源代码。

# 绘制文本

从`Canvas`操作的角度来看，文本可以被认为是一个基本元素，但我们将它单独放在这里，因为它非常重要。我们没有从最简单的例子开始，因为我们刚刚介绍了路径，我们将继续上一个例子，在`Path`顶部绘制文本。要绘制文本，我们将重用贝塞尔曲线的`Paint`对象，但我们将添加一些文本参数：

```kt
pathPaint.setTextSize(50.f); 
pathPaint.setTextAlign(Paint.Align.CENTER); 
```

这设置了文本的大小，并将文本对齐到`Path`的中心，这样每次我们添加新点时，文本位置都会适应保持居中。要绘制文本，我们只需调用`drawTextOnPath()`方法：

```kt
canvas.drawTextOnPath("Building Android UIs with Custom Views", path, 0, 0, pathPaint); 
```

这是我们代码中一个非常快速的增加，但如果我们执行我们的应用程序，我们可以看到文本覆盖在`Path`线条上的结果：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/0dad2444-d349-4e37-891e-1bcf98d01ac0.png)

请记住，我们正在绘制之前绘制过的相同内容，但我们可以自由地使用`Path`作为文本的指导。无需绘制它或绘制控制点。

在 GitHub 仓库的`Example19-Text folder`中查看这个例子的完整源代码。

我们已经开始在路径上绘制文本，因为我们的例子几乎已经构建完成。然而，还有更简单的方法来绘制文本。例如，我们可以通过调用`canvas.drawText(String text, float x, float y, Paint paint)`或`canvas.drawText(char[] text, float x, float y, Paint paint)`在屏幕上的特定位置绘制文本。

这些方法只会完成它们的工作，但它们不会检查文本是否适合可用空间，而且绝对不会拆分和换行文本。要做到这一点，我们必须自己动手。`Paint`类为我们提供了测量文本和计算文本边界的方法。例如，我们创建了一个小助手方法，它返回`String`的宽度和高度：

```kt
private static final float[] getTextSize(String str, Paint paint) { 
    float[] out = new float[2]; 
    Rect boundaries = new Rect(); 
    paint.getTextBounds(str, 0, str.length(), boundaries); 

    out[0] = paint.measureText(str); 
    out[1] = boundaries.height(); 
    return out; 
} 
```

我们使用了文本边界来获取文本高度，但我们使用了`measureText()`方法来获取文本宽度。这两种方法在计算大小上有一些差异。尽管目前 Android 的官方文档网站上没有正确记录这一点，但在 Stack Overflow 上有一个关于这个问题的旧讨论：

[`stackoverflow.com/questions/7549182/android-paint-measuretext-vs-gettextbounds`](http://stackoverflow.com/questions/7549182/android-paint-measuretext-vs-gettextbounds)。

然而，我们不应该实现自己的文本拆分方法。如果我们想要绘制大段文本，并且我们知道它可能需要拆分和换行，我们可以使用`StaticLayout`类。在这个例子中，我们将创建一个宽度为视图宽度一半的`StaticLayout`。

我们可以在我们的`onLayout()`方法中实现它：

```kt
@Override 
protected void onLayout(boolean changed, int left, int top, int right, int bottom) { 
    super.onLayout(changed, left, top, right, bottom); 

    // create a layout of half the width of the View 
    if (layout == null) { 
        layout = new StaticLayout( 
                LONG_TEXT, 
                0, 
                LONG_TEXT.length(), 
                paint, 
                (right - left) / 2, 
                Layout.Alignment.ALIGN_NORMAL, 
                1.f, 
                1.f, 
                true); 
    } 
} 
```

在我们的`onDraw()`方法中，我们将它绘制在屏幕中心。我们知道，布局宽度是视图宽度的一半；我们知道我们需要将其位移到宽度的四分之一处。

```kt
@Override 
protected void onDraw(Canvas canvas) { 
    canvas.drawColor(BACKGROUND_COLOR); 

    canvas.save(); 
    // center the layout on the View 
    canvas.translate(canvas.getWidth()/4, 0); 
    layout.draw(canvas); 
    canvas.restore(); 
} 
```

这是结果：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/3ff97fdf-3797-4dc0-a960-57061d606d7d.png)

在 GitHub 仓库的`Example20-Text`文件夹中查看这个示例的完整源代码。

# 变换和操作

在我们的自定义视图上，我们已经使用了一些`canvas`变换，但让我们重新审视我们可以使用的`Canvas`操作。首先，让我们看看如何连接这些变换。一旦我们使用了变换，我们使用的任何其他变换都会被连接或应用在我们之前的操作之上。为了避免这种行为，我们必须调用我们之前也使用过的`save()`和`restore()`方法。为了了解变换是如何层层叠加的，让我们创建一个简单的示例。

首先，在我们构造函数中创建一个`paint`对象：

```kt
public PrimitiveDrawer(Context context, AttributeSet attributeSet) { 
    super(context, attributeSet); 

    paint = new Paint(); 
    paint.setStyle(Paint.Style.STROKE); 
    paint.setAntiAlias(true); 
    paint.setColor(0xffffffff); 
} 
```

现在，让我们在`onLayout()`方法中根据屏幕大小计算矩形尺寸：

```kt
@Override 
 protected void onLayout(boolean changed, int left, int top, int right,
 int bottom) { 
     super.onLayout(changed, left, top, right, bottom); 

     int smallerDimension = (right - left); 
     if (bottom - top < smallerDimension) smallerDimension = bottom -
     top; 

     rectSize = smallerDimension / 10; 
     timeStart = System.currentTimeMillis(); 
} 
```

我们还存储了开始时间，稍后我们将使用它进行快速简单的动画。现在，我们准备实现`onDraw()`方法：

```kt
@Override 
protected void onDraw(Canvas canvas) { 
    float angle = (System.currentTimeMillis() - timeStart) / 100.f; 

    canvas.drawColor(BACKGROUND_COLOR); 

    canvas.save(); 
    canvas.translate(canvas.getWidth() / 2, canvas.getHeight() / 2); 

    for (int i = 0; i < 15; i++) { 
        canvas.rotate(angle); 
        canvas.drawRect(-rectSize / 2, -rectSize / 2, rectSize / 2,
        rectSize / 2, paint); 
        canvas.scale(1.2f, 1.2f); 
    } 

    canvas.restore(); 
    invalidate(); 
} 
```

我们首先根据自开始以来经过的时间计算了`angle`。动画应该总是基于时间，而不是基于绘制的帧数。

然后，我们绘制背景，通过调用`canvas.save()`保存`canvas`状态，并进行平移到屏幕中心。我们将所有的变换和绘制都基于中心，而不是左上角。

在这个示例中，我们将绘制 15 个矩形，每个矩形都会逐渐旋转和缩放。由于变换是层层叠加的，因此在一个简单的`for()`循环中很容易实现。重要的是要从`-rectSize / 2`绘制到`rectSize / 2`，而不是从`0`到`rectSize`；否则，它将从一个角度旋转。

修改我们绘制矩形的代码行，改为`canvas.drawRect(0, 0, rectSize, rectSize, paint)`，看看会发生什么。

然而，这种方法有一个替代方案：我们可以在变换中使用枢轴点。`rotate()`和`scale()`方法都支持两个额外的`float`参数，它们是枢轴点的坐标。如果我们查看`scale(float sx, float sy, float px, float py)`的源代码实现，我们可以看到它只是应用了一个平移，调用了简单的缩放方法，然后应用了相反的平移：

```kt
public final void scale(float sx, float sy, float px, float py) { 
    translate(px, py); 
    scale(sx, sy);
    translate(-px, -py); 
} 
```

使用这种方法，我们可以以另一种方式实现`onDraw()`方法：

```kt
@Override 
protected void onDraw(Canvas canvas) { 
    float angle = (System.currentTimeMillis() - timeStart) / 100.f; 

    canvas.drawColor(BACKGROUND_COLOR); 

    canvas.save(); 
    canvas.translate(canvas.getWidth() / 2, 
                     canvas.getHeight() / 2); 

    for (int i = 0; i < 15; i++) { 
        canvas.rotate(angle, rectSize / 2, rectSize / 2); 
        canvas.drawRect(0, 0, rectSize, rectSize, paint); 
        canvas.scale(1.2f, 1.2f, rectSize / 2, rectSize / 2); 
    } 

    canvas.restore(); 
    invalidate(); 
} 
```

查看以下截图，了解矩形的连接方式：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/8235837e-4edc-49f9-9f1e-842f8fe94de8.png)

此外，这个完整示例的源代码可以在 GitHub 仓库的`Example21-Transformations`文件夹中找到。

我们已经了解了一些关于矩阵的基本操作，比如`scale()`、`rotate()`和`translate()`，但`canvas`为我们提供了更多附加方法：

+   `skew`：这应用一个斜切变换。

+   `setMatrix`：这让我们计算一个变换矩阵，并直接将其设置到我们的`canvas`中。

+   `concat`：这类似于前面的情况。我们可以将任何矩阵与当前矩阵进行拼接。

# 将它们全部组合在一起

到目前为止，我们已经看到了许多不同的绘图原语、剪辑操作和矩阵变换，但最有趣的部分是我们将它们全部组合在一起的时候。为了构建出色的自定义视图，我们必须使用许多不同类型的操作和变换。

然而，拥有如此多的操作是一个双刃剑。在向自定义视图添加这种复杂性时，我们必须小心，因为很容易损害性能。我们应该检查是否应用了过多的或不必要的剪辑操作，或者是否没有足够优化，或者没有最大化剪辑和变换操作的重用。在这种情况下，我们甚至可以使用`canvas`对象的`quickReject()`方法快速丢弃将落在剪辑区域外的区域。

同时，我们需要跟踪我们对`canvas`执行的所有`save()`和`restore()`。执行额外的`restore()`方法，不仅意味着我们的代码存在问题，实际上它是一个错误。如果我们需要改变到不同的先前保存的状态，我们可以使用`restoreToCount()`方法，并结合保存状态编号的调用来保存状态。

正如我们之前提到的，并在后续章节中会再次提到，避免在`onDraw()`方法中分配内存或创建对象的新实例；特别是如果你认为需要在`onDraw()`内部创建一个新的`paint`对象实例时，请记住这一点。重用`paint`对象或在类构造函数中初始化它们。

# 总结

在本章中，我们了解了如何绘制更复杂的图形原语，变换它们，并在绘制自定义视图时使用剪辑操作。大多数情况下，这些原语本身并不能为我们提供太多价值，但我们还看到了许多快速示例，展示了如何将它们组合在一起创建有用的东西。我们没有涵盖所有可能的方法、操作或变换，因为这将包含大量信息并且可能不实用；它可能会像是阅读一本语言字典。要了解所有可能的方法和绘图原语，请持续查看开发者的 Android 文档，并关注每个新版本的 Android 的发行说明，以了解新增内容。

在下一章中，我们将了解如何使用 OpenGL ES 为自定义视图添加 3D 渲染。


# 第五章：引入 3D 自定义视图

在前面的章节中，我们已经了解了如何使用安卓 2D 图形库实现自定义视图。这是我们最常用的方法，但在某些情况下，由于额外的渲染特性或自定义视图的需求，我们可能需要更多的性能。在这些情况下，我们可能会使用**嵌入式系统 OpenGL**（**OpenGL ES**），并在我们的视图中启用 3D 渲染操作。

在本章中，我们将了解如何在自定义视图中使用 OpenGL ES，并展示一个实际示例，说明我们如何构建一个。更详细地说，我们将涵盖以下主题：

+   OpenGL ES 简介

+   绘制几何体

+   加载外部几何体

# OpenGL ES 简介

安卓支持 OpenGL ES 进行 3D 渲染。OpenGL ES 是桌面**OpenGL API**实现的一个子集。**开放图形库**（**OpenGL**）本身是一个非常流行的跨平台 API，用于渲染 2D 和 3D 图形。

使用 OpenGL ES 来渲染我们的自定义视图比标准的安卓画布绘制原语要稍微复杂一些，正如我们将在本章中看到的，它需要与常识一起使用，并不总是最佳方法。

有关 OpenGL ES 的任何额外信息，请参考 Khronos 集团的官方文档：

[Khronos 集团的 OpenGL ES 官方文档](https://www.khronos.org/opengles/).

# 在安卓中开始使用 OpenGL ES

创建一个支持 3D 的自定义视图非常简单。我们可以通过简单地扩展`GLSurfaceView`而不是仅从`View`类扩展来实现。复杂性在于渲染部分，但让我们一步一步来。首先，我们将创建一个名为`GLDrawer`的类并将其添加到我们的项目中：

```kt
package com.packt.rrafols.draw; 

import android.content.Context; 
import android.opengl.GLSurfaceView; 
import android.util.AttributeSet; 

public class GLDrawer extends GLSurfaceView { 
    private GLRenderer glRenderer; 

    public GLDrawer(Context context, AttributeSet attributeSet) { 
        super(context, attributeSet); 
    } 
} 
```

与我们之前的示例一样，我们使用`AttributeSet`创建了构造函数，因此我们可以从 XML 布局文件中充气并设置参数（如果需要的话）。

我们可能会认为 OpenGL ES 只用于全屏游戏，但它也可以用于非全屏视图，甚至可以在`ViewGroups`或`ScrollView`内部使用。

为了观察其行为，让我们将其添加到两个`TextView`之间的`layout`文件中：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<LinearLayout  

    android:id="@+id/activity_main" 
    android:layout_width="match_parent" 
    android:layout_height="match_parent" 
    android:orientation="vertical" 
    android:padding="@dimen/activity_vertical_margin" 
    tools:context="com.packt.rrafols.draw.MainActivity"> 

<TextView 
        android:layout_width="match_parent" 
        android:layout_height="100dp" 
        android:background="@android:color/background_light" 
        android:gravity="center_vertical|center_horizontal" 
        android:text="@string/filler_text"/> 

<com.packt.rrafols.draw.GLDrawer 
        android:layout_width="match_parent" 
        android:layout_height="100dp"/> 

<TextView 
        android:layout_width="match_parent" 
        android:layout_height="100dp" 
        android:background="@android:color/background_light" 
        android:gravity="center_vertical|center_horizontal" 
        android:text="@string/filler_text"/> 
</LinearLayout> 
```

在我们的`GLDrawer`类可以工作之前，我们需要进行一个额外的步骤。我们必须创建一个`GLSurfaceView.Renderer`对象来处理所有的渲染工作，并通过使用`setRenderer()`方法将其设置到视图中。当我们设置这个渲染器时，`GLSurfaceView`将额外创建一个新线程来管理视图的绘制周期。让我们在`GLDrawer`类文件的末尾添加一个`GLRenderer`类：

```kt
class GLRenderer implements GLSurfaceView.Renderer { 
    @Override 
    public void onSurfaceCreated(GL10 gl, EGLConfig config) { 

    } 

    @Override 
    public void onSurfaceChanged(GL10 gl, int width, int height) { 

    } 

    @Override 
    public void onDrawFrame(GL10 gl) { 
        gl.glClearColor(1.f, 0.f, 0.f, 1.f); 
        gl.glClear(GL10.GL_COLOR_BUFFER_BIT); 
    } 
} 
```

`glClearColor()`方法告诉 OpenGL 我们希望从屏幕上清除哪种颜色。我们设置了四个分量：红色、绿色、蓝色和 alpha，以浮点格式表示，范围从`0`到`1`。`glClear()`是实际清除屏幕的方法。由于 OpenGL 还可以清除其他几个缓冲区，如果我们设置了`GL_COLOR_BUFFER_BIT`标志，它才会清除屏幕。现在我们已经介绍了一些 OpenGL 函数，让我们创建一个`GLRenderer`实例变量，并在类构造函数中初始化它：

```kt
private GLRenderer glRenderer;
public GLDrawer(Context context, AttributeSet attributeSet) { 
    super(context, attributeSet); 
    glRenderer = new GLRenderer()
    setRenderer(glRenderer);
} 
```

实现一个`GLSurfaceView.Renderer`类时，我们必须重写以下三个方法或回调：

+   `onSurfaceCreated()`: 每当 Android 需要创建 OpenGL 上下文时，都会调用此方法——例如，在首次创建渲染线程时，或者每次 OpenGL 上下文丢失时。当应用程序进入后台时，上下文可能会丢失。这个回调是放置所有依赖于 OpenGL 上下文的初始化代码的理想方法。

+   `onSurfaceChanged()`: 当视图大小发生变化时，将调用此方法。在第一次创建表面时也会被调用。

+   `onDrawFrame()`: 此方法是负责实际绘制的内容，并且每次需要绘制视图时都会被调用。

在我们的示例中，我们留下了`onSurfaceCreated()`和`onSurfaceChanged()`方法为空，因为此时我们只关注绘制实心背景以检查是否一切正常工作，而且我们暂时还不需要视图的大小。

如果我们运行这个示例，我们将看到两个`TextView`和带有红色背景的自定义视图：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/55be06cb-b0bb-4248-9da3-cbbe3d4bbd7e.png)

如果我们在`onDrawFrame()`方法中设置断点或打印日志，我们将看到视图在不断地重绘。这种行为与普通视图不同，因为渲染线程会不断调用`onDrawFrame()`方法。通过调用设置渲染器对象后的`setRender()`方法，可以修改这种行为。如果我们在此之前调用它，应用程序将会崩溃。有两种渲染模式：

+   `setRenderMode`(`RENDERMODE_CONTINUOUSLY`): 这是默认行为。渲染器将不断被调用以渲染视图。

+   `setRenderMode`(`RENDERMODE_WHEN_DIRTY`): 可以设置此选项以避免视图的连续重绘。我们不需要调用 invalidate，而必须调用`requestRender`来请求视图的新渲染。

# 绘制基本几何图形

我们已经初始化了视图并绘制了一个实心的红色背景。接下来让我们绘制一些更有趣的内容。在以下示例中，我们将关注 OpenGL ES 2.0，因为它自 Android 2.2 或 API 级别 8 起就已经可用，而且解释如何在 OpenGL ES 1.1 中实现它并没有太大意义。然而，如果你想了解更多，GitHub 上有些将旧的 NeHe OpenGL ES 教程移植到 Android 的项目：

[`github.com/nea/nehe-android-ports`](https://github.com/nea/nehe-android-ports)。

OpenGLES 1.1 和 OpenGL ES 2.0 的代码是不兼容的，因为 OpenGL ES 1.1 的代码基于固定功能管线，你需要指定几何体、灯光等，而 OpenGL ES 2.0 基于可编程管线，由顶点和片段着色器处理。

首先，由于我们需要 OpenGL ES 2.0，应该在清单文件中添加一个`uses-feature`配置行，这样 Google Play 就不会将应用程序展示给不兼容的设备：

```kt
<application> 
    .... 
<uses-feature android:glEsVersion="0x00020000" android:required="true" /> 
    ... 
</application> 
```

如果我们使用 OpenGL ES3.0 的特定 API，我们应该将要求更改为`android:glEsVersion="0x00030000"`，以便 Google Play 相应地进行筛选。

完成这一步后，我们可以开始绘制更多形状和几何体。但在设置渲染器之前，我们应该将渲染器上下文设置为`2`，以便创建一个 OpenGL ES 2.0 上下文。我们可以通过修改`GLDrawer`类的构造函数轻松实现这一点：

```kt
public GLDrawer(Context context, AttributeSet attributeSet) { 
    super(context, attributeSet); 
    setEGLContextClientVersion(2);
    glRenderer = new GLRenderer(); 
    setRenderer(glRenderer); 
} 
```

现在我们一步一步来学习如何在屏幕上画一个矩形。如果你熟悉 OpenGL ES 1.1 但不熟悉 OpenGL ES 2.0，你会发现这里需要多做一点工作，但最终，我们将从 OpenGL ES 2.0 的额外灵活性和强大功能中受益。

我们将从定义一个以位置`0, 0, 0`为中心的矩形或四边形的坐标数组开始：

```kt
private float quadCoords[] = { 
    -1.f, -1.f, 0.0f, 
    -1.f,  1.f, 0.0f, 
     1.f,  1.f, 0.0f, 
     1.f, -1.f, 0.0f 
 }; 
```

我们要画三角形，因此需要定义它们的顶点索引：

```kt
private short[] index = { 
    0, 1, 2, 
    0, 2, 3 
}; 
```

要理解这些索引背后的逻辑，如何将它们映射到我们之前定义的顶点索引，以及如何使用两个三角形来绘制一个四边形，请看以下图表：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/553dbbb6-5901-4c39-9689-13577d604010.png)

如果我们画一个顶点为`0`、`1`和`2`的三角形，再画一个顶点为`0`、`2`和`3`的三角形，最终我们会得到一个四边形。

在使用 OpenGL ES 时，我们需要使用`Buffer`或其子类来提供数据，因此让我们将这些数组转换为`Buffer`：

```kt
ByteBuffer vbb = ByteBuffer.allocateDirect(quadCoords.length * (Float.SIZE / 8)); 
vbb.order(ByteOrder.nativeOrder()); 

vertexBuffer = vbb.asFloatBuffer(); 
vertexBuffer.put(quadCoords); 
vertexBuffer.position(0); 
```

首先，我们需要为`Buffer`分配所需的空间。由于我们知道数组的大小，这会非常简单：只需将其乘以浮点数的大小（以字节为单位）。一个浮点数正好是四个字节，但我们也可以通过获取位数（使用`Float.SIZE`）并除以`8`来计算。在 Java 8 中，有一个名为`Float.BYTES`的新常量，它正好返回以字节为单位的大小。

我们需要指出，我们放入数据的`Buffer`将具有平台的本地字节序。我们可以通过在`Buffer`上调用`order()`方法，并以`ByteOrder.nativeOrder()`作为参数来实现这一点。完成这一步后，我们可以通过调用`Buffer.asFloatBuffer()`将其转换为浮点缓冲区，并设置数据。最后，我们将`Buffer`的位置重置为开始位置，即设置为`0`。

我们必须为顶点以及索引执行这个过程。由于索引作为短整数存储，我们在转换缓冲区以及计算大小时需要考虑这一点。

```kt
ByteBuffer ibb = ByteBuffer.allocateDirect(index.length * (Short.SIZE / 8)); 
ibb.order(ByteOrder.nativeOrder()); 

indexBuffer = ibb.asShortBuffer(); 
indexBuffer.put(index); 
indexBuffer.position(0); 
```

如前所述，OpenGL ES 2.0 渲染管线由顶点和片段`shader`处理。让我们创建一个辅助方法来加载和编译`shader`代码：

```kt
// Source: 
// https://developer.android.com/training/graphics/opengl/draw.html 
public static int loadShader(int type, String shaderCode){ 

    // create a vertex shader type (GLES20.GL_VERTEX_SHADER) 
    // or a fragment shader type (GLES20.GL_FRAGMENT_SHADER) 
    int shader = GLES20.glCreateShader(type); 

    // add the source code to the shader and compile it 
    GLES20.glShaderSource(shader, shaderCode); 
    GLES20.glCompileShader(shader); 

    return shader; 
} 
```

使用这个新方法，我们可以加载顶点和片段`shaders`：

```kt
private void initShaders() { 
    int vertexShader = loadShader(GLES20.GL_VERTEX_SHADER, vertexShaderCode); 
    int fragmentShader = loadShader(GLES20.GL_FRAGMENT_SHADER, fragmentShaderCode); 

    shaderProgram = GLES20.glCreateProgram(); 
    GLES20.glAttachShader(shaderProgram, vertexShader); 
    GLES20.glAttachShader(shaderProgram, fragmentShader); 
    GLES20.glLinkProgram(shaderProgram); 
} 
```

目前，让我们使用来自 Android 开发者 OpenGL 培训网站的默认`shaders`。

`vertexShader`如下所示：

```kt
// Source: 
// https://developer.android.com/training/graphics/opengl/draw.html 
private final String vertexShaderCode = 
        // This matrix member variable provides a hook to manipulate 
        // the coordinates of the objects that use this vertex shader 
"uniform mat4 uMVPMatrix;" + 
"attribute vec4 vPosition;" + 
"void main() {" + 
        // The matrix must be included as a modifier of gl_Position. 
        // Note that the uMVPMatrix factor *must be first* in order 
        // for the matrix multiplication product to be correct. 
"  gl_Position = uMVPMatrix * vPosition;" + 
"}"; 
```

`fragmentShader`如下所示：

```kt
private final String fragmentShaderCode = 
"precision mediump float;" + 
"uniform vec4 vColor;" + 
"void main() {" + 
"  gl_FragColor = vColor;" + 
"}"; 
```

在我们的`vertexShader`中添加了矩阵乘法，因此我们可以通过更新`uMVPMatrix`来修改顶点的位置。让我们添加一个投影和一些变换，以便实现基本的渲染。

我们不应该忘记`onSurfaceChanged()`回调；让我们使用它来设置我们的投影矩阵，并定义相机的裁剪平面，考虑到屏幕的宽度和高度以保持其长宽比：

```kt
@Override 
public void onSurfaceChanged(GL10 unused, int width, int height) { 
    GLES20.glViewport(0, 0, width, height); 

    float ratio = (float) width / height; 
    Matrix.frustumM(mProjectionMatrix, 0, -ratio * 2, ratio * 2, -2, 2,
    3, 7); 
} 
```

让我们通过使用`Matrix.setLookAtM()`计算视图矩阵，并将其与我们刚刚在`mProjectionMatrix`上计算出的投影矩阵相乘：

```kt
@Override 
public void onDrawFrame(GL10 unused) { 

    ... 

    Matrix.multiplyMM(mMVPMatrix, 0, mProjectionMatrix, 0, mViewMatrix,
    0); 

    int mMVPMatrixHandle = GLES20.glGetUniformLocation(shaderProgram,
    "uMVPMatrix"); 
    GLES20.glUniformMatrix4fv(mMVPMatrixHandle, 1, false, mMVPMatrix,
    0); 

    ... 

} 
```

在前面的代码中，我们还看到了如何更新一个可以从`shader`中读取的变量。为此，我们首先需要获取统一变量的句柄。通过使用`GLES20.glGetUniformLocation(shaderProgram, "uMVPMatrix")`我们可以得到`uMVPMatrix`统一变量的句柄，并在`GLES20.glUniformMatrix4fv`调用中使用这个句柄，我们可以将刚刚计算出的矩阵设置到它上面。如果我们检查`shader`的代码，可以看到我们定义了`uMVPMatrix`为统一变量：

```kt
uniform mat4 uMVPMatrix; 
```

既然我们知道如何设置一个统一变量，那么对于颜色我们也做同样的处理。在片段`shader`中，我们将`vColor`也设置为统一变量，因此我们可以使用同样的方法来设置它：

```kt
float color[] = { 0.2f, 0.2f, 0.9f, 1.0f }; 

... 

int colorHandle = GLES20.glGetUniformLocation(shaderProgram, "vColor"); 
GLES20.glUniform4fv(colorHandle, 1, color, 0); 
```

使用同样的机制，但将`glGetUniformLocation`更改为`glGetAttribLocation`，我们也可以设置顶点坐标：

```kt
int positionHandle = GLES20.glGetAttribLocation(shaderProgram, "vPosition"); 

GLES20.glVertexAttribPointer(positionHandle, 3, 
        GLES20.GL_FLOAT, false, 
        3 * 4, vertexBuffer); 
```

我们已经准备好将其绘制到屏幕上；我们只需要启用顶点属性数组，因为我们已经使用`glVertexAttribPointer()`调用和`glDrawElements()`只绘制启用的数组：

```kt
GLES20.glEnableVertexAttribArray(positionHandle); 

GLES20.glDrawElements( 
       GLES20.GL_TRIANGLES, index.length, 
       GLES20.GL_UNSIGNED_SHORT, indexBuffer); 

GLES20.glDisableVertexAttribArray(positionHandle); 
```

在 OpenGL 上绘制几何体的方法有很多，但我们使用了指向之前创建的面索引缓冲区的`glDrawElements()`调用。这里我们使用了`GL_TRIANGLES`图元，但还有许多其他的 OpenGL 图元可以使用。更多信息请查看 Khronos 官方文档关于`glDrawElements()`的部分：

[`www.khronos.org/registry/OpenGL-Refpages/gl4/html/glDrawElements.xhtml`](https://www.khronos.org/registry/OpenGL-Refpages/gl4/html/glDrawElements.xhtml)。

同时，作为良好的实践，并在绘制后恢复 OpenGL 机器状态，我们禁用了顶点属性数组。

如果我们执行这段代码，我们将得到以下结果——虽然还不是很有用，但这是一个开始！

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/9d92fb4b-de8c-40a2-b36d-acf1bc25cb0e.png)

在 GitHub 仓库中查看`Example23-GLSurfaceView`以获取完整的示例源代码。

# 绘制几何体

到目前为止，我们已经了解了如何设置 OpenGL 渲染器并绘制一些非常基础的几何图形。但是，正如你所想象的，我们可以利用 OpenGL 做更多的事情。在本节中，我们将了解如何进行一些更复杂的操作以及如何加载使用外部工具定义的几何图形。有时，使用代码定义几何图形可能很有用，但大多数时候，尤其是如果几何图形非常复杂，它将通过 3D 建模工具设计和创建。知道如何导入这些几何图形对我们项目肯定非常有帮助。

# 添加体积

在上一个例子中，我们已经了解了如何用单一颜色绘制四边形，但如果是每个顶点都有完全不同的颜色呢？这个过程与我们已经做的不会有很大不同，但让我们看看如何实现它。

首先，让我们改变颜色数组，使其包含四个顶点的颜色：

```kt
float color[] = { 
        1.0f, 0.2f, 0.2f, 1.0f, 
        0.2f, 1.0f, 0.2f, 1.0f, 
        0.2f, 0.2f, 1.0f, 1.0f, 
        1.0f, 1.0f, 1.0f, 1.0f, 
}; 
```

现在，在我们的`initBuffers()`方法中，我们来初始化一个额外的`Buffer`来存储颜色：

```kt
private FloatBuffer colorBuffer; 

... 

ByteBuffer cbb = ByteBuffer.allocateDirect(color.length * (Float.SIZE / 8)); 
cbb.order(ByteOrder.nativeOrder()); 

colorBuffer = cbb.asFloatBuffer(); 
colorBuffer.put(color); 
colorBuffer.position(0); 
```

我们还必须更新我们的`shaders`以考虑颜色参数。首先，在我们的`vertexShader`中，我们必须创建一个新的属性，我们将其称为`aColor`，以保存每个顶点的颜色：

```kt
private final String vertexShaderCode = 
"uniform mat4 uMVPMatrix;" + 
"attribute vec4 vPosition;" + 
"attribute vec4 aColor;" + 
"varying vec4 vColor;" + 
"void main() {" + 
"  gl_Position = uMVPMatrix * vPosition;" + 
"  vColor = aColor;" + 
"}"; 
```

然后，我们定义一个可变的`vColor`变量，该变量将传递给`fragmentShader`，而`fragmentShader`将计算每个片段的值。让我们看看`fragmentShader`上的变化：

```kt
private final String fragmentShaderCode = 
"precision mediump float;" + 
"varying vec4 vColor;" + 
"void main() {" + 
"  gl_FragColor = vColor;" + 
"}"; 
```

我们唯一改变的是`vColor`的声明；它不再是统一变量，现在是一个`varying`变量。

就像我们对顶点和面索引所做的那样，我们必须将颜色数据设置到`shader`中：

```kt
int colorHandle = GLES20.glGetAttribLocation(shaderProgram, "aColor"); 
GLES20.glVertexAttribPointer(colorHandle, 4, 
        GLES20.GL_FLOAT, false, 
        4 * 4, colorBuffer); 
```

在绘制之前，我们必须启用和禁用顶点数组。如果颜色数组没有被启用，我们将得到一个黑色的正方形，因为`glDrawElements()`将无法获取颜色信息；

```kt
GLES20.glEnableVertexAttribArray(colorHandle); 
GLES20.glEnableVertexAttribArray(positionHandle); 
GLES20.glDrawElements( 
        GLES20.GL_TRIANGLES, index.length, 
        GLES20.GL_UNSIGNED_SHORT, indexBuffer); 

GLES20.glDisableVertexAttribArray(positionHandle); 
GLES20.glDisableVertexAttribArray(colorHandle); 
```

如果我们运行这个例子，我们会看到与上一个例子相似的效果，但我们可以看到颜色是如何在顶点之间插值的：

![图片](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/5c79b673-9efb-487a-a670-b7b80d2f4857.png)

既然我们知道如何插值颜色，让我们在几何体中增加一些深度。到目前为止，我们所绘制的所有内容都非常平坦，所以让我们将四边形转换为立方体。这非常简单。首先定义顶点和新的面索引：

```kt
private float quadCoords[] = { 
       -1.f, -1.f, -1.0f, 
       -1.f,  1.f, -1.0f, 
        1.f,  1.f, -1.0f, 
        1.f, -1.f, -1.0f, 

       -1.f, -1.f,  1.0f, 
       -1.f,  1.f,  1.0f, 
        1.f,  1.f,  1.0f, 
        1.f, -1.f,  1.0f 
}; 
```

我们复制了之前相同的四个顶点，但是位移了*Z*坐标，这将给立方体增加体积。

现在，我们必须创建新的面索引。立方体有六个面，或者说四边形，可以用十二个三角形来复制：

```kt
private short[] index = { 
        0, 1, 2,        // front 
        0, 2, 3,        // front 
        4, 5, 6,        // back 
        4, 6, 7,        // back 
        0, 4, 7,        // top 
        0, 3, 7,        // top 
        1, 5, 6,        // bottom 
        1, 2, 6,        // bottom 
        0, 4, 5,        // left 
        0, 1, 5,        // left 
        3, 7, 6,        // right 
        3, 2, 6         // right 
}; 
```

同时为新的四个顶点添加新颜色：

```kt
float color[] = { 
        1.0f, 0.2f, 0.2f, 1.0f, 
        0.2f, 1.0f, 0.2f, 1.0f, 
        0.2f, 0.2f, 1.0f, 1.0f, 
        1.0f, 1.0f, 1.0f, 1.0f, 

        1.0f, 1.0f, 0.2f, 1.0f, 
        0.2f, 1.0f, 1.0f, 1.0f, 
        1.0f, 0.2f, 1.0f, 1.0f, 
        0.2f, 0.2f, 0.2f, 1.0f 
}; 
```

如果我们按原样执行这个例子，我们会得到一个类似以下截图的奇怪结果：

![图片](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/760e6080-d9a9-432e-b521-453297d9451e.png)

让我们给`mMVPMatrix`矩阵添加一个旋转变换，看看会发生什么。

我们必须定义一个私有变量来保存旋转角度，并将旋转应用到`mMVPMatrix`中：

```kt
private float angle = 0.f; 
... 
Matrix.setLookAtM(mViewMatrix, 0, 
        0, 0, -4, 
        0f, 0f, 0f, 
        0f, 1.0f, 0.0f); 

Matrix.multiplyMM(mMVPMatrix, 0, mProjectionMatrix, 0, mViewMatrix, 0); Matrix.rotateM(mMVPMatrix, 0, angle, 1.f, 1.f, 1.f);
```

在这个例子中，为了观察正在发生的事情，我们将旋转应用到三个轴：*x*、*y*和*z*。我们还稍微将相机从上一个示例中的位置移开，因为如果我们不这样做，现在可能会有一些剪辑。

为了定义我们必须旋转的角度，我们将使用一个 Android 定时器：

```kt
private long startTime; 
... 
@Override 
public void onSurfaceCreated(GL10 unused, EGLConfig config) { 
    initBuffers(); 
    initShaders(); 
    startTime = SystemClock.elapsedRealtime();
} 
```

我们在`startTime`变量上存储开始时间，在我们的`onDrawFrame()`方法中，我们根据自这一刻起经过的时间计算角度：

```kt
angle = ((float) SystemClock.elapsedRealtime() - startTime) * 0.02f; 
```

在这里，我们只是将其乘以`0.02f`以限制旋转速度，否则它会太快。这样做，动画速度将不受渲染帧率或 CPU 速度的影响，在所有设备上都是相同的。现在，如果我们运行这段代码，我们将看到我们遇到的问题的来源：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/5e919ddd-cbb4-4b83-9e1b-75d836ef6a17.png)

问题在于，OpenGL 在绘制所有三角形时没有检查像素的 z 坐标，因此可能会出现一些重叠和过度绘制，正如我们从前面的屏幕截图中轻易看到的那样。幸运的是，这个问题很容易解决。OpenGL 有一个状态，我们可以用它来启用和禁用深度（z）测试：

```kt
GLES20.glEnable(GLES20.GL_DEPTH_TEST);
GLES20.glEnableVertexAttribArray(colorHandle); 
GLES20.glEnableVertexAttribArray(positionHandle); 
GLES20.glDrawElements( 
        GLES20.GL_TRIANGLES, index.length, 
        GLES20.GL_UNSIGNED_SHORT, indexBuffer); 

GLES20.glDisableVertexAttribArray(positionHandle); 
GLES20.glDisableVertexAttribArray(colorHandle); GLES20.glDisable(GLES20.GL_DEPTH_TEST);
```

与上一个示例一样，在绘制之后，我们禁用我们启用的状态，以避免为任何其他绘图操作留下未知的 OpenGL 状态。如果我们运行这段代码，我们将看到差异：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/d984ccec-3892-428b-86df-98af92c587e0.png)

在 GitHub 仓库中查看`Example24-GLDrawing`以获取完整的示例源代码。

# 添加纹理

让我们继续做更有趣的事情！我们已经看到了如何为每个顶点添加颜色，但现在让我们看看如果我们想为 3D 对象添加一些纹理，我们需要做哪些改变。

首先，让我们将颜色数组替换为纹理坐标数组。我们将纹理坐标`0`映射到纹理的起点，在两个轴上都是如此，将`1`映射到纹理的终点，在两个轴上也是如此。使用我们上一个示例中的几何图形，我们可以这样定义纹理坐标：

```kt
private float texCoords[] = { 
        1.f, 1.f, 
        1.f, 0.f, 
        0.f, 0.f, 
        0.f, 1.f, 

        1.f, 1.f, 
        1.f, 0.f, 
        0.f, 0.f, 
        0.f, 1.f, 
}; 
```

为了加载这些纹理坐标，我们使用的流程与之前完全相同：

```kt
ByteBuffer tbb = ByteBuffer.allocateDirect(texCoords.length * (Float.SIZE / 8)); 
tbb.order(ByteOrder.nativeOrder()); 

texBuffer = tbb.asFloatBuffer(); 
texBuffer.put(texCoords); 
texBuffer.position(0); 
```

让我们也创建一个辅助方法来将资源加载到纹理中：

```kt
private int loadTexture(int resId) { 
    final int[] textureIds = new int[1]; 
    GLES20.glGenTextures(1, textureIds, 0); 

    if (textureIds[0] == 0) return -1; 

    // do not scale the bitmap depending on screen density 
    final BitmapFactory.Options options = new BitmapFactory.Options(); 
    options.inScaled = false; 

    final Bitmap textureBitmap =
    BitmapFactory.decodeResource(getResources(), resId, options); 
    GLES20.glBindTexture(GLES20.GL_TEXTURE_2D, textureIds[0]); 

    GLES20.glTexParameteri(GLES20.GL_TEXTURE_2D, 
            GLES20.GL_TEXTURE_MIN_FILTER, GLES20.GL_NEAREST); 

    GLES20.glTexParameteri(GLES20.GL_TEXTURE_2D, 
            GLES20.GL_TEXTURE_MAG_FILTER, GLES20.GL_NEAREST); 

    GLES20.glTexParameterf(GLES20.GL_TEXTURE_2D, 
            GLES20.GL_TEXTURE_WRAP_S, GLES20.GL_CLAMP_TO_EDGE); 

    GLES20.glTexParameterf(GLES20.GL_TEXTURE_2D, 
            GLES20.GL_TEXTURE_WRAP_T, GLES20.GL_CLAMP_TO_EDGE); 

    GLUtils.texImage2D(GLES20.GL_TEXTURE_2D, 0, textureBitmap, 0); 
    textureBitmap.recycle(); 

    return textureIds[0]; 
} 
```

我们必须考虑到纹理的两个维度都必须是 2 的幂。为了保持图像的原始大小并避免 Android 进行的任何缩放，我们必须将位图选项`inScaled`标志设置为`false`。在之前的代码中，我们生成了一个纹理 ID 来保存对我们纹理的引用，将其绑定为活动纹理，设置过滤和包裹的参数，并最终加载位图数据。完成这些操作后，我们可以回收临时位图，因为我们不再需要它。

如之前所做，我们也必须更新我们的`shaders`。在我们的`vertexShader`中，我们必须应用与之前几乎相同的更改，添加一个属性来设置顶点纹理坐标，以及一个`varying`变量传递给`fragmentShader`：

```kt
private final String vertexShaderCode = 
"uniform mat4 uMVPMatrix;" + 
"attribute vec4 vPosition;" + 
"attribute vec2 aTex;" + 
"varying vec2 vTex;" + 
"void main() {" + 
"  gl_Position = uMVPMatrix * vPosition;" + 
"  vTex = aTex;" + 
"}"; 
```

请注意，顶点坐标是 `vec2` 而不是 `vec4`，因为我们只有两个坐标：U 和 V。我们新的 `fragmentShader` 比我们之前的要复杂一些：

```kt
private final String fragmentShaderCode = 
"precision mediump float;" + 
"uniform sampler2D sTex;" + 
"varying vec2 vTex;" + 
"void main() {" + 
"  gl_FragColor = texture2D(sTex, vTex);" + 
"}"; 
```

我们必须创建一个 `varying` 纹理坐标变量，以及一个统一的 `sampler2D` 变量，我们将在其中设置活动的纹理。为了获取颜色，我们必须使用 `texture2D` 查找函数从指定坐标的纹理中读取颜色数据。

现在，让我们在我们的 `res` 文件夹的 drawables 中添加一个名为 `texture.png` 的位图，并修改 `onSurfaceCreated()` 方法以将其作为纹理加载：

```kt
@Override 
public void onSurfaceCreated(GL10 unused, EGLConfig config) { 
    initBuffers(); 
    initShaders(); 

    textureId = loadTexture(R.drawable.texture); 

    startTime = SystemClock.elapsedRealtime(); 
} 
```

这是我们示例中使用的图像：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/52a4bc51-0f65-4acb-917f-1d025ff08a65.png)

最后，让我们更新 `onDrawFrame()` 方法以设置纹理坐标：

```kt
int texCoordHandle = GLES20.glGetAttribLocation(shaderProgram, "aTex"); 
GLES20.glVertexAttribPointer(texCoordHandle, 2, 
        GLES20.GL_FLOAT, false, 
        0, texBuffer); 
```

这就是纹理本身：

```kt
int texHandle = GLES20.glGetUniformLocation(shaderProgram, "sTex"); 
GLES20.glActiveTexture(GLES20.GL_TEXTURE0); 
GLES20.glBindTexture(GLES20.GL_TEXTURE_2D, textureId); 
GLES20.glUniform1i(texHandle, 0); 
```

同样，正如我们之前所做的，我们必须启用，稍后禁用，纹理坐标顶点数组。

如果我们运行这段代码，我们将得到以下结果：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/157987b0-6971-4066-ab7d-707b4325c097.png)

在 GitHub 仓库中查看 `Example25-GLDrawing` 以获取完整的示例源代码。

# 加载外部几何图形

到目前为止，我们一直在绘制四边形和立方体，但如果我们想要绘制更复杂的几何图形，使用 3D 建模工具进行建模可能更为方便，而不是通过代码实现。我们可以用多个章节来涵盖这个主题，但让我们先看一个快速示例，了解如何实现，你可以根据需要扩展它。

我们使用了 Blender 来建模我们的示例数据。Blender 是一个免费且开源的 3D 建模工具集，可以在其网站上免费下载：

[`www.blender.org/`](https://www.blender.org/)。

在这个例子中，我们没有建模一个极其复杂的例子；我们只是使用了 Blender 提供的一个基本形状：Suzanne：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/0f8fb505-8aeb-46bd-b17e-fc7dcd36f3f4.png)

为了简化我们的导入工具，我们将在右侧的“场景”|“Suzanne”下拉菜单下选择对象网格，当我们按下 *Ctrl* + *T* 时，Blender 将把所有面转换为三角形。否则，我们的导出文件中既有三角形也有四边形，从我们的 Android 应用程序代码中实现面导入器并不直接：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/976e8d5b-34e3-4ddb-8ebf-9d791dc29f78.png)

现在，我们将它导出为 `Wavefront`（`.obj`）文件，这将创建一个 `.obj` 文件和一个 `.mtl` 文件。后者是材质信息，目前我们将忽略它。让我们将导出的文件放入我们项目的 `assets` 文件夹中。

现在，让我们自己创建一个简单的 `Wavefront` 文件对象解析器。由于我们将要处理文件加载和解析，因此我们需要异步执行：

```kt
public class WavefrontObjParser { 
    public static void parse(Context context, String name, ParserListener listener) { 
        WavefrontObjParserHelper helper = new WavefrontObjParserHelper(context, name, listener); 
        helper.start(); 
    } 

    public interface ParserListener { 
        void parsingSuccess(Scene scene); 
        void parsingError(String message); 
    } 
} 
```

如你所见，这里并没有实际完成工作。为了进行实际的加载和解析，我们创建了一个帮助类，它将在一个单独的**线程**上执行，并根据解析文件成功或出现错误来调用监听器：

```kt
class WavefrontObjParserHelper extends Thread { 
    private String name; 
    private WavefrontObjParser.ParserListener listener; 
    private Context context; 

    WavefrontObjParserHelper(Context context, String name,
    WavefrontObjParser.ParserListener listener) { 
        this.context = context; 
        this.name = name; 
        this.listener = listener; 
    } 

```

然后，当我们调用 `helper.start()` 时，它将创建实际的线程，并在其上执行 `run()` 方法：

```kt
public void run() { 
        try { 

            InputStream is = context.getAssets().open(name); 
            BufferedReader br = new BufferedReader(new
            InputStreamReader(is)); 

            Scene scene = new Scene(); 
            Object3D obj = null; 

            String str; 
            while ((str = br.readLine()) != null) { 
                if (!str.startsWith("#")) { 
                    String[] line = str.split(""); 

                    if("o".equals(line[0])) { 
                        if (obj != null) obj.prepare(); 
                        obj = new Object3D(); 
                        scene.addObject(obj); 

                    } else if("v".equals(line[0])) { 
                        float x = Float.parseFloat(line[1]); 
                        float y = Float.parseFloat(line[2]); 
                        float z = Float.parseFloat(line[3]); 
                        obj.addCoordinate(x, y, z); 
                    } else if("f".equals(line[0])) { 

                        int a = getFaceIndex(line[1]); 
                        int b = getFaceIndex(line[2]); 
                        int c = getFaceIndex(line[3]); 

                        if (line.length == 4) { 
                            obj.addFace(a, b, c); 
                        } else { 
                            int d = getFaceIndex(line[4]); 
                            obj.addFace(a, b, c, d); 
                        } 
                    } else { 
                        // skip 
                    } 
                } 
            } 
            if (obj != null) obj.prepare(); 
            br.close(); 

            if (listener != null) listener.parsingSuccess(scene); 
        } catch(Exception e) { 
            if (listener != null) listener.parsingError(e.getMessage()); 
            e.printStackTrace(); 
        } 
    } 
```

在之前的代码中，我们首先通过提供的名称打开文件来读取资源。为了获取应用程序资源，这里我们需要一个`context`：

```kt
InputStream is = context.getAssets().open(name); 
BufferedReader br = new BufferedReader(new InputStreamReader(is)); 
```

然后，我们逐行读取文件，并根据开始的关键字采取不同的行动，除非行以`#`开始，这意味着它是一个注释。我们只考虑新对象、顶点坐标和面索引的命令；我们忽略了文件中可能存在的任何附加命令，比如使用的材质，或顶点和面法线。

由于我们可以获取面索引信息，如 f 330//278 336//278 338//278 332//278，我们创建了一个辅助方法来解析这些信息，并只提取面索引。斜杠后面的数字是面法线索引。参考官方文件格式以更详细地了解面索引数字的使用：

```kt
private static int getFaceIndex(String face) { 
    if(!face.contains("/")) { 
        return Integer.parseInt(face) - 1; 
    } else { 
        return Integer.parseInt(face.split("/")[0]) - 1; 
    } 
} 
```

同时，由于面索引从`1`开始，我们需要减去`1`以得到正确的结果。

为了存储我们从文件中读取的所有这些数据，我们还创建了一些数据类。`Object3D`类将存储所有相关信息——顶点、面索引，而`Scene`类将存储整个 3D 场景以及所有内部的`Objects3D`。为了简单起见，我们尽可能保持了这些实现的简短，但根据我们的需要，它们可以变得更加复杂：

```kt
public class Scene { 
    private ArrayList<Object3D> objects; 

    public Scene() { 
        objects = new ArrayList<>(); 
    } 

    public void addObject(Object3D obj) { 
        objects.add(obj); 
    } 

    public ArrayList<Object3D> getObjects() { 
        return objects; 
    } 

    public void render(int shaderProgram, String posAttributeName,
    String colAttributeName) { 
        GLES20.glEnable(GLES20.GL_DEPTH_TEST); 

        for (int i = 0; i < objects.size(); i++) { 
            objects.get(i).render(shaderProgram, posAttributeName,
            colAttributeName); 
        } 

        GLES20.glDisable(GLES20.GL_DEPTH_TEST); 
    } 
} 

```

我们可以看到`Scene`类上有一个`render()`方法。我们将渲染所有 3D 对象的责任移到了`Scene`本身，并且应用相同的原则，每个对象也负责渲染自身：

```kt
public void prepare() { 
    if (coordinateList.size() > 0 && coordinates == null) { 
        coordinates = new float[coordinateList.size()]; 
        for (int i = 0; i < coordinateList.size(); i++) { 
            coordinates[i] = coordinateList.get(i); 
        } 
    } 

    if (indexList.size() > 0 && indexes == null) { 
        indexes = new short[indexList.size()]; 
        for (int i = 0; i < indexList.size(); i++) { 
            indexes[i] = indexList.get(i); 
        } 
    } 

    colors = new float[(coordinates.length/3) * 4]; 
    for (int i = 0; i < colors.length/4; i++) { 
        float intensity = (float) (Math.random() * 0.5 + 0.4); 
        colors[i * 4    ] = intensity; 
        colors[i * 4 + 1] = intensity; 
        colors[i * 4 + 2] = intensity; 
        colors[i * 4 + 3] = 1.f; 
    } 

    ByteBuffer vbb = ByteBuffer.allocateDirect(coordinates.length *
   (Float.SIZE / 8)); 
    vbb.order(ByteOrder.nativeOrder()); 

    vertexBuffer = vbb.asFloatBuffer(); 
    vertexBuffer.put(coordinates); 
    vertexBuffer.position(0); 

    ByteBuffer ibb = ByteBuffer.allocateDirect(indexes.length *
   (Short.SIZE / 8)); 
    ibb.order(ByteOrder.nativeOrder()); 

    indexBuffer = ibb.asShortBuffer(); 
    indexBuffer.put(indexes); 
    indexBuffer.position(0); 

    ByteBuffer cbb = ByteBuffer.allocateDirect(colors.length * 
    (Float.SIZE / 8)); 
    cbb.order(ByteOrder.nativeOrder()); 

    colorBuffer = cbb.asFloatBuffer(); 
    colorBuffer.put(colors); 
    colorBuffer.position(0); 

    Log.i(TAG, "Loaded obj with " + coordinates.length + " vertices &"
    + (indexes.length/3) + " faces"); 
} 

```

一旦我们为`3DObject`设置好所有数据，我们可以通过调用其`prepare()`方法来准备渲染。这个方法将创建顶点和索引`Buffer`，并且由于在这种情况下数据文件中的网格没有任何颜色信息，它将为每个顶点生成一个随机颜色，或者更确切地说是一个强度。

在这里`3DObject`本身创建缓冲区允许我们渲染任何类型的对象。`Scene`容器不知道内部是什么类型的对象或几何图形。只要它处理自己的渲染，我们可以轻松地将这个类扩展为另一种类型的`3DObject`。

最后，我们在`3DObject`中添加了一个`render()`方法：

```kt
public void render(int shaderProgram, String posAttributeName, String colAttributeName) { 
    int positionHandle = GLES20.glGetAttribLocation(shaderProgram,
    posAttributeName); 
    GLES20.glVertexAttribPointer(positionHandle, 3, 
            GLES20.GL_FLOAT, false, 
            3 * 4, vertexBuffer); 

    int colorHandle = GLES20.glGetAttribLocation(shaderProgram,
    colAttributeName); 
    GLES20.glVertexAttribPointer(colorHandle, 4, 
            GLES20.GL_FLOAT, false, 
            4 * 4, colorBuffer); 

    GLES20.glEnableVertexAttribArray(colorHandle); 
    GLES20.glEnableVertexAttribArray(positionHandle); 
    GLES20.glDrawElements( 
            GLES20.GL_TRIANGLES, indexes.length, 
            GLES20.GL_UNSIGNED_SHORT, indexBuffer); 

    GLES20.glDisableVertexAttribArray(positionHandle); 
    GLES20.glDisableVertexAttribArray(colorHandle); 
} 
```

这个方法负责启用和禁用正确的数组并渲染自身。我们从方法参数中获取`shader`属性。理想情况下，每个对象都可以有自己的`shader`，但我们不想在这个示例中增加太多复杂性。

在我们的`GLDrawer`类中，我们还添加了一个辅助方法来计算透视失真矩阵。OpenGL 中最常用的调用之一是`gluPerspective`，而许多出色的 OpenGL 教程的作者 NeHe 创建了一个函数将`gluPerspective`转换为`glFrustrum`调用：

```kt
// source: http://nehe.gamedev.net/article/replacement_for_gluperspective/21002/ 

private static void perspectiveFrustrum(float[] matrix, float fov, float aspect, float zNear, float zFar) { 
    float fH = (float) (Math.tan( fov / 360.0 * Math.PI ) * zNear); 
    float fW = fH * aspect; 

    Matrix.frustumM(matrix, 0, -fW, fW, -fH, fH, zNear, zFar); 
} 
```

因为我们不再需要它，我们从`GLDrawer`中移除了所有顶点和面索引信息，并简化了`onDrawFrame()`方法，现在将所有对象的渲染委托给`Scene`类，默认情况下，委托给每个单独的`3DObject`：

```kt
@Override 
public void onDrawFrame(GL10 unused) { 
    angle = ((float) SystemClock.elapsedRealtime() - startTime) *
    0.02f; 
    GLES20.glClearColor(1.0f, 0.0f, 0.0f, 1.0f); 
    GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT | 
    GLES20.GL_DEPTH_BUFFER_BIT); 

    if (scene != null) { 
        Matrix.setLookAtM(mViewMatrix, 0, 
                0, 0, -4, 
                0f, 0f, 0f, 
                0f, 1.0f, 0.0f); 

        Matrix.multiplyMM(mMVPMatrix, 0, mProjectionMatrix, 0,
        mViewMatrix, 0); 
        Matrix.rotateM(mMVPMatrix, 0, angle, 0.8f, 2.f, 1.f); 

        GLES20.glUseProgram(shaderProgram); 

        int mMVPMatrixHandle = GLES20.glGetUniformLocation(shaderProgram, "uMVPMatrix"); 
        GLES20.glUniformMatrix4fv(mMVPMatrixHandle, 1, false,
        mMVPMatrix, 0); 

        scene.render(shaderProgram, "vPosition", "aColor"); 
    } 
} 
```

把所有内容放在一起，如果我们运行这个示例，我们将得到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/88851ca6-f800-445a-9f74-e2e0c7edf0f9.png)

请在 GitHub 仓库中查看`Example26-GLDrawing`以获取完整的示例源代码。

# 总结

在本章中，我们学习了如何使用 OpenGL ES 创建非常基础的自定义视图。OpenGL ES 在创建自定义视图时提供了很多可能性，但如果我们没有太多与之工作的经验，它也会增加很多复杂性。我们本可以在这一主题上涵盖更多章节，但这并不是本书的主要目标。我们会有更多使用 3D 自定义视图的示例，但关于如何在 Android 设备上学习甚至掌握 OpenGL ES，已经有很多发布的材料了。

在下一章中，我们将学习如何为自定义视图添加更多动画和平滑的运动。由于我们可以动画化任何参数或变量，无论是 3D 自定义视图还是标准的 2D 自定义视图，这都不重要，但我们将看到如何在这两种情况下应用动画。


# 第六章：动画

到目前为止，我们已经了解了如何创建和渲染不同类型的自定义视图，从非常简单的 2D 画布绘图到更复杂的画布操作，以及最近如何使用 OpenGL ES 和顶点/片段着色器创建自定义视图。在一些用于演示如何使用这些渲染原语的示例中，我们已经使用了一些动画，正如你可以想象的，动画是自定义视图的关键元素之一。如果我们想使用自定义视图构建高度复杂的 UI，但完全不使用动画，那么使用静态图像可能更好。

在本章中，我们将介绍如何向自定义视图添加动画。有许多方法可以实现这一点，但我们会更详细地探讨以下主题：

+   自定义动画

+   固定时间步长技术

+   使用 Android 属性动画

此外，我们还将探讨如果我们错误地实现一些动画，可能会出现哪些问题，因为这看起来可能更简单，也许仅仅是运气好，尽管这可能会对我们不利，但它们似乎在我们的设备上可以完美运行。

# 自定义动画

让我们从如何自己实现一些值的变化开始，而不是过分依赖 Android SDK 提供的方法和类。在本节中，我们将了解如何使用不同的机制对一个或多个属性进行动画处理。这样，我们就可以根据我们想要实现的动画类型或我们正在实现的观点的具体特点，在我们自定义的视图中应用更合适的方法。

# 定时帧动画

在我们上一章的 3D 示例中，我们已经使用了这种类型的动画。主要概念是在绘制新帧之前，根据经过的时间为所有可动画属性分配一个新值。我们可能会被诱惑根据已绘制的帧数递增或计算一个新值，但这是非常不建议的，因为动画的播放速度将取决于设备速度、计算或绘图复杂性以及其他在后台执行的过程。

为了正确实现，我们必须引入与渲染速度、每秒帧数或已绘制的帧数无关的东西，而基于时间的动画是一个完美的解决方案。

Android 为我们提供了几种机制来实现这一点。例如，我们可以使用 `System.currentTimeMillis()`、`System.nanoTime()`，甚至是一些系统时钟中可用的方法，如 `elapsedRealtime()`。

让我们构建一个简单的示例来比较不同的方法。首先，创建一个简单的自定义视图，绘制四个旋转不同角度的矩形，或者说是 `Rect`：

```kt
private static final int BACKGROUND_COLOR = 0xff205020; 
private static final int FOREGROUND_COLOR = 0xffffffff; 
private static final int QUAD_SIZE = 50; 

private float[] angle; 
private Paint paint; 

public AnimationExampleView(Context context, AttributeSet attributeSet) { 
    super(context, attributeSet); 

    paint = new Paint(); 
    paint.setStyle(Paint.Style.FILL); 
    paint.setAntiAlias(true); 
    paint.setColor(FOREGROUND_COLOR); 
    paint.setTextSize(48.f); 

    angle = new float[4]; 
    for (int i = 0; i < 4; i++) { 
        angle[i] = 0.f; 
    } 
} 
```

在类的构造函数中，我们初始化 `Paint` 对象，并创建一个包含四个浮点数的数组来保存每个矩形的旋转角度。此时，这四个角度都将是 `0`。现在，让我们实现 `onDraw()` 方法。

在`onDraw()`方法中，我们首先要做的是用纯色清除画布背景，以清除我们之前的帧。

完成这些后，我们计算将绘制四个矩形的坐标并开始绘制。为了简化旋转，在本例中，我们使用了`canvas.translate`和`canvas.rotate`，以矩形的中心点作为旋转轴点。同时，为了避免进行额外的计算并尽可能保持简单，我们在每个矩形绘制前后分别使用`canvas.save`和`canvas.restore`，以保持每次绘制操作之前的状态：

```kt
@Override 
protected void onDraw(Canvas canvas) { 
    canvas.drawColor(BACKGROUND_COLOR); 

    int width = getWidth(); 
    int height = getHeight(); 

    // draw 4 quads on the screen: 
    int wh = width / 2; 
    int hh = height / 2; 

    int qs = (wh * QUAD_SIZE) / 100; 

    // top left 
    canvas.save(); 
    canvas.translate( 
        wh / 2 - qs / 2, 
        hh / 2 - qs / 2); 

    canvas.rotate(angle[0], qs / 2.f, qs / 2.f); 
    canvas.drawRect(0, 0, qs, qs, paint); 
    canvas.restore(); 

    // top right 
    canvas.save(); 
    canvas.translate( 
        wh + wh / 2 - qs / 2, 
        hh / 2 - qs / 2); 

    canvas.rotate(angle[1], qs / 2.f, qs / 2.f); 
    canvas.drawRect(0, 0, qs, qs, paint); 
    canvas.restore(); 

    // bottom left 
    canvas.save(); 
    canvas.translate( 
        wh / 2 - qs / 2, 
        hh + hh / 2 - qs / 2); 

    canvas.rotate(angle[2], qs / 2.f, qs / 2.f); 
    canvas.drawRect(0, 0, qs, qs, paint); 
    canvas.restore(); 

    // bottom right 
    canvas.save(); 
    canvas.translate( 
        wh + wh / 2 - qs / 2, 
        hh + hh / 2 - qs / 2); 

    canvas.rotate(angle[3], qs / 2.f, qs / 2.f); 
    canvas.drawRect(0, 0, qs, qs, paint); 
    canvas.restore(); 

    canvas.drawText("a: " + angle[0], 16, hh - 16, paint); 
    canvas.drawText("a: " + angle[1], wh + 16, hh - 16, paint); 
    canvas.drawText("a: " + angle[2], 16, height - 16, paint); 
    canvas.drawText("a: " + angle[3], wh + 16, height - 16, paint); 

    postInvalidateDelayed(10); 
} 
```

为了更清晰地看到差异，我们绘制了一个文本，显示每个矩形旋转的角度。并且，为了实际触发视图的重绘，我们调用了延迟 10 毫秒的`invalidate`。

第一个矩形将在每次绘制时简单地增加其角度，忽略时间方法，而其他三个将分别使用：`System.currentTimeMillis()`、`System.nanoTime()`和`SystemClock.elapsedRealtime()`。让我们初始化一些变量来保存定时器的初始值：

```kt
private long timeStartMillis; 
private long timeStartNanos; 
private long timeStartElapsed; 
```

在`onDraw()`方法的开头添加一个小计算：

```kt
if (timeStartMillis == -1)  
    timeStartMillis = System.currentTimeMillis(); 

if (timeStartNanos == -1)  
    timeStartNanos = System.nanoTime(); 

if (timeStartElapsed == -1)  
    timeStartElapsed = SystemClock.elapsedRealtime(); 

angle[0] += 0.2f; 
angle[1] = (System.currentTimeMillis() - timeStartMillis) * 0.02f; 
angle[2] = (System.nanoTime() - timeStartNanos) * 0.02f * 0.000001f; 
angle[3] = (SystemClock.elapsedRealtime() - timeStartElapsed) * 0.02f; 
```

由于从初始类创建到调用`onDraw()`方法之间可能经过了一段时间，我们在这里计算定时器的初始值。例如，如果`timeStartElapsed`的值是`-1`，这意味着它尚未初始化。

首先，我们设定了初始时间，然后可以计算出已经过去了多少时间，并将其作为动画的基础值。我们可以乘以一个因子来控制速度。在本例中，我们使用了`0.02`作为示例，并考虑到纳秒和毫秒的量级不同。

如果我们运行这个示例，我们将得到类似于以下截图的结果：

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/6e50b408-0c88-4542-89ab-9015488a3b94.png)

这种方法的一个问题是，如果我们把应用放到后台，过一段时间再把它调到前台，我们会看到所有基于时间的值都会向前跳跃，因为当我们的应用在后台时时间并不会停止。为了控制这一点，我们可以重写`onVisibilityChanged()`回调，并检查我们的视图是可见还是不可见：

```kt
@Override 
protected void onVisibilityChanged(@NonNull View changedView, int visibility) { 
    super.onVisibilityChanged(changedView, visibility); 

    // avoid doing this check before View is even visible 
    if ((visibility == View.INVISIBLE || visibility == View.GONE) &&  
          previousVisibility == View.VISIBLE) { 

        invisibleTimeStart = SystemClock.elapsedRealtime(); 
    } 

    if ((previousVisibility == View.INVISIBLE || previousVisibility ==
        View.GONE) && 
        visibility == View.VISIBLE) { 

        timeStartElapsed += SystemClock.elapsedRealtime() -
        invisibleTimeStart; 
    } 
    previousVisibility = visibility; 
} 
```

在前面的代码中，我们计算了视图不可见的时间，并调整`timeStartElapsed`。我们必须避免在第一次执行此操作，因为该方法将在视图第一次可见时被调用。因此，我们检查`timeStartElapsed`是否不等于`-1`。

由于我们有这个回调正好在视图变为可见之前，我们可以轻松地更改之前的代码来计算定时器的初始值，并将其放在这里，也简化我们的`onDraw()`方法：

```kt
@Override 
protected void onVisibilityChanged(@NonNull View changedView, int visibility) { 
    super.onVisibilityChanged(changedView, visibility); 

    // avoid doing this check before View is even visible 
    if (timeStartElapsed != -1) { 
        if ((visibility == View.INVISIBLE || visibility == View.GONE)
            && 
            previousVisibility == View.VISIBLE) { 

            invisibleTimeStart = SystemClock.elapsedRealtime(); 
        } 

        if ((previousVisibility == View.INVISIBLE || previousVisibility
            == View.GONE) && 
            visibility == View.VISIBLE) { 

            timeStartElapsed += SystemClock.elapsedRealtime() -
            invisibleTimeStart; 
        } 
    } else {
        timeStartMillis = System.currentTimeMillis();
        timeStartNanos = System.nanoTime();
        timeStartElapsed = SystemClock.elapsedRealtime();
    }
    previousVisibility = visibility;
}
```

通过这个微小的调整，只修改了`timeStartElapsed`，即使我们把应用放到后台，我们也会看到右下方的矩形保留了动画。

你可以在 GitHub 仓库的`Example27-Animations`文件夹中找到整个示例的源代码。

# 固定时间步长

在处理动画时，有时计算可能会非常复杂。一个明显的例子就是物理模拟和一般游戏中的情况，但在其他一些时候，即使是对于一个简单自定义视图，当使用基于时间的动画时，我们的计算也可能会有点棘手。固定时间步长将允许我们从时间变量中抽象出动画逻辑，但仍然使我们的动画与时间相关联。

设定固定时间步长的逻辑是假设我们的动画逻辑将始终以固定的速率执行。例如，我们可以假设无论实际渲染的每秒帧数是多少，它都将以*60* fps 的速率执行。为了展示如何做到这一点，我们将创建一个新的自定义视图，该视图将在我们按或拖动屏幕的位置生成粒子，并应用一些非常基础简单的物理效果。

首先，我们按照之前的示例创建一个基本的自定义视图：

```kt
private static final int BACKGROUND_COLOR = 0xff404060; 
private static final int FOREGROUND_COLOR = 0xffffffff; 
private static final int N_PARTICLES = 800; 

private Paint paint; 
private Particle[] particles; 
private long timeStart; 
private long accTime; 
private int previousVisibility; 
private long invisibleTimeStart; 

public FixedTimestepExample(Context context, AttributeSet attributeSet) { 
    super(context, attributeSet); 

    paint = new Paint(); 
    paint.setStyle(Paint.Style.FILL); 
    paint.setAntiAlias(true); 
    paint.setColor(FOREGROUND_COLOR); 

    particles = new Particle[N_PARTICLES]; 
    for (int i = 0; i < N_PARTICLES; i++) { 
        particles[i] = new Particle(); 
    } 

    particleIndex = 0; 
    timeStart = -1; 
    accTime = 0; 
    previousVisibility = View.GONE; 
} 
```

我们初始化基本变量，并且创建一个`particles`数组。同样，由于我们在上一个示例中实现了`onVisibilityChange`回调，让我们利用它：

```kt
@Override 
protected void onVisibilityChanged(@NonNull View changedView, int visibility) { 
    super.onVisibilityChanged(changedView, visibility); 
    if (timeStartElapsed != -1) { 
        // avoid doing this check before View is even visible 
        if ((visibility == View.INVISIBLE ||  visibility == View.GONE)
            && 
            previousVisibility == View.VISIBLE) { 

            invisibleTimeStart = SystemClock.elapsedRealtime(); 
        } 

        if ((previousVisibility == View.INVISIBLE || previousVisibility 
            == View.GONE) && 
            visibility == View.VISIBLE) { 

            timeStart += SystemClock.elapsedRealtime() -
            invisibleTimeStart; 
        } 
    } else { 
        timeStart = SystemClock.elapsedRealtime(); 
    } 
    previousVisibility = visibility; 
} 
```

现在我们来定义一个`Particle`类，尽量保持其简单：

```kt
class Particle { 
    float x; 
    float y; 
    float vx; 
    float vy; 
    float ttl; 

    Particle() { 
        ttl = 0.f; 
    } 
} 
```

我们只定义了`x`、`y`坐标，`x`和`y`的速度分别为`vx`和`vy`，以及粒子的生命周期。当粒子的生命周期达到`0`时，我们将不再更新或绘制它。

现在，我们来实现`onDraw()`方法：

```kt
@Override 
protected void onDraw(Canvas canvas) { 
    animateParticles(getWidth(), getHeight()); 

    canvas.drawColor(BACKGROUND_COLOR); 

    for(int i = 0; i < N_PARTICLES; i++) { 
        float px = particles[i].x; 
        float py = particles[i].y; 
        float ttl = particles[i].ttl; 

        if (ttl > 0) { 
            canvas.drawRect( 
                px - PARTICLE_SIZE, 
                py - PARTICLE_SIZE, 
                px + PARTICLE_SIZE, 
                py + PARTICLE_SIZE, paint); 
        } 
    } 
    postInvalidateDelayed(10); 
} 
```

我们将所有动画委托给`animateParticles()`方法，在这里我们只是遍历所有粒子，检查它们的生命周期是否为正，如果是，就绘制它们。

让我们看看如何使用固定时间步长来实现`animateParticles()`方法：

```kt
private static final int TIME_THRESHOLD = 16; 
private void animateParticles(int width, int height) { 
    long currentTime = SystemClock.elapsedRealtime(); 
    accTime += currentTime - timeStart; 
    timeStart = currentTime; 

    while(accTime > TIME_THRESHOLD) { 
        for (int i = 0; i < N_PARTICLES; i++) { 
            particles[i].logicTick(width, height); 
        } 

        accTime -= TIME_THRESHOLD; 
    } 
} 
```

我们计算自上次以来的时间差，或者说是时间增量，并将其累积在`accTime`变量中。然后，只要`accTime`高于我们定义的阈值，我们就执行一个逻辑步骤。可能会在两次渲染之间执行多个逻辑步骤，或者在有些情况下，可能在两帧之间没有执行。

最后，我们为每个执行的逻辑步骤从`accTime`中减去我们定义的时间阈值，并将新的`timeStart`设置为用于计算从上一次调用`animateParticles()`以来时间差的时间。

在这个例子中，我们将时间阈值定义为`16`，所以每`16`毫秒我们将执行一个逻辑步骤，无论我们是渲染`10`帧还是`60`帧每秒。

`Particle`类上的`logicTick()`方法完全忽略了计时器的当前值，因为它假设它将在固定的时间步长上执行：

```kt
void logicTick(int width, int height) { 
    ttl--; 

    if (ttl > 0) { 
        vx = vx * 0.95f; 
        vy = vy + 0.2f; 

        x += vx; 
        y += vy; 

        if (y < 0) { 
            y = 0; 
            vy = -vy * 0.8f; 
        } 

        if (x < 0) { 
            x = 0; 
            vx = -vx * 0.8f; 
        } 

        if (x >= width) { 
            x = width - 1; 
            vx = -vx * 0.8f; 
        } 
    } 
} 
```

这是对粒子物理模拟的极度简化。它基本上对粒子应用摩擦力并添加垂直加速度，计算它们是否需要从屏幕边缘反弹，并计算新的`x`和`y`位置。

我们只是缺少在按或拖动`TouchEvent`时生成新粒子的代码：

```kt
@Override 
public boolean onTouchEvent(MotionEvent event) { 
    switch (event.getAction()) { 
        case MotionEvent.ACTION_DOWN: 
        case MotionEvent.ACTION_MOVE: 
            spawnParticle(event.getX(), event.getY()); 
            return true; 
    } 
    return super.onTouchEvent(event); 
} 
```

在这里，只要我们有按下的或移动的触摸事件，我们就会调用`spawnParticle()`。`spawnParticle()`的实现也非常简单：

```kt
private static final int SPAWN_RATE = 8; 
private int particleIndex; 

private void spawnParticle(float x, float y) { 
    for (int i = 0; i < SPAWN_RATE; i++) { 
        particles[particleIndex].x = x; 
        particles[particleIndex].y = y; 
        particles[particleIndex].vx = (float) (Math.random() * 40.f) -
        20.f; 
        particles[particleIndex].vy = (float) (Math.random() * 20.f) -
        10.f; 
        particles[particleIndex].ttl = (float) (Math.random() * 100.f)
        + 150.f; 
        particleIndex++; 
        if (particleIndex == N_PARTICLES) particleIndex = 0; 
    } 
} 
```

我们使用`particleIndex`变量作为`particles`数组的循环索引。每当它到达数组末尾时，它将重新从数组开始处继续。这种方法设置触摸事件的`x`和`y`坐标，并随机化每个生成粒子的速度和生存时间。我们创建了一个`SPAWN_RATE`常量，以在同一个触摸事件上生成多个粒子，从而改善视觉效果。

如果我们运行应用程序，我们可以看到它的实际效果，它将与以下截图非常相似，但在这种情况下，很难在截图中捕捉到动画的想法：

![图片](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/7dcca15c-8bc9-4b99-bd5c-6b14d70328c7.png)

但我们遗漏了一些东西。正如我们之前提到的，有时在两帧渲染之间，我们会执行两个或更多的逻辑步骤，但在其他时候，我们可能在连续的两帧之间不执行任何逻辑步骤。如果我们在这两帧之间不执行任何逻辑步骤，结果将是相同的，并且会浪费 CPU 和电池寿命。

即使我们处于逻辑步骤之间，这并不意味着在帧之间没有经过任何时间。实际上，我们处于上一个计算出的逻辑步骤和下一个步骤之间的某个位置。好消息是，我们实际上可以计算出这一点，从而提高动画的平滑度并同时解决此问题。

让我们把这个修改包括到`animateParticles()`方法中：

```kt
private void animateParticles(int width, int height) {
    long currentTime = SystemClock.elapsedRealtime();
    accTime += currentTime - timeStart;
    timeStart = currentTime;

     while(accTime > TIME_THRESHOLD) {
        for (int i = 0; i < N_PARTICLES; i++) {
            particles[i].logicTick(width, height);
        }

         accTime -= TIME_THRESHOLD;
    }

     float factor = ((float) accTime) / TIME_THRESHOLD;
     for (int i = 0; i < N_PARTICLES; i++) {
        particles[i].adjustLogicStep(factor);
    }
}
```

我们正在计算一个因子，该因子将告诉我们距离下一个逻辑步骤有多近或多远。如果因子是`0`，这意味着我们正好处于刚刚执行的逻辑步骤的确切时间。如果因子是`0.5`，这意味着我们处于当前步骤和下一个步骤之间的一半，而如果因子是`0.8`，我们几乎要到达下一个逻辑步骤，并且精确地*80%*的时间已经自上一个步骤过去了。在一步逻辑步骤和下一步之间平滑过渡的方法是使用这个因子进行插值，但要能够这样做，我们首先需要计算下一步的值。让我们改变`logicTick()`方法以实现这个变化：

```kt
float nextX; 
float nextY; 
float nextVX; 
float nextVY; 

void logicTick(int width, int height) { 
    ttl--; 

    if (ttl > 0) { 
        x = nextX; 
        y = nextY; 
        vx = nextVX; 
        vy = nextVY; 

        nextVX = nextVX * 0.95f; 
        nextVY = nextVY + 0.2f; 

        nextX += nextVX; 
        nextY += nextVY; 

        if (nextY < 0) { 
            nextY = 0; 
            nextVY = -nextVY * 0.8f; 
        } 

        if (nextX < 0) { 
            nextX = 0; 
            nextVX = -nextVX * 0.8f; 
        } 

        if (nextX >= width) { 
            nextX = width - 1; 
            nextVX = -nextVX * 0.8f; 
        } 
    } 
} 
```

现在，在每一个逻辑步骤中，我们都在将下一个逻辑步骤的值赋给当前变量以避免重新计算它们，并计算下一个逻辑步骤。这样，我们得到了这两个值；在执行下一个逻辑步骤之后的当前值和新值。

由于我们将使用`x`、`y`和`nextX`、`nextY`之间的中间值，我们也会在新变量上计算这些值。

```kt
float drawX; 
float drawY; 

void adjustLogicStep(float factor) { 
    drawX = x * (1.f - factor) + nextX * factor; 
    drawY = y * (1.f - factor) + nextY * factor; 
} 
```

正如我们所看到的，`drawX`和`drawY`将是当前逻辑步骤和下一个逻辑步骤之间的中间状态。如果我们将前一个示例的值应用到这个因子上，我们就会看到这种方法是如何工作的。

如果因子是`0`，则`drawX`和`drawY`正好是`x`和`y`。相反，如果因子是`1`，则`drawX`和`drawY`正好是`nextX`和`nextY`，尽管这实际上不会发生，因为另一个逻辑步骤将被触发。

在因子为`0.8`的情况下，`drawX`和`drawY`的值是对下一个逻辑步骤的值*80%*和当前步骤的值*20%*的线性插值，从而实现状态之间的平滑过渡。

你可以在 GitHub 仓库的`Example28-FixedTimestep`文件夹中找到整个示例源代码。固定时间步进在 Gaffer On Games 博客的“fix your timestep”文章中有更详细的介绍。

# 使用 Android SDK 类

到目前为止，我们已经了解了如何使用基于时间动画或固定时间步机制来创建我们自己的动画。但 Android 提供了多种使用其 SDK 和动画框架进行动画制作的方法。在大多数情况下，我们可以通过仅使用属性动画系统来简化我们的动画，而无需创建自己的系统，但这将取决于我们想要实现的内容的复杂性以及我们想要如何处理开发。

有关更多信息，请参考 Android 开发者文档网站上的属性动画框架。

# 值动画

作为属性动画系统的一部分，我们有`ValueAnimator`类。我们可以使用它来简单地动画化`int`、`float`或`color`变量或属性。它非常易于使用，例如，我们可以使用以下代码在`1500`毫秒内将浮点值从`0`动画化到`360`：

```kt
ValueAnimator angleAnimator = ValueAnimator.ofFloat(0, 360.f); 
angleAnimator.setDuration(1500); 
angleAnimator.start(); 
```

这是正确的，但如果我们想要获取动画的更新并对其做出反应，我们必须设置一个`AnimatorUpdateListener()`。

```kt
final ValueAnimator angleAnimator = ValueAnimator.ofFloat(0, 360.f); 
angleAnimator.setDuration(1500); 
angleAnimator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { 
    @Override 
    public void onAnimationUpdate(ValueAnimator animation) { 
        angle = (float) angleAnimator.getAnimatedValue(); 
        invalidate(); 
    } 
}); 
angleAnimator.start(); 
```

同时，在这个例子中，我们可以看到我们在`AnimatorUpdateListener()`中调用了`invalidate()`，因此我们也在告诉 UI 重新绘制视图。

我们可以配置动画行为的许多方面：从动画重复模式、重复次数和插值器类型。让我们使用本章开始时使用的同一个示例来看一下它的实际应用。让我们在屏幕上绘制四个矩形，并使用`ValueAnimator`的不同设置来旋转它们：

```kt
//top left 
final ValueAnimator angleAnimatorTL = ValueAnimator.ofFloat(0, 360.f); 
angleAnimatorTL.setRepeatMode(ValueAnimator.REVERSE); 
angleAnimatorTL.setRepeatCount(ValueAnimator.INFINITE); 
angleAnimatorTL.setDuration(1500); 
angleAnimatorTL.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { 
    @Override 
    public void onAnimationUpdate(ValueAnimator animation) { 
        angle[0] = (float) angleAnimatorTL.getAnimatedValue(); 
        invalidate(); 
    } 
}); 

//top right 
final ValueAnimator angleAnimatorTR = ValueAnimator.ofFloat(0, 360.f); 
angleAnimatorTR.setInterpolator(new DecelerateInterpolator()); 
angleAnimatorTR.setRepeatMode(ValueAnimator.RESTART); 
angleAnimatorTR.setRepeatCount(ValueAnimator.INFINITE); 
angleAnimatorTR.setDuration(1500); 
angleAnimatorTR.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { 
    @Override 
    public void onAnimationUpdate(ValueAnimator animation) { 
        angle[1] = (float) angleAnimatorTR.getAnimatedValue(); 
        invalidate(); 
    } 
}); 

//bottom left 
final ValueAnimator angleAnimatorBL = ValueAnimator.ofFloat(0, 360.f); 
angleAnimatorBL.setInterpolator(new AccelerateDecelerateInterpolator()); 
angleAnimatorBL.setRepeatMode(ValueAnimator.RESTART); 
angleAnimatorBL.setRepeatCount(ValueAnimator.INFINITE); 
angleAnimatorBL.setDuration(1500); 
angleAnimatorBL.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { 
    @Override 
    public void onAnimationUpdate(ValueAnimator animation) { 
        angle[2] = (float) angleAnimatorBL.getAnimatedValue(); 
        invalidate(); 
    } 
}); 

//bottom right 
final ValueAnimator angleAnimatorBR = ValueAnimator.ofFloat(0, 360.f); 
angleAnimatorBR.setInterpolator(new OvershootInterpolator()); 
angleAnimatorBR.setRepeatMode(ValueAnimator.REVERSE); 
angleAnimatorBR.setRepeatCount(ValueAnimator.INFINITE); 
angleAnimatorBR.setDuration(1500); 
angleAnimatorBR.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { 
    @Override 
    public void onAnimationUpdate(ValueAnimator animation) { 
        angle[3] = (float) angleAnimatorBR.getAnimatedValue(); 
        invalidate(); 
    } 
}); 

angleAnimatorTL.start(); 
angleAnimatorTR.start(); 
angleAnimatorBL.start(); 
angleAnimatorBR.start(); 
```

我们现在配置了四个不同的 `ValueAnimators`，并通过它们的 `onAnimationUpdate()` 回调触发失效调用，而不是设置初始时间和计算时间差。在这些 `ValueAnimator` 上，我们使用了不同的插值器和不同的重复模式：`ValueAnimator.RESTART` 和 `ValueAnimator.REVERSE`。在所有这些中，我们将重复次数设置为 `ValueAnimator.INFINITE`，这样我们就可以在没有压力的情况下观察和比较插值器的细节。

在 `onDraw()` 方法中，我们移除了 `postInvalidate` 调用，因为视图将被动画失效，但保留 `drawText()` 非常有趣，因为这样我们可以看到 `OvershootInterpolator()` 的行为以及它如何超出最大值。

如果我们运行这个示例，我们将看到四个矩形使用不同的插值机制进行动画处理。尝试使用不同的插值器，甚至可以通过扩展 `TimeInterpolator` 并实现 `getInterpolation(float input)` 方法来实现自己的插值器。

`getInterpolation` 方法的输入参数将在 `0` 到 `1` 之间，将 `0` 映射到动画的开始，将 `1` 映射到动画的结束。返回值应在 `0` 到 `1` 之间，但如果像 `OvershootInterpolator` 那样我们想要超出原始值，它可能更低或更高。然后 `ValueAnimator` 将根据这个因素计算初始值和最终值之间的正确值。

这个示例需要在模拟器或真实设备上查看，但为屏幕截图添加一点动态模糊可以稍微显示矩形以不同的速度和加速度进行动画处理。

![](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/bd-andr-ui-cus-view/img/c7fb9c2a-db94-400b-b144-bcc709754b08.png)

# ObjectAnimator

如果我们想直接对对象而不是属性进行动画处理，我们可以使用 `ObjectAnimator` 类。`ObjectAnimator` 是 `ValueAnimator` 的一个子类，并使用相同的功能和特性，但增加了通过名称对对象属性进行动画处理的能力。

例如，为了展示其工作原理，我们可以以这种方式动画化我们 View 的一个属性。让我们为整个画布添加一个小的旋转，由 `canvasAngle` 变量控制：

```kt
float canvasAngle; 

@Override 
protected void onDraw(Canvas canvas) { 
    canvas.save(); 
    canvas.rotate(canvasAngle, getWidth() / 2, getHeight() / 2); 

    ... 

    canvas.restore(); 
} 
```

我们需要创建具有正确名称的设置器和获取器：以驼峰命名法命名的 `set<变量名>` 和 `get<变量名>`，在我们的特定案例中：

```kt
public void setCanvasAngle(float canvasAngle) { 
    this.canvasAngle = canvasAngle; 
} 

public float getCanvasAngle() { 
    return canvasAngle; 
} 
```

由于这些方法将被 `ObjectAnimator` 调用，我们已经创建它们，现在可以设置 `ObjectAnimator` 本身了：

```kt
ObjectAnimator canvasAngleAnimator = ObjectAnimator.ofFloat(this, "canvasAngle", -10.f, 10.f); 
canvasAngleAnimator.setDuration(3000); 
canvasAngleAnimator.setRepeatCount(ValueAnimator.INFINITE); 
canvasAngleAnimator.setRepeatMode(ValueAnimator.REVERSE); 
canvasAngleAnimator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { 
    @Override 
    public void onAnimationUpdate(ValueAnimator animation) { 
        invalidate(); 
    } 
}); 
```

这基本上与 `ValueAnimator` 的方法相同，但在这种情况下，我们指定要使用字符串和对象引用进行动画处理的属性。正如我们刚才提到的，`ObjectAnimator` 将使用 `set<变量名>` 和 `get<变量名>` 的格式调用属性的获取器和设置器。此外，在 `onAnimationUpdate` 回调中只有一个 `invalidate()` 调用。我们移除了任何像前一个示例中的值赋值，因为它们将自动由 `ObjectAnimator` 更新。

你可以在 GitHub 仓库的`Example29-PropertyAnimation`文件夹中找到整个示例的源代码。

# 总结

在本章中，我们学习了如何为自定义视图添加不同类型的动画，从使用 Android 属性动画系统中的`ValueAnimator`和`ObjectAnimator`类，到创建基于时间或使用固定时间步进机制的自定义动画。

Android 为我们提供了更多的动画类，比如`AnimatorSet`，我们可以组合多个动画，并指定哪个动画在另一个之前或之后播放。

作为建议，我们不应重复发明轮子，如果 Android 提供的功能足够用，尽量使用它，或者根据我们的特定需求进行扩展，但如果它不适合，不要强求，因为或许构建自己的动画可能会更简单且更容易维护。

与软件开发中的所有事物一样，应使用常识并选择最佳可用选项。

在下一章中，我们将学习如何提高自定义视图的性能。在自定义视图中，我们完全控制着绘制过程，因此优化绘制方法和资源分配至关重要，以避免使应用程序变得迟缓并节省用户的电量。
