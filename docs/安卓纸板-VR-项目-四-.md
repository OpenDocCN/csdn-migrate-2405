# 安卓纸板 VR 项目（四）

> 原文：[`zh.annas-archive.org/md5/94E6723D45DBCC15CF10E16526443AE5`](https://zh.annas-archive.org/md5/94E6723D45DBCC15CF10E16526443AE5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：3D 模型查看器

三维模型随处可见，从机械工程的机械零件到医学成像；从视频游戏设计到 3D 打印。 3D 模型与照片、视频、音乐和其他媒体一样丰富多样。然而，虽然浏览器和应用程序对其他媒体类型有原生支持，但对 3D 模型的支持并不多。有一天，3D 查看标准将集成到浏览器中（例如 WebGL 和 WebVR）。在那之前，我们将不得不依赖插件和姊妹应用程序来查看我们的模型。例如，可以在网上找到免费的 OBJ 格式的 3D 文件模型，包括 TF3DM（[`tf3dm.com/`](http://tf3dm.com/)）、TurboSquid（[`www.turbosquid.com/`](http://www.turbosquid.com/)）和其他许多网站（[`www.hongkiat.com/blog/60-excellent-free-3d-model-websites/`](http://www.hongkiat.com/blog/60-excellent-free-3d-model-websites/)）。

在这个项目中，我们将构建一个 Android 3D 模型查看器应用程序，让您可以使用 Cardboard VR 头盔打开和查看 3D 模型。我们将使用的文件格式是 OBJ，这是 Wavefront Technologies 最初为电影 3D 动画开发的开放格式。OBJ 可以由许多 3D 设计应用程序创建和导出，包括开源应用程序，如 Blender 和 MeshLab，以及商业应用程序，如 3D Studio Max 和 Maya。OBJ 是一个非压缩的纯文本文件，用于存储由三角形（或更高阶多边形）组成的 3D 对象的表面网格的描述。

为了实现查看器，我们将读取和解析 OBJ 文件模型，并在 3D 中显示它们以供 Cardboard 查看。我们将通过以下步骤实现这一目标：

+   设置新项目

+   编写 OBJ 文件解析器以导入几何图形

+   显示 3D 模型

+   使用用户的头部运动旋转对象的视图

此项目的源代码可以在 Packt Publishing 网站上找到，并且在 GitHub 上也可以找到（[`github.com/cardbookvr/modelviewer`](https://github.com/cardbookvr/modelviewer)）（每个主题作为单独的提交）。

# 建立一个新项目

为了构建这个项目，我们将使用在第五章中创建的`RenderBox`库，*RenderBox 引擎*。您可以使用您自己的库，或者从本书提供的可下载文件或我们的 GitHub 存储库中获取副本（使用标记为`after-ch7`的提交—[`github.com/cardbookvr/renderboxlib/releases/tag/after-ch7`](https://github.com/cardbookvr/renderboxlib/releases/tag/after-ch7)）。有关如何导入`RenderBox`库的更详细描述，请参阅第五章的最后一节，*在未来项目中使用 RenderBox*。执行以下步骤创建一个新项目：

1.  打开 Android Studio，创建一个新项目。让我们将其命名为`Gallery360`，并以**空活动**为目标定位到**Android 4.4 KitKat (API 19)**。

1.  创建`renderbox`，`common`和`core`包的新模块，使用**文件** | **新建模块** | **导入.JAR/.AAR 包**。

1.  使用**文件** | **项目结构**将模块设置为应用程序的依赖项。

1.  按照第二章中的说明编辑`build.gradle`文件，*Cardboard 项目的骨架*，以便对 SDK 22 进行编译。

1.  更新`/res/layout/activity_main.xml`和`AndroidManifest.xml`，如前几章所述。

1.  将`MainActivity`编辑为`class MainActivity extends CardboardActivity implements IRenderBox`，并实现接口方法存根（*Ctrl* + *I*）。

我们可以继续在`MainActivity`中定义`onCreate`方法。该类现在具有以下代码：

```kt
public class MainActivity extends CardboardActivity implements IRenderBox {
    private static final String TAG = "ModelViewer";
    CardboardView cardboardView;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        cardboardView = (CardboardView) findViewById(R.id.cardboard_view);
        cardboardView.setRenderer(new RenderBox(this, this));
        setCardboardView(cardboardView);
    }
    @Override
    public void setup() {
    }
    @Override
    public void preDraw() {
        // code run beginning each frame
    }
    @Override
    public void postDraw() {
        // code run end of each frame
    }
}
```

您可以将一个立方体临时添加到场景中，以确保一切设置正确。将其添加到`setup`方法中，如下所示：

```kt
    public void setup() {
        new Transform()
            .setLocalPosition(0,0,-7)
            .setLocalRotation(45,60,0)
            .addComponent(new Cube(true));
    }
```

如果您记得，`Cube`是添加到`Transform`的`Component`。`Cube`定义了它的几何形状（例如，顶点）。`Transform`定义了它在 3D 空间中的位置、旋转和缩放。

您应该能够在 Android 设备上点击**Run 'app'**而没有编译错误，并看到立方体和 Cardboard 分屏视图。

# 了解 OBJ 文件格式

该项目的目标是查看 Wavefront OBJ 格式的 3D 模型。在我们开始编码之前，让我们来看看文件格式。可以在[`www.fileformat.info/format/wavefrontobj/egff.htm`](http://www.fileformat.info/format/wavefrontobj/egff.htm)找到参考资料。

正如我们所知，3D 模型可以表示为 X、Y 和 Z 顶点的网格。顶点集连接在一起定义网格表面的一个面。完整的网格表面是这些面的集合。

每个顶点也可以分配一个法线向量和/或纹理坐标。法线向量定义了该顶点的外向面向方向，用于光照计算。UV 纹理坐标可用于将纹理图像映射到网格表面上。格式的其他特性包括自由曲线和材质，我们在这个项目中不会支持。

作为纯文本文件，OBJ 被组织为单独的文本行。每个非空行以关键字开头，后面是由空格分隔的该关键字的数据。注释以`#`开头，并且被解析器忽略。

OBJ 数据关键字包括：

+   `v`: 几何顶点（例如，`v 0.0 1.0 0.0`）

+   `vt`: 纹理顶点（例如，`vt 0.0 1.0 0.0`）[在我们的项目中不受支持]

+   `vn`: 顶点法线（例如，`vn 0.0 1.0 0.0`）

+   `f`: 多边形面索引（例如，`f 1 2 3`）

面值是指向顶点列表中的顶点的索引（从第一个顶点开始为 1）。

至于指定面索引的`f`命令，它们是整数值，用于索引顶点列表。当有三个索引时，它描述一个三角形；四个描述一个四边形，依此类推。

当纹理顶点存在时，它们被引用为斜杠后的第二个数字，例如，`f 1/1 2/2 3/3`。我们现在不支持它们，但可能需要在`f`命令中解析它们。当顶点法线存在时，它们被引用为斜杠后的第三个数字，例如，`f 1//1 2//2 3//3`或`f 1/1/1 2/2/2 3/3/3`。

索引可以是负数，这种情况下它们将以-1 表示最后（最近遇到的）项目，-2 表示前一个项目，依此类推。

其他行，包括我们这里不支持的数据，将被忽略。

例如，以下数据表示一个简单的三角形：

```kt
# Simple Wavefront file
v 0.0 0.0 0.0
v 0.0 1.0 0.0
v 1.0 0.0 0.0
f 1 2 3
```

我们的 OBJ 实现是有限的。它可以安全地处理本书附带的示例模型，也许还可以处理您在互联网上找到或自己制作的其他模型。然而，这只是一个示例代码和演示项目。在我们的`RenderBox`引擎中编写一个强大的数据导入器并支持 OBJ 的许多特性超出了本书的范围。

# 创建`ModelObject`类

首先，我们将定义一个`ModelObject`类，它扩展了`RenderObject`。它将从 OBJ 文件加载模型数据，并设置其材质所需的缓冲区（以及 OpenGL ES 着色器，以在 VR 场景中呈现）。

右键单击`app/java/com.cardboardvr.modelviewer/`文件夹，转到**New** | **Java Class**，并命名为`ModelObject`。定义它以扩展`RenderObject`，如下所示：

```kt
public class ModelObject extends RenderObject {
}
```

就像我们在之前的章节中所做的那样，当引入新类型的`RenderObjects`时，我们将有一个或多个构造函数，可以实例化一个`Material`并设置缓冲区。对于`ModelObject`，我们将传入一个文件资源句柄，解析文件（参考下一个主题），并创建一个纯色材质（最初，没有光照），如下所示：

```kt
    public ModelObject(int objFile) {
        super();
        InputStream inputStream = RenderBox.instance.mainActivity.getResources().openRawResource(objFile);
        if (inputStream == null)
            return; // error
        parseObj(inputStream);
        createMaterial();
    }
```

现在添加材质如下。首先，声明缓冲区的变量（就像我们在之前的项目中为其他`RenderObjects`所做的那样）。这些可以是私有的，但我们的约定是如果我们想在外部定义新材质，就将它们保持为公共的：

```kt
    public static FloatBuffer vertexBuffer;
    public static FloatBuffer colorBuffer;
    public static FloatBuffer normalBuffer;
    public static ShortBuffer indexBuffer;
    public int numIndices;
```

这是`createMaterial`方法（从构造函数中调用）：

```kt
    public ModelObject createMaterial(){
        SolidColorLightingMaterial scm = new SolidColorLightingMaterial(new float[]{0.5f, 0.5f, 0.5f, 1});
        scm.setBuffers(vertexBuffer, normalBuffer, indexBuffer, numIndices);
        material = scm;
        return this;
    }
```

接下来，我们实现`parseObj`方法。

# 解析 OBJ 模型

`parseObj`方法将打开资源文件作为`InputStream`。它一次读取一行，解析命令和数据，构建模型的顶点、法线和索引列表。然后，我们从数据构建缓冲区。

首先，在`ModelObject`类的顶部，声明数据列表的变量：

```kt
    Vector<Short> faces=new Vector<Short>();
    Vector<Short> vtPointer=new Vector<Short>();
    Vector<Short> vnPointer=new Vector<Short>();
    Vector<Float> v=new Vector<Float>();
    Vector<Float> vn=new Vector<Float>();
    Vector<Material> materials=null;
```

让我们编写`parseObj`，并为辅助方法添加占位符。我们打开文件，处理每一行，构建缓冲区，并处理潜在的 IO 错误：

```kt
    void parseObj(InputStream inputStream) {
        BufferedReader reader = null;
        String line = null;

        reader = new BufferedReader(new InputStreamReader(inputStream));
        if (reader == null)
            return; // error

        try { // try to read lines of the file
            while ((line = reader.readLine()) != null) {
                parseLine(line);
            }
            buildBuffers();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
```

`parseLine`代码非常简单。行的第一个标记是一个或两个字符的命令（如`v`、`vn`或`f`），后面是数据值（浮点坐标或整数索引）。以下是`parseLine`和`v`、`vn`顶点的解析器的代码：

```kt
    private void parseLine(String line) {
        Log.v("obj", line);
        if(line.startsWith("f")){//a polygonal face
            processFLine(line);
        }
        else
        if(line.startsWith("vn")){
            processVNLine(line);
        }
        else
        if(line.startsWith("v")){ //line having geometric position of single vertex
            processVLine(line);
        }
    }

    private void processVLine(String line){
        String [] tokens=line.split("[ ]+"); 
        //split the line at the spaces
        int c=tokens.length;
        for(int i=1; i<c; i++){ //add the vertex to the vertex array
            v.add(Float.valueOf(tokens[i]));
        }
    }

    private void processVNLine(String line){
        String [] tokens=line.split("[ ]+"); 
        //split the line at the spaces
        int c=tokens.length;
        for(int i=1; i<c; i++){ //add the vertex to the vertex array
            vn.add(Float.valueOf(tokens[i]));
        }
    }
```

`f`行需要处理各种值情况。

至于指定面索引的`f`命令，它们是索引到顶点列表的整数值。当有三个索引时，它描述一个三角形，四个描述一个四边形，依此类推。超过三边的任何形状都需要被细分为三角形，以便在 OpenGL ES 中进行渲染。

还可以有任意组合的索引值，包括格式如`v`或`v/vt`或`v/vt/vn`，甚至`v//vn`，`/vt/vn`或`//vn`。（请记住，由于我们没有映射纹理，我们只会使用第一个和第三个。）

让我们先处理最简单的情况，即三角形面：

```kt
    private void processFLine(String line){
        String [] tokens=line.split("[ ]+");
        int c=tokens.length;

        if(tokens[1].matches("[0-9]+")){//f: v
            if(c==4){//3 faces
                for(int i=1; i<c; i++){
                    Short s=Short.valueOf(tokens[i]);
                    s--;
                    faces.add(s);
                }
            }
        }
    }
```

现在考虑面上有超过三个索引。我们需要一个方法来将多边形三角化。让我们现在编写这个方法：

```kt
    public static Vector<Short> triangulate(Vector<Short> polygon){
        Vector<Short> triangles=new Vector<Short>();
        for(int i=1; i<polygon.size()-1; i++){
            triangles.add(polygon.get(0));
            triangles.add(polygon.get(i));
            triangles.add(polygon.get(i+1));
        }
        return triangles;
    }
```

我们可以在`processFLine`中使用它：

```kt
    private void processFLine(String line) {
        String[] tokens = line.split("[ ]+");
        int c = tokens.length;

        if (tokens[1].matches("[0-9]+") || //f: v
            tokens[1].matches("[0-9]+/[0-9]+")) {//f: v/vt

            if (c == 4) {//3 faces
                for (int i = 1; i < c; i++) {
                    Short s = Short.valueOf(tokens[i]);
                    s--;
                    faces.add(s);
                }
            }
            else{//more faces
                Vector<Short> polygon=new Vector<Short>();
                for(int i=1; i<tokens.length; i++){
                    Short s=Short.valueOf(tokens[i]);
                    s--;
                    polygon.add(s);
                }
                faces.addAll(triangulate(polygon));
                //triangulate the polygon and //add the resulting faces
            }
        }
        //if(tokens[1].matches("[0-9]+//[0-9]+")){//f: v//vn
        //if(tokens[1].matches("[0-9]+/[0-9]+/[0-9]+")){
		//f: v/vt/vn
    }
```

这段代码适用于面值`v`和`v/vt`，因为我们跳过纹理。我还注释掉了面索引值的其他两种排列。其余部分大部分只是暴力字符串解析。`v//vn`情况如下：

```kt
    if(tokens[1].matches("[0-9]+//[0-9]+")){//f: v//vn
        if(c==4){//3 faces
            for(int i=1; i<c; i++){
                Short s=Short.valueOf(tokens[i].split("//")[0]);
                s--;
                faces.add(s);
                s=Short.valueOf(tokens[i].split("//")[1]);
                s--;
                vnPointer.add(s);
            }
        }
        else{//triangulate
            Vector<Short> tmpFaces=new Vector<Short>();
            Vector<Short> tmpVn=new Vector<Short>();
            for(int i=1; i<tokens.length; i++){
                Short s=Short.valueOf(tokens[i].split("//")[0]);
                s--;
                tmpFaces.add(s);
                s=Short.valueOf(tokens[i].split("//")[1]);
                s--;
                tmpVn.add(s);
            }
            faces.addAll(triangulate(tmpFaces));
            vnPointer.addAll(triangulate(tmpVn));
        }
    }
```

最后，`v/vt/vn`情况如下：

```kt
    if(tokens[1].matches("[0-9]+/[0-9]+/[0-9]+")){//f: v/vt/vn
        if(c==4){//3 faces
            for(int i=1; i<c; i++){
                Short s=Short.valueOf(tokens[i].split("/")[0]);
                s--;
                faces.add(s);
                // (skip vt)
                s=Short.valueOf(tokens[i].split("/")[2]);
                s--;
                vnPointer.add(s);
            }
        }
        else{//triangulate
            Vector<Short> tmpFaces=new Vector<Short>();
            Vector<Short> tmpVn=new Vector<Short>();
            for(int i=1; i<tokens.length; i++){
                Short s=Short.valueOf(tokens[i].split("/")[0]);
                s--;
                tmpFaces.add(s);
                // (skip vt)
                s=Short.valueOf(tokens[i].split("/")[2]);
                s--;
                tmpVn.add(s);
            }
            faces.addAll(triangulate(tmpFaces));
            vnPointer.addAll(triangulate(tmpVn));
        }
    }
```

如前所述，在 OBJ 文件格式描述中，索引可以是负数；在这种情况下，它们需要从顶点列表的末尾向后引用。这可以通过将索引值添加到索引列表的大小来实现。为了支持这一点，在前面的代码中，用以下内容替换所有`s--`行：

```kt
                   if (s < 0)
                       s = (short)(s + v.size());
                   else
                       s--;
```

## buildBuffers

`parseObj`方法的最后一步是从模型数据构建我们的着色器缓冲区，即`vertexBuffer`、`normalBuffer`和`indexBuffer`变量。我们现在可以将其添加到`buildBuffers`方法中，如下所示：

```kt
    private void buildBuffers() {
        numIndices = faces.size();
        float[] tmp = new float[v.size()];
        int i = 0;
        for(Float f : v)
            tmp[i++] = (f != null ? f : Float.NaN);
        vertexBuffer = allocateFloatBuffer(tmp);

        i = 0;
        tmp = new float[vn.size()];
        for(Float f : vn)
            tmp[i++] = (f != null ? -f : Float.NaN); 
            //invert normals
        normalBuffer = allocateFloatBuffer(tmp);

        i = 0;
        short[] indicies = new short[faces.size()];
        for(Short s : faces)
            indicies[i++] = (s != null ? s : 0);
        indexBuffer = allocateShortBuffer(indicies);
    }
```

有一个注意事项。我们注意到对于`RenderBox`坐标系和着色器，有必要从 OBJ 数据中反转法线（使用`-f`而不是`f`）。实际上，这取决于 OBJ 导出器（3Ds Max、Blender 和 Maya）。其中一些会翻转法线，而另一些则不会。不幸的是，除了查看模型之外，没有办法确定法线是否被翻转。因此，一些 OBJ 导入器/查看器提供了（可选的）功能，可以根据面几何计算法线，而不是依赖于导入数据本身。

# 模型范围、缩放和中心

3D 模型有各种形状和大小。为了在我们的应用程序中查看它们，我们需要知道模型的最小和最大边界以及其几何中心，以便适当地进行缩放和定位。让我们现在将这些添加到`ModelObject`中。

在`ModelObject`类的顶部，添加以下变量：

```kt
    public Vector3 extentsMin, extentsMax;
```

在解析器中初始化范围，然后解析模型数据。最小范围初始化为最大可能值；最大范围初始化为最小可能值：

```kt
    public ModelObject(int objFile) {
        super();
        extentsMin = new Vector3(Float.MAX_VALUE, Float.MAX_VALUE, Float.MAX_VALUE);
        extentsMax = new Vector3(Float.MIN_VALUE, Float.MIN_VALUE, Float.MIN_VALUE);
        . . .
```

我们将在模型加载后而不是在导入过程中计算范围。当我们向顶点列表添加一个新顶点时，我们将计算当前范围。在`processVLine`循环中添加一个调用`setExtents`：

```kt
    private void processVLine(String line) {
        String[] tokens = line.split("[ ]+"); 
        //split the line at the spaces
        int c = tokens.length;
        for (int i = 1; i < c; i++) { //add the vertex to the vertex array
            Float value = Float.valueOf(tokens[i]);
            v.add(value);
            setExtents(i, value);
        }
    }
```

然后，`setExtents`方法可以实现如下：

```kt
    private void setExtents(int coord, Float value) {
        switch (coord) {
            case 1:
                if (value < extentsMin.x)
                    extentsMin.x = value;
                if (value > extentsMax.x)
                    extentsMax.x = value;
                break;
            case 2:
                if (value < extentsMin.y)
                    extentsMin.y = value;
                if (value > extentsMax.y)
                    extentsMax.y = value;
                break;
            case 3:
                if (value < extentsMin.z)
                    extentsMin.z = value;
                if (value > extentsMax.z)
                    extentsMax.z = value;
                break;
        }
    }
```

让我们添加一个标量方法，当我们将模型添加到场景中时会很有用（正如你将在下一个主题中看到的），将其缩放到一个标准大小，范围为`-1`到`1`：

```kt
    public float normalScalar() {
        float sizeX = (extentsMax.x - extentsMin.x);
        float sizeY = (extentsMax.y - extentsMin.y);
        float sizeZ = (extentsMax.z - extentsMin.z);
        return (2.0f / Math.max(sizeX, Math.max(sizeY, sizeZ)));
    }
```

现在，让我们试试吧！

# 我是一个小茶壶

几十年来，3D 计算机图形研究人员和开发人员一直在使用这个可爱的茶壶模型。它是一个经典！背后的故事是，著名的计算机图形先驱和研究人员马丁·纽维尔需要一个模型来进行他的工作，他的妻子建议他在家里对他们的茶壶进行建模。原作现在展览在波士顿计算机博物馆。我们已经在本书的可下载文件中包含了这个经典模型的 OBJ 版本。

当然，你可以选择自己的 OBJ 文件，但如果你想使用茶壶，找到`teapot.obj`文件，并将其复制到`res/raw`文件夹中（如果需要，创建该文件夹）。

现在加载模型并尝试。在`MainActivity`中，添加一个变量到`MainActivity`类的顶部来保存当前模型：

```kt
    Transform model;
```

将以下代码添加到`setup`方法中。注意，我们将其缩放到原始大小的一小部分，并将其放置在摄像头前方 3 个单位处：

```kt
    public void setup() {
        ModelObject modelObj = new ModelObject(R.raw.teapot);
        float scalar = modelObj.normalScalar();
        model = new Transform()
                .setLocalPosition(0, 0, -3)
                .setLocalScale(scalar, scalar, scalar)
                .addComponent(modelObj);
    }
```

运行项目，应该看起来像这样：

![我是一个小茶壶](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_08_01.jpg)

你可以看到模型已经成功加载和渲染。不幸的是，阴影很难辨认。为了更好地观看阴影茶壶，让我们把它下移一点。修改`setup`中的`setLocalPosition`方法，如下所示：

```kt
                .setLocalPosition(0, -2, -3) 
```

以下截图被裁剪和放大，这样你就可以看到这里的阴影茶壶，就像你在 Cardboard 观看器中看到的一样：

![我是一个小茶壶](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_08_02.jpg)

# 我是一个旋转的小茶壶

通过旋转模型来增强观看体验，当用户旋转头部时模型也会旋转。这种效果与“正常”的虚拟现实体验不同。通常情况下，在 VR 中移动头部会旋转场景中相机的主观视图，以便与头部运动一起四处张望。在这个项目中，头部运动就像一个输入控制旋转模型。模型始终固定在你面前的位置。

实现这个功能非常简单。`RenderBox preDraw`接口方法在每一帧开始时被调用。我们将获取当前的头部角度并相应地旋转模型，将头部后欧拉角转换为四元数（组合多个欧拉角可能导致意外的最终旋转方向）。我们还会共轭（即反转）旋转，这样当你抬头时，你会看到物体的底部，依此类推。这样感觉更自然。

在`MainActivity`中，添加以下代码到`preDraw`：

```kt
    public void preDraw() {
        float[] hAngles = RenderBox.instance.headAngles;
        Quaternion rot = new Quaternion();
        rot.setEulerAnglesRad(hAngles[0], hAngles[1], hAngles[2]);
        model.setLocalRotation(rot.conjugate());
    }
```

在`setup`中，确保`setLocalPosition`方法将茶壶直立在摄像头前方：

```kt
                .setLocalPosition(0, 0, -3)
```

尝试运行它。我们快要成功了！模型随着头部旋转，但我们仍然在 VR 空间中四处张望。

为了锁定头部位置，我们只需要在`RenderBox`中禁用头部跟踪。如果你的`RenderBox`版本（在第五章中构建的*RenderBox Engine*）还没有这个功能，那么将其添加到你的单独的`RenderBoxLib` lib 项目中，如下所示：

在`Camera.java`文件中，首先添加一个新的公共变量`headTracking`：

```kt
    public boolean headTracking = true;
```

修改`onDrawEye`方法以有条件地更新视图变换，如下所示：

```kt
        if (headTracking) {
            // Apply the eye transformation to the camera.
            Matrix.multiplyMM(view, 0, eye.getEyeView(), 0, camera, 0);
        } else {
             // copy camera into view
            for (int i=0; i < camera.length; i++) { view[i] = camera[i]; }
        }
```

确保在重新构建后将更新的`.aar`文件复制到`ModelViewer`项目的`RenderBox`模块文件夹中。

现在，在`MainActivity`类的`setup()`中，添加以下设置：

```kt
        RenderBox.instance.mainCamera.headTracking = false;
```

现在运行它，当你移动头部时，模型保持相对静止，但随着你转动头部而旋转。太棒了！好多了。

# 线程安全

在第七章中，*360 度画廊*，我们解释了需要工作线程将处理从渲染线程中卸载的需求。在这个项目中，我们将在`ModelObject`构造函数中添加线程，用于读取和解析模型文件：

```kt
    public ModelObject(final int objFile) {
        super();
        extentsMin = new Vector3(Float.MAX_VALUE, Float.MAX_VALUE, Float.MAX_VALUE);
        extentsMax = new Vector3(Float.MIN_VALUE, Float.MIN_VALUE, Float.MIN_VALUE);

        SolidColorLightingMaterial.setupProgram();
        enabled = false;
        new Thread(new Runnable() {
            @Override
            public void run() {
                InputStream inputStream = RenderBox.instance.mainActivity.getResources().openRawResource(objFile);
                if (inputStream == null)
                    return; // error
                createMaterial();
                enabled = true;
                float scalar = normalScalar();
                transform.setLocalScale(scalar, scalar, scalar);
            }
        }).start();
    }
```

我们必须将文件句柄`objFile`声明为`final`，以便能够从内部类中访问它。您可能还注意到，我们在启动线程之前添加了对材质的`setup`程序的调用，以确保它在时间上得到正确设置并避免崩溃应用。这避免了在`queueEvent`过程中调用`createMaterial`的需要，因为着色器编译器利用了图形上下文。同样，我们在加载完成之前禁用对象。最后，由于加载是异步的，必须在此过程的末尾设置比例。我们以前的方法在`setup()`中设置了比例，现在在模型加载完成之前完成了。

# 使用意图启动

在第七章中，*360 度画廊*，我们介绍了使用 Android 意图将应用程序与特定文件类型相关联，以便将我们的应用程序作为这些文件的查看器启动。我们将在这里为 OBJ 文件做同样的事情。

**意图**是任何应用程序都可以发送到 Android 系统的消息，宣告其意图使用另一个应用程序来完成某个特定目的。意图对象包含许多成员，用于描述需要执行的操作类型，以及（如果有的话）需要执行操作的数据。对于图像库，我们将意图过滤器与图像 MIME 类型相关联。对于这个项目，我们将意图过滤器与文件名扩展名相关联。

在您的`AndroidManifest.xml`文件中，向活动块添加一个意图过滤器。这让 Android 知道该应用程序可以用作 OBJ 文件查看器。我们需要将其指定为文件方案和文件名模式。通配符 MIME 类型和主机也是 Android 所必需的。添加以下 XML 代码：

```kt
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="file" />
                <data android:mimeType="*/*" />
                <data android:pathPattern=".*\\.obj" />
                <data android:host="*" />
            </intent-filter>
```

为了处理这种情况，我们将在`ModelObject`中添加一个新的构造函数，该构造函数接受一个 URI 字符串而不是资源 ID，就像我们之前做的那样。与其他构造函数一样，我们需要打开一个输入流并将其传递给`parseObj`。以下是构造函数，包括工作线程：

```kt
    public ModelObject(final String uri) {
        super();
        extentsMin = new Vector3(Float.MAX_VALUE, Float.MAX_VALUE, Float.MAX_VALUE);
        extentsMax = new Vector3(Float.MIN_VALUE, Float.MIN_VALUE, Float.MIN_VALUE);
        SolidColorLightingMaterial.setupProgram();
        enabled = false;
        new Thread(new Runnable() {
            @Override
            public void run() {
                File file = new File(uri.toString());
                FileInputStream fileInputStream;
                try {
                    fileInputStream = new FileInputStream(file);
                } catch (IOException e) {
                    e.printStackTrace();
                    return; // error
                }
                parseObj(fileInputStream);
                createMaterial();
                enabled = true;
                float scalar = normalScalar();
                transform.setLocalScale(scalar, scalar, scalar);
            }
        }).start();
    }
```

现在在`MainActivity`类的`setup`中，我们将检查应用程序是否是从意图启动的，并使用意图 URI。否则，我们将查看默认模型，就像我们之前做的那样：

```kt
    public void setup() {
        ModelObject modelObj;
        Uri intentUri = getIntent().getData();
        if (intentUri != null) {
            Log.d(TAG, "!!!! intent " + intentUri.getPath());
            modelObj = new ModelObject(intentUri.getPath());
        } else {
            // default object
            modelObj = new ModelObject(R.raw.teapot);
        }
        //...        
```

现在项目已经构建并安装到手机上，让我们尝试一些网络集成。打开网络浏览器并访问一个 3D 模型下载网站。

找到有趣模型的**下载**链接，将其下载到手机上，然后在提示时，使用`ModelViewer`应用程序查看它！

# 实用和生产就绪

请注意，正如前面提到的，我们已经创建了 OBJ 模型格式的有限实现，因此您找到的每个模型在这一点上可能无法正确查看（如果有的话）。不过，这可能是足够的，取决于您自己项目的要求，例如，如果您在资源文件夹中包含特定模型，可以在应用的发布版本中查看。当您完全控制输入数据时，您可以偷个懒。

虽然 OBJ 文件格式的基本结构并不是非常复杂，正如我们在这里所展示的，就像软件（以及生活中的许多事物）一样，“魔鬼在细节中”。以这个项目作为起点，然后构建您自己的实用和生产就绪的 OBJ 文件解析器和渲染器将需要相当多的额外工作。您还可以研究现有的软件包、其他模型格式，或者甚至从开源游戏引擎（如 LibGDX）中提取一些代码。我们省略的 OBJ 的特性，但值得考虑的包括以下内容：

+   纹理顶点

+   材质定义

+   曲线元素

+   几何图形的分组

+   颜色和其他顶点属性

# 总结

在这个项目中，我们编写了一个简单的查看器，用于以开放的 OBJ 文件格式查看 3D 模型。我们实现了一个`ModelObject`类，它解析模型文件并构建了`RenderBox`需要的向量和法线缓冲区，以在场景中渲染对象。然后我们启用了阴影。然后我们使查看器交互，这样模型就会随着你移动头部而旋转。

在下一章中，我们将探索另一种类型的媒体，即音乐。音乐可视化器会响应当前的音乐播放器，在 VR 世界中显示跳舞的几何图形。


# 第九章：音乐可视化

> “'看音乐，听舞蹈'，”著名的俄罗斯裔编舞家、美国芭蕾舞之父乔治·巴兰钦说道。

我们不打算提升艺术形式的水平，但或许将手机上的播放列表可视化会很有趣。在这个项目中，我们将创建 3D 动画抽象图形，以音乐的节奏起舞。您可能熟悉 2D 音乐可视化，但在 VR 中会是什么样子呢？要获得灵感，可以尝试使用短语*geometry wars*在 Google 上搜索图像，例如 XBox 的经典游戏！

可视化应用程序从 Android 音频系统接收输入并显示可视化效果。在这个项目中，我们将利用 Android 的`Visualizer`类，让应用程序捕获当前播放音频的一部分，而不是完整的高保真音乐细节，而是足够进行可视化的低质量音频内容。

在这个项目中，我们将：

+   设置新项目

+   构建名为 VisualizerBox 的 Java 类架构

+   从手机音频播放器中捕获波形数据

+   构建几何可视化

+   构建基于纹理的可视化

+   捕获 FFT 数据并构建 FFT 可视化

+   添加迷幻轨迹模式

+   支持多个并发可视化

此项目的源代码可以在 Packt Publishing 网站和 GitHub 上找到，网址为[`github.com/cardbookvr/visualizevr`](https://github.com/cardbookvr/visualizevr)（每个主题作为单独的提交）。

# 设置新项目

要构建此项目，我们将使用我们在第五章中创建的 RenderBox 库，*RenderBox 引擎*。您可以使用您自己的库，或者从本书提供的可下载文件或我们的 GitHub 存储库中获取副本（使用标记为`after-ch8`的提交 - [`github.com/cardbookvr/renderboxlib/releases/tag/after-ch8`](https://github.com/cardbookvr/renderboxlib/releases/tag/after-ch8)）。有关如何导入`RenderBox`库的更详细描述，请参阅第五章的最后一节，*在未来项目中使用 RenderBox*。要创建新项目，请执行以下步骤：

1.  打开 Android Studio，创建一个新项目。让我们将其命名为`VisualizeVR`，并针对**Android 4.4 KitKat (API 19)**使用**空活动**。

1.  为`renderbox`、`common`和`core`包创建新模块，使用**文件**|**新建模块**|**导入.JAR/.AAR 包**。

1.  将模块设置为应用程序的依赖项，使用**文件**|**项目结构**。

1.  根据第二章中的说明编辑`build.gradle`文件，*骨架硬纸板项目*，以便编译针对 SDK 22。

1.  更新`/res/layout/activity_main.xml`和`AndroidManifest.xml`，如前几章所述。

1.  将`MainActivity`编辑为`class MainActivity extends CardboardActivity implements IRenderBox`，并实现接口方法存根（*Ctrl* + *I*）。

我们可以继续在`MainActivity`中定义`onCreate`方法。该类现在具有以下代码：

```kt
public class MainActivity extends CardboardActivity implements IRenderBox {
    private static final String TAG = "MainActivity";CardboardView cardboardView;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        cardboardView = (CardboardView) findViewById(R.id.cardboard_view);
        cardboardView.setRenderer(new RenderBox(this, this));
        setCardboardView(cardboardView);
    }
    @Override
    public void setup() {
    }
    @Override
    public void preDraw() {
        // code run beginning each frame
    }
    @Override
    public void postDraw() {
        // code run end of each frame
    }
}
```

您可以将一个立方体临时添加到场景中，以确保一切设置正确。将其添加到`setup`方法中，如下所示：

```kt
    public void setup() {
        new Transform()
            .setLocalPosition(0,0,-7)
            .setLocalRotation(45,60,0)
            .addComponent(new Cube(true));
    }
```

如果您记得，`Cube`是添加到`Transform`的`Component`。`Cube`定义了其几何形状（例如，顶点）。`Transform`定义了其在 3D 空间中的位置、旋转和缩放。

您应该能够在 Android 设备上单击**运行'app'**而没有编译错误，并看到立方体和硬纸板分屏视图。

# 捕获音频数据

使用 Android 的`Visualizer`类（[`developer.android.com/reference/android/media/audiofx/Visualizer.html`](http://developer.android.com/reference/android/media/audiofx/Visualizer.html)），我们可以以指定的采样率检索当前播放的音频数据的一部分。您可以选择捕获波形和/或频率数据：

+   **波形**：这是表示音频振幅采样系列的单声道音频波形字节数组，或**脉冲编码调制**（**PCM**）数据

+   **频率**：这是表示音频频率采样的**快速傅立叶变换**（**FFT**）字节数组

数据限制为 8 位，因此对于播放而言并不有用，但对于可视化来说足够了。您可以指定采样率，尽管它必须是 2 的幂。

掌握了这些知识，我们现在将继续实施一个架构，捕获音频数据并使其可用于您可以构建的可视化渲染器。

# VisualizerBox 架构

音乐可视化器通常看起来非常酷，尤其是一开始。但是一段时间后，它们可能会显得太重复，甚至无聊。因此，在我们的设计中，我们将构建一个能够排队一些不同可视化的能力，然后在一段时间后从一个切换到另一个。

为了开始我们的实施，我们将定义一个可扩展的架构结构，让我们在开发新的可视化时能够扩展。

然而，即使在那之前，我们必须确保应用程序有权限使用我们需要的 Android 音频功能。将以下指令添加到`AndroidManifest.xml`中：

```kt
    <!-- Visualizer permissions -->
    <uses-permission android:name="android.permission.RECORD_AUDIO" />
    <uses-permission android:name="android.permission.MODIFY_AUDIO_SETTINGS" />
```

请记住，`RenderBox`库最初是在第五章中开发的，*RenderBox 引擎*，允许`MainActivity`将大部分图形和 Cardboard VR 工作委托给`RenderBox`类和相关类（`Component`，`Material`等）。我们将在此基础上构建一个类似的设计模式，建立在`RenderBox`之上。`MainActivity`可以实例化特定的可视化，然后将工作委托给`VisualizerBox`类。

`VisualizerBox`类将提供回调函数给 Android 的`Visualizer`类。让我们首先定义这个的骨架实现。创建一个`VisualizerBox`Java 类，如下所示：

```kt
public class VisualizerBox {
    static final String TAG = "VisualizerBox";
    public VisualizerBox(final CardboardView cardboardView){
    }
    public void setup() {
    }
    public void preDraw() {
    }
    public void postDraw() {
    }
}
```

将`VisualizerBox`集成到`MainActivity`中，在类的顶部添加一个`visualizerBox`变量。在`MainActivity`中，添加以下行：

```kt
    VisualizerBox visualizerBox;
```

在`onCreate`中进行初始化：

```kt
        visualizerBox = new VisualizerBox(cardboardView);
```

此外，在`MainActivity`中，调用每个`IRenderBox`接口方法的相应版本：

```kt
    @Override
    public void setup() {
        visualizerBox.setup();
    }
    @Override
    public void preDraw() {
        visualizerBox.preDraw();
    }
    @Override
    public void postDraw() {
        visualizerBox.postDraw();
    }
```

很好。现在我们将设置`VisualizerBox`，让您构建和使用一个或多个可视化。因此，首先让我们在`Visualization.java`文件中定义抽象的`Visualization`类，如下所示：

```kt
public abstract class Visualization {
    VisualizerBox visualizerBox;            //owner

    public Visualization(VisualizerBox visualizerBox){
        this.visualizerBox = visualizerBox;
    }
    public abstract void setup();
    public abstract void preDraw();
    public abstract void postDraw();
}
```

现在我们有了一个机制来为应用程序创建各种可视化实现。在我们继续编写其中一个之前，让我们还提供与`VisualizerBox`的集成。在`VisualizerBox`类的顶部，添加一个变量到当前的`activeViz`对象：

```kt
    public Visualization activeViz;
```

然后，从接口方法中调用它：

```kt
    public void setup() {
        if(activeViz != null)
            activeViz.setup();
    }
    public void preDraw() {
        if(activeViz != null)
            activeViz.preDraw();
    }
    public void postDraw() {
        if(activeViz != null)
            activeViz.postDraw();
    }
```

当然，我们甚至还没有使用 Android 的`Visualizer`类，也没有在屏幕上渲染任何东西。接下来会有。

现在，让我们为可视化创建一个占位符。在项目中创建一个名为`visualizations`的新文件夹。右键单击您的 Java 代码文件夹（例如`java/com/cardbookvr/visualizevr/`），转到**新建** | **包**，并将其命名为`visualizations`。然后，右键单击新的`visualizations`文件夹，转到**新建** | **Java 类**，并将其命名为`BlankVisualization`。然后，将其定义为`extends Visualization`，如下所示：

```kt
public class BlankVisualization extends Visualization {
    static final String TAG = "BlankVisualization";
    public BlankVisualization(VisualizerBox visualizerBox) {
        super(visualizerBox);
    }
    @Override
    public void setup() {
    }
    @Override
    public void preDraw() {
    }
    @Override
    public void postDraw() {
    }
}
```

我们将能够将其用作特定可视化器的模板。每种方法的目的都相当不言自明：

+   `setup`：这个方法初始化可视化的变量、转换和材料

+   `preDraw`：此代码在每帧开始时执行；例如，使用当前捕获的音频数据

+   `postDraw`：此代码在每帧结束时执行

现在让我们给这个骨架添加一些内容。

# 波形数据捕获

如前所述，Android 的`Visualizer`类让我们定义回调来捕获音频数据。这些数据有两种格式：波形和 FFT。我们现在将仅添加波形数据到`VisualizerBox`类中。

首先，定义我们将用于捕获音频数据的变量，如下所示：

```kt
    Visualizer visualizer;
    public static int captureSize;
    public static byte[] audioBytes;
```

使用 API，我们可以确定可用的最小捕获大小，然后将其用作我们的捕获样本大小。

然后，在构造函数中初始化它们如下。首先，实例化一个 Android`Visualizer`。然后设置要使用的捕获大小，并分配我们的缓冲区：

```kt
    public VisualizerBox(final CardboardView cardboardView){
        visualizer = new Visualizer(0);
        captureSize = Visualizer.getCaptureSizeRange()[0];
        visualizer.setCaptureSize(captureSize);
        // capture audio data
        // Visualizer.OnDataCaptureListener captureListener = ...
        visualizer.setDataCaptureListener(captureListener, Visualizer.getMaxCaptureRate(), true, true);
        visualizer.setEnabled(true);
    }
```

我们希望出于各种原因使用最小尺寸。首先，它会更快，而在虚拟现实中，速度至关重要。其次，它将我们的 FFT 样本（稍后讨论）组织成更少的桶。这很有帮助，因为每个桶可以在更广泛的频率范围内捕捉更多的活动。

### 注意

请注意，我们在定义捕获监听器的地方留下了一个注释，然后在可视化器中设置它。确保你启用了可视化器作为始终监听。

首先编写仅用于波形数据的`captureListener`对象。我们定义并实例化一个实现`Visualizer.OnDataCaptureListener`的新匿名类，并为其提供一个名为`onWaveFormDataCapture`的函数，该函数接收波形字节并将其存储到我们的`Visualization`代码中（即将推出）：

```kt
        // capture audio data
        Visualizer.OnDataCaptureListener captureListener = new Visualizer.OnDataCaptureListener() {
            @Override
            public void onWaveFormDataCapture(Visualizer visualizer, byte[] bytes, int samplingRate) {
                audioBytes = bytes;
            }
            @Override
            public void onFftDataCapture(Visualizer visualizer, byte[] bytes, int samplingRate) {
            }
        };
```

界面仍然要求我们提供一个`onFftDataCapture`方法，但我们暂时将其留空。

现在我们准备为这个项目添加一些图形。

# 一个基本的几何可视化

对于我们的第一个可视化，我们将创建一个基本的均衡器波形图形。它将是一个由一系列根据音频波形数据进行缩放的立方体组成的矩形块。我们将使用内置的`Cube`组件，已经在`RenderBox`库中的基本顶点颜色照明材质。

在`visualizations/`文件夹中，创建一个名为`GeometricVisualization`的新的 Java 类，并开始如下：

```kt
public class GeometricVisualization extends Visualization {
    static final String TAG = "GeometricVisualization";
    public GeometricVisualization(VisualizerBox visualizerBox) {
        super(visualizerBox);
    }
}
```

在类的顶部，声明一个立方体变换的`Transform`数组和相应的`RenderObjects`数组：

```kt
    Transform[] cubes;
    Cube[] cubeRenderers;
```

然后，在`setup`方法中初始化它们。我们将分配立方体数组，对齐并缩放为相邻的一组块，创建一个波浪状块的 3D 表示。`setup`方法可以实现如下：

```kt
    public void setup() {
        cubes = new Transform[VisualizerBox.captureSize / 2];
        cubeRenderers = new Cube[VisualizerBox.captureSize / 2];

        float offset = -3f;
        float scaleFactor = (offset * -2) / cubes.length;
        for(int i = 0; i < cubes.length; i++) {
            cubeRenderers[i] = new Cube(true);
            cubes[i] = new Transform()
                    .setLocalPosition(offset, -2, -5)
                    .addComponent(cubeRenderers[i]);
            offset += scaleFactor;
        }
    }
```

现在在每一帧上，我们只需要根据音频源中当前的波形数据（在`VisualizerBox`中获取）修改每个立方体的高度。实现`preDraw`方法如下：

```kt
    public void preDraw() {
        if (VisualizerBox.audioBytes != null) {
            float scaleFactor = 3f / cubes.length;
            for(int i = 0; i < cubes.length; i++) {
                cubes[i].setLocalScale(scaleFactor, VisualizerBox.audioBytes[i] * 0.01f, 1);
            }
        }
    }

    public void postDraw() {
    }
```

我们还需要为`postDraw`实现添加一个存根。然后，实例化可视化并使其成为活动状态。在`MainActivity`中，在`onCreate`的末尾，添加以下代码行：

```kt
        visualizerBox.activeViz = new GeometricVisualization(visualizerBox);
```

现在我们只需要这些。

在手机上播放一些音乐。然后运行应用程序。你会看到类似这样的东西：

![基本几何可视化](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_09_01.jpg)

正如你所看到的，我们在场景中保留了单位立方体，因为它有助于澄清发生了什么。每个音频数据都是一个薄的“切片”（或者是一个扁平的立方体），其高度随音频值的变化而变化。如果你正在查看前一个屏幕图像的彩色版本，你会注意到可视化立方体的彩色面就像孤立的立方体，因为它们使用相同的对象和材质进行渲染。

这个可视化是使用音频波形数据动态修改 3D 几何的一个非常基本的例子。让你的想象力奔放，创造属于你自己的。音频字节可以控制任何变换参数，包括比例、位置和旋转。记住我们在一个 3D 虚拟现实空间中，你可以使用所有这些——把你的东西四处移动，上下移动，甚至在你的身后。我们有一些基本的原始几何形状（立方体、球体、平面、三角形等）。但你也可以使用音频数据来参数化生成新的形状和模型。此外，你甚至可以集成前一章的`ModelObject`类来加载有趣的 3D 模型！

在下一个主题中，我们将看看如何在基于纹理的材质着色器中使用音频波形数据。

# 基于 2D 纹理的可视化

第二个可视化也将是基本的示波器类型显示波形数据。然而，以前我们使用音频数据来缩放 3D 切片立方体；这一次，我们将使用一个着色器，在 2D 平面上渲染它们全部，使用音频数据作为输入。

我们的`RenderBox`库允许我们定义新的材质和着色器。在以前的项目中，我们构建了使用位图图像进行纹理映射的材质，以便在渲染时将其渲染到几何图形上。在这个项目中，我们将使用音频字节数组来绘制四边形，使用字节值来控制设置更亮颜色的位置。（请注意，`Plane`类是在第七章中添加到`RenderBox`库中的，*360 度画廊*。）

## 纹理生成器和加载器

首先，让我们生成一个纹理结构来保存我们的纹理数据。在`VisualizerBox`类中，添加以下方法来设置 GLES 中的纹理。我们不能使用我们正常的纹理流程，因为它是设计为直接从图像数据中分配纹理。我们的数据是一维的，所以使用`Texture2D`资源可能看起来有点奇怪，但我们将高度设置为一个像素：

```kt
    public static int genTexture(){
        final int[] textureHandle = new int[1];
        GLES20.glGenTextures(1, textureHandle, 0);
        RenderBox.checkGLError("VisualizerBox GenTexture");
        if (textureHandle[0] != 0) {
            // Bind to the texture in OpenGL
            GLES20.glBindTexture(GLES20.GL_TEXTURE_2D, textureHandle[0]);
            // Set filtering
            GLES20.glTexParameteri(GLES20.GL_TEXTURE_2D, GLES20.GL_TEXTURE_MIN_FILTER, GLES20.GL_NEAREST);
            GLES20.glTexParameteri(GLES20.GL_TEXTURE_2D, GLES20.GL_TEXTURE_MAG_FILTER, GLES20.GL_NEAREST);
        }
        if (textureHandle[0] == 0){
            throw new RuntimeException("Error loading texture.");
        }
        return textureHandle[0];
    }
```

然后添加`setup`的调用，包括一个静态变量来保存生成的纹理句柄：

```kt
    public static int audioTexture = -1;

    public void setup() {
        audioTexture = genTexture();
        if(activeViz != null)
            activeViz.setup();
    }
```

现在我们可以从音频字节数据中填充纹理。在 Android 的`Visualizer`监听器中，在`onWaveFormDataCapture`方法中添加一个`loadTexture`的调用：

```kt
            public void onWaveFormDataCapture(Visualizer visualizer, byte[] bytes, int samplingRate){
                audioBytes = bytes;
                loadTexture(cardboardView, audioTexture, bytes);
            }
```

让我们按照以下方式定义`loadTexture`。它将音频字节复制到一个新的数组缓冲区，并将其传递给 OpenGL ES，使用`glBindTexture`和`glTexImage2D`调用。

（参考[`stackoverflow.com/questions/14290096/how-to-create-a-opengl-texture-from-byte-array-in-android`](http://stackoverflow.com/questions/14290096/how-to-create-a-opengl-texture-from-byte-array-in-android)。）：

```kt
    public static void loadTexture(CardboardView cardboardView, final int textureId, byte[] bytes){
        if(textureId < 0)
            return;
        final ByteBuffer buffer = ByteBuffer.allocateDirect(bytes.length * 4);
        final int length = bytes.length;
        buffer.order(ByteOrder.nativeOrder());
        buffer.put(bytes);
        buffer.position(0);
        cardboardView.queueEvent(new Runnable() {
            @Override
            public void run() {
                GLES20.glBindTexture(GLES20.GL_TEXTURE_2D, textureId);
                GLES20.glTexImage2D(GLES20.GL_TEXTURE_2D, 0, GLES20.GL_LUMINANCE, length, 1, 0,
                        GLES20.GL_LUMINANCE, GLES20.GL_UNSIGNED_BYTE, buffer);
            }
        });
    }
```

## 波形着色器

现在是时候编写着色器程序了，这些程序将决定在`Material`类中需要设置的参数和属性，以及其他内容。

如果需要，为着色器创建一个资源目录，`res/raw/`。然后，创建`waveform_vertex.shader`和`waveform_fragment.shader`文件。定义如下。

`waveform_vertex.shader`文件与我们之前使用的`unlit_tex_vertex`着色器相同。严格来说，我们可以重用这个文件，并在`createProgram`函数中指定它的资源，但是除非你明确遵循某种模式，否则最好定义单独的着色器文件。

文件：`res/raw/waveform_vertex.shader`：

```kt
uniform mat4 u_MVP;
attribute vec4 a_Position;
attribute vec2 a_TexCoordinate;
varying vec2 v_TexCoordinate;
void main() {
   // pass through the texture coordinate
   v_TexCoordinate = a_TexCoordinate;
   // final point in normalized screen coordinates
   gl_Position = u_MVP * a_Position;
}
```

对于`waveform_fragment`着色器，我们添加了一个固定颜色（`u_Color`）和阈值宽度（`u_Width`）的变量。然后，添加一些逻辑来决定当前正在渲染的像素的*y*坐标是否在样本的`u_Width`范围内。

文件：`res/raw/waveform_fragment.shader`

```kt
precision mediump float;        // default medium precision
uniform sampler2D u_Texture;    // the input texture
varying vec2 v_TexCoordinate;   // interpolated texture coordinate per fragment
uniform vec4 u_Color;
uniform float u_Width;
// The entry point for our fragment shader.
void main() {
    vec4 color;
    float dist = abs(v_TexCoordinate.y - texture2D(u_Texture, v_TexCoordinate).r);
    if(dist < u_Width){
        color = u_Color;
    }
    gl_FragColor = color;
}
```

## 基本波形材质

现在我们为着色器定义`Material`类。创建一个名为`WaveformMaterial`的新的 Java 类，并将其定义如下：

```kt
public class WaveformMaterial extends Material {
    private static final String TAG = "WaveformMaterial";
}
```

为纹理 ID、边框、宽度和颜色添加材质变量。然后，添加着色器程序引用和缓冲区的变量，如下所示：

```kt
    static int program = -1; //Initialize to a totally invalid value for setup state
    static int positionParam;
    static int texCoordParam;
    static int textureParam;
    static int MVPParam;
    static int colorParam;
    static int widthParam;

    public float borderWidth = 0.01f;
    public float[] borderColor = new float[]{0.6549f, 0.8392f, 1f, 1f};

    FloatBuffer vertexBuffer;
    FloatBuffer texCoordBuffer;
    ShortBuffer indexBuffer;
    int numIndices;
```

现在我们可以添加一个构造函数。正如我们之前看到的，它调用了一个`setupProgram`辅助方法，该方法创建着色器程序并获取对其参数的引用：

```kt
    public WaveformMaterial() {
        super();
        setupProgram();
    }

    public static void setupProgram() {
        if(program > -1) return;
        //Create shader program
        program = createProgram( R.raw.waveform_vertex, R.raw.waveform_fragment );
        RenderBox.checkGLError("Bitmap GenTexture");

        //Get vertex attribute parameters
        positionParam = GLES20.glGetAttribLocation(program, "a_Position");
        RenderBox.checkGLError("Bitmap GenTexture");
        texCoordParam = GLES20.glGetAttribLocation(program, "a_TexCoordinate");
        RenderBox.checkGLError("Bitmap GenTexture");

        //Enable them (turns out this is kind of a big deal ;)
        GLES20.glEnableVertexAttribArray(positionParam);
        RenderBox.checkGLError("Bitmap GenTexture");
        GLES20.glEnableVertexAttribArray(texCoordParam);
        RenderBox.checkGLError("Bitmap GenTexture");

        //Shader-specific parameters
        textureParam = GLES20.glGetUniformLocation(program, "u_Texture");
        MVPParam = GLES20.glGetUniformLocation(program, "u_MVP");
        colorParam = GLES20.glGetUniformLocation(program, "u_Color");
        widthParam = GLES20.glGetUniformLocation(program, "u_Width");
        RenderBox.checkGLError("Waveform params");
    }
```

同样，我们添加一个`setBuffers`方法，供`RenderObject`组件（`Plane`）调用：

```kt
    public WaveformMaterial setBuffers(FloatBuffer vertexBuffer, FloatBuffer texCoordBuffer, ShortBuffer indexBuffer, int numIndices) {
        //Associate VBO data with this instance of the material
        this.vertexBuffer = vertexBuffer;
        this.texCoordBuffer = texCoordBuffer;
        this.indexBuffer = indexBuffer;
        this.numIndices = numIndices;
        return this;
    }
```

添加`draw`代码，它将从`Camera`组件中调用，以渲染在缓冲区中准备的几何图形（通过`setBuffers`）。`draw`方法如下所示：

```kt
    @Override
    public void draw(float[] view, float[] perspective) {
        GLES20.glUseProgram(program);

        // Set the active texture unit to texture unit 0.
        GLES20.glActiveTexture(GLES20.GL_TEXTURE0);

        // Bind the texture to this unit.
        GLES20.glBindTexture(GLES20.GL_TEXTURE_2D, VisualizerBox.audioTexture);

        // Tell the texture uniform sampler to use this texture in //the shader by binding to texture unit 0.
        GLES20.glUniform1i(textureParam, 0);

        Matrix.multiplyMM(modelView, 0, view, 0, RenderObject.model, 0);
        Matrix.multiplyMM(modelViewProjection, 0, perspective, 0, modelView, 0);
        // Set the ModelViewProjection matrix for eye position.
        GLES20.glUniformMatrix4fv(MVPParam, 1, false, modelViewProjection, 0);

        GLES20.glUniform4fv(colorParam, 1, borderColor, 0);
        GLES20.glUniform1f(widthParam, borderWidth);

        //Set vertex attributes
        GLES20.glVertexAttribPointer(positionParam, 3, GLES20.GL_FLOAT, false, 0, vertexBuffer);
        GLES20.glVertexAttribPointer(texCoordParam, 2, GLES20.GL_FLOAT, false, 0, texCoordBuffer);

        GLES20.glDrawElements(GLES20.GL_TRIANGLES, numIndices, GLES20.GL_UNSIGNED_SHORT, indexBuffer);

        RenderBox.checkGLError("WaveformMaterial draw");
    }
```

还有一件事；让我们提供一个销毁现有材质的方法：

```kt
    public static void destroy(){
        program = -1;
    }
```

## 波形可视化

现在我们可以创建一个新的可视化对象。在`visualizations/`文件夹下，创建一个名为`WaveformVisualization`的新的 Java 类，并将其定义为`extends Visualization`：

```kt
public class WaveformVisualization extends Visualization {
    static final String TAG = "WaveformVisualization";
    public WaveformVisualization(VisualizerBox visualizerBox) {
        super(visualizerBox);
    }
    @Override
    public void setup() {
    }
    @Override
    public void preDraw() {
    }
    @Override
    public void postDraw() {
    }
}
```

声明我们将要创建的`Plane`组件的变量：

```kt
    RenderObject plane;
```

在`setup`方法中创建如下。将材质设置为新的`WaveformMaterial`，并将其位置设置为靠左：

```kt
    public void setup() {
        plane = new Plane().setMaterial(new WaveformMaterial()
                .setBuffers(Plane.vertexBuffer, Plane.texCoordBuffer, Plane.indexBuffer, Plane.numIndices));

        new Transform()
                .setLocalPosition(-5, 0, 0)
                .setLocalRotation(0, 90, 0)
                .addComponent(plane);
    }
```

现在在`MainActivity`的`onCreate`中，用这个替换以前的可视化：

```kt
        visualizerBox.activeViz = new WaveformVisualization(visualizerBox);
```

当您运行项目时，您会得到这样的可视化：

![波形可视化](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_09_02.jpg)

# FFT 可视化

对于下一个可视化，我们将引入使用 FFT 数据（而不是波形数据）。与前一个示例一样，我们将从数据动态生成纹理，并编写材质和着色器来渲染它。

## 捕获 FFT 音频数据

首先，我们需要将数据捕获添加到我们的`VisualizerBox`类中。我们将首先添加我们需要的变量：

```kt
    public static byte[] fftBytes, fftNorm;
    public static float[] fftPrep;
    public static int fftTexture = -1;
```

我们需要分配 FFT 数据数组，并且为此我们需要知道它们的大小。我们可以询问 Android `Visualizer` API 它能够给我们多少数据。现在，我们将选择最小的大小，然后分配数组如下：

```kt
    public VisualizerBox(final CardboardView cardboardView){
        . . .
        fftPrep = new float[captureSize / 2];
        fftNorm = new byte[captureSize / 2];
        ...
```

捕获 FFT 数据类似于捕获波形数据。但是在保存之前，我们将对其进行一些预处理。根据 Android `Visualizer` API 文档，([http://developer.android.com/reference/android/media/audiofx/Visualizer.html#getFft(byte[]](http://developer.android.com/reference/android/media/audiofx/Visualizer.html#getFft(byte[])) `getFfT`函数提供以下指定的数据：

+   捕获是 8 位幅度 FFT；覆盖的频率范围是 0（DC）到`getSamplingRate()`返回的采样率的一半

+   捕获返回与捕获大小的一半加一相等的频率点的实部和虚部

### 注意

请注意，只有实部返回给第一个点（DC）和最后一个点（*采样频率/2*）。

返回的字节数组中的布局如下：

+   *n*是`getCaptureSize()`返回的捕获大小

+   `Rfk`和`Ifk`分别是第*k*频率分量的实部和虚部

+   如果`Fs`是`getSamplingRate()`返回的采样频率，则第*k*频率为：*(k*Fs)/(n/2)*

同样，我们将把传入的捕获数据准备成一个在 0 到 255 之间的归一化值数组。我们的实现如下。在`OnDataCaptureListener`实例中的`onWaveFormDataCapture`方法之后立即添加`onFftDataCapture`声明：

```kt
            @Override
            public void onFftDataCapture(Visualizer visualizer, byte[] bytes, int samplingRate) {
                fftBytes = bytes;
                float max = 0;
                for(int i = 0; i < fftPrep.length; i++) {
                    if(fftBytes.length > i * 2) {
                        fftPrep[i] = (float)Math.sqrt(fftBytes[i * 2] * fftBytes[i * 2] + fftBytes[i * 2 + 1] * fftBytes[i * 2 + 1]);
                        if(fftPrep[i] > max){
                            max = fftPrep[i];
                        }
                    }
                }
                float coeff = 1 / max;
                for(int i = 0; i < fftPrep.length; i++) {
                    if(fftPrep[i] < MIN_THRESHOLD){
                        fftPrep[i] = 0;
                    }
                    fftNorm[i] = (byte)(fftPrep[i] * coeff * 255);
                }
                loadTexture(cardboardView, fftTexture, fftNorm);
            }
```

请注意，我们的算法使用`MIN_THRESHOLD`值为 1.5 来过滤掉不重要的值：

```kt
    final float MIN_THRESHOLD = 1.5f;
```

现在在`setup()`中，用生成的纹理初始化`fftTexture`，就像我们对`audioTexture`变量做的那样：

```kt
    public void setup() {
        audioTexture = genTexture();
 fftTexture = genTexture();
        if(activeViz != null)
            activeViz.setup();
    }
```

## FFT 着色器

现在我们需要编写着色器程序。

如果需要，为着色器创建一个资源目录`res/raw/`。`fft_vertex.shader`与之前创建的`waveform_vertext.shader`相同，因此可以直接复制它。

对于`fft_fragment`着色器，我们添加了一些逻辑来决定当前坐标是否正在渲染。在这种情况下，我们没有指定宽度，只是渲染所有低于该值的像素。从某种角度来看，我们的波形着色器是一条线图（实际上是一个散点图），而我们的 FFT 着色器是一个条形图。

文件：`res/raw/fft_fragment.shader`

```kt
precision mediump float;        // default medium precision
uniform sampler2D u_Texture;    // the input texture

varying vec2 v_TexCoordinate;   // interpolated texture coordinate per fragment
uniform vec4 u_Color;

void main() {
    vec4 color;
    if(v_TexCoordinate.y < texture2D(u_Texture, v_TexCoordinate).r){
        color = u_Color;
    }
    gl_FragColor = color;
}
```

## 基本 FFT 材质

`FFTMaterial`类的代码与`WaveformMaterial`类的代码非常相似。因此，为了简洁起见，只需将该文件复制到一个名为`FFTMaterial.java`的新文件中。然后，修改如下。

确保类名和构造方法名称现在读作`FFTMaterial`：

```kt
public class FFTMaterial extends Material {
    private static final String TAG = "FFTMaterial";
    ...

    public FFTMaterial(){
    ...
```

我们决定将`borderColor`数组更改为不同的色调：

```kt
    public float[] borderColor = new float[]{0.84f, 0.65f, 1f, 1f};
```

在`setupProgram`中，确保您引用了`R.raw.fft_vertex`和`R.raw.fft_fragment`着色器：

```kt
        program = createProgram( R.raw.fft_vertex, R.raw.fft_fragment);
```

然后，确保正在设置适当的特定于着色器的参数。这些着色器使用`u_Color`（但没有`u_Width`变量）：

```kt
    //Shader-specific parameters
    textureParam = GLES20.glGetUniformLocation(program, "u_Texture");
    MVPParam = GLES20.glGetUniformLocation(program, "u_MVP");
    colorParam = GLES20.glGetUniformLocation(program, "u_Color");
    RenderBox.checkGLError("FFT params");
```

现在，在`draw`方法中，我们将使用`VisualizerBox.fftTexture`值进行绘制（而不是`VisualizerBox.audioTexture`），因此将调用`GLES20.glBindTexture`更改如下：

```kt
GLES20.glBindTexture(GLES20.GL_TEXTURE_2D, VisualizerBox.fftTexture);
```

确保`colorParam`参数已设置（但与`WaveformMaterial`类不同，这里没有宽度参数）：

```kt
GLES20.glUniform4fv(colorParam, 1, borderColor, 0);
```

## FFT 可视化

现在我们可以为 FFT 数据添加可视化。在`visualizations/`文件夹中，将`WaveformVisualization.java`文件复制到一个名为`FFTVisualization.java`的新文件中。确保它定义如下：

```kt
    public class FFTVisualization extends Visualization {
```

在它的`setup`方法中，我们将创建一个`Plane`组件，并使用`FFTMaterial`类对其进行纹理处理，如下所示（还要注意修改位置和旋转值）：

```kt
    public void setup() {
        plane = new Plane().setMaterial(new FFTMaterial()
                .setBuffers(Plane.vertexBuffer, Plane.texCoordBuffer, Plane.indexBuffer, Plane.numIndices));

        new Transform()
                .setLocalPosition(5, 0, 0)
                .setLocalRotation(0, -90, 0)
                .addComponent(plane);
    }
```

现在在`MainActivity`的`onCreate`中，用这个替换以前的可视化：

```kt
visualizerBox.activeViz = new FFTVisualization(visualizerBox);
```

当你运行这个项目时，我们得到了一个像这样的可视化，旋转并定位到右边：

![FFT 可视化](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_09_03.jpg)

这个简单的例子说明了 FFT 数据将音频的空间频率分离成离散的数据值。即使不理解底层的数学（这是非常复杂的），通常只需要知道数据随着音乐的变化和流动。我们在这里使用它来驱动纹理映射。FFT 也可以像我们在第一个例子中使用波形数据一样，用来驱动场景中 3D 对象的属性，包括位置、比例和旋转，以及参数化定义的几何形状。事实上，它通常是更好的数据通道。每个条形图对应一个单独的频率范围，因此您可以指定某些对象对高频率和低频率做出响应。

# 迷幻轨迹模式

如果你渴望致幻的模拟，我们将在我们的可视化中引入一个“迷幻轨迹模式”！这个实现被添加到了`RenderBox`库本身。如果你正在使用已完成的`RenderBox`库，那么只需在你的应用程序中切换到这个模式。例如，在`MainActivity`的`setup()`中，在最后添加以下代码行：

```kt
        RenderBox.mainCamera.trailsMode = true;
```

要在你的`RenderBox`库的副本中实现它，打开 Android Studio 中的那个项目。在`Camera`类（`components/Camera.java`文件）中添加`public boolean trailsMode`：

```kt
    public boolean trailsMode;
```

然后，在`onDrawEye`中，我们不再擦除新帧的屏幕，而是在整个帧上绘制一个全屏四边形，带有 alpha 透明度，从而留下上一帧的幽灵般的淡化图像。每个后续帧都会被更多的半透明黑色覆盖，导致它们随着时间的推移而淡出。定义颜色值如下：

```kt
public static float[] customClearColor = new float[]{0,0,0,0.05f};
```

然后，修改`onDrawEye`，使其如下所示：

```kt
    public void onDrawEye(Eye eye) {
 if(trailsMode) {
 GLES20.glEnable(GLES20.GL_BLEND);
 GLES20.glBlendFunc(GLES20.GL_SRC_ALPHA, GLES20.GL_ONE_MINUS_SRC_ALPHA);
 customClear(customClearColor);
 GLES20.glEnable(GLES20.GL_DEPTH_TEST);
 GLES20.glClear(GLES20.GL_DEPTH_BUFFER_BIT);
 } else {
            GLES20.glEnable(GLES20.GL_DEPTH_TEST);
            GLES20.glClear(GLES20.GL_COLOR_BUFFER_BIT | GLES20.GL_DEPTH_BUFFER_BIT);
        }

        ...
```

`customClear`方法跳过清除调用，保留上一帧的颜色。相反，它只是绘制一个半透明的全屏黑色四边形，略微变暗每一帧的“旧”图像。在我们这样做之前，相机需要一个着色器程序来绘制全屏的纯色。

`fullscreen_solid_color_vertex.shader` 如下所示：

```kt
attribute vec4 v_Position;

void main() {
   gl_Position = v_Position;
}
```

`fullscreen_solid_color_fragment.shader` 如下所示：

```kt
precision mediump float;
uniform vec4 u_Color;

void main() {
    gl_FragColor = u_Color;
}
```

现在回到`Camera`组件。我们设置程序并定义一个全屏四边形网格，缓冲区和其他变量。首先，我们定义我们需要的变量：

```kt
    static int program = -1;
    static int positionParam, colorParam;
    static boolean setup;
    public static FloatBuffer vertexBuffer;
    public static ShortBuffer indexBuffer;
    public static final int numIndices = 6;
    public boolean trailsMode;

    public static final float[] COORDS = new float[] {
            -1.0f, 1.0f, 0.0f,
            1.0f, 1.0f, 0.0f,
            -1.0f, -1.0f, 0.0f,
            1.0f, -1.0f, 0.0f
    };
    public static final short[] INDICES = new short[] {
            0, 1, 2,
            1, 3, 2
    };
    public static float[] customClearColor = new float[]{0,0,0,0.05f};
```

然后，定义一个设置程序的方法：

```kt
    public static void setupProgram(){
        if(program > -1)    //This means program has been set up //(valid program or error)
            return;
        //Create shader program
        program = Material.createProgram(R.raw.fullscreen_solid_color_vertex, R.raw.fullscreen_solid_color_fragment);

        //Get vertex attribute parameters
        positionParam = GLES20.glGetAttribLocation(program, "v_Position");

        //Enable vertex attribute parameters
        GLES20.glEnableVertexAttribArray(positionParam);

        //Shader-specific parameters
        colorParam = GLES20.glGetUniformLocation(program, "u_Color");

        RenderBox.checkGLError("Fullscreen Solid Color params");
    }
```

定义一个分配缓冲区的方法：

```kt
    public static void allocateBuffers(){
        setup = true;
        vertexBuffer = RenderObject.allocateFloatBuffer(COORDS);
        indexBuffer = RenderObject.allocateShortBuffer(INDICES);
    }
```

然后，从`Camera`初始化器中调用这些方法：

```kt
    public Camera(){
        transform = new Transform();
 setupProgram();
 allocateBuffers();
    }
```

最后，我们可以实现`customClear`方法：

```kt
    public static void customClear(float[] clearColor){
        GLES20.glUseProgram(program);
        // Set the position buffer
        GLES20.glVertexAttribPointer(positionParam, 3, GLES20.GL_FLOAT, false, 0, vertexBuffer);
        GLES20.glUniform4fv(colorParam, 1, clearColor, 0);
        GLES20.glDrawElements(GLES20.GL_TRIANGLES, numIndices, GLES20.GL_UNSIGNED_SHORT, indexBuffer);
    }
```

重新构建`RenderBox`模块，并将库文件复制回`VisualizeVR`项目。不要忘记将`trailsMode`设置为`true`！

现在当你运行这个应用程序时，它看起来很迷幻和酷！

![迷幻轨迹模式](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_09_04.jpg)

# 多个同时的可视化

现在我们有了一系列的可视化，我们可以增强应用程序，使其能够同时运行多个可视化，并在它们之间进行切换。

为了支持多个并发的可视化，用`visualizations`列表替换`VisualizerBox`中的`activeViz`变量。

```kt
public List<Visualization> visualizations = new ArrayList<Visualization|();
```

然后，在使用它的每个`VisualizerBox`方法中循环列表。我们总是希望设置所有这些，但只绘制（`preDraw`，`postDraw`）活动的可视化：

```kt
    public void setup() {
        audioTexture = genTexture();
        fftTexture = genTexture();
        for (Visualization viz : visualizations) {
            viz.setup();
        }
    }
    public void preDraw() {
        for (Visualization viz : visualizations) {
            viz.preDraw();
        }
    }
    public void postDraw() {
        for (Visualization viz : visualizations) {
            viz.postDraw();
        }
    }
```

我们可以在`MainActivity`中控制场景。修改`MainActivity`类的`onCreate`方法来填充`visualizations`列表，如下所示：

```kt
visualizerBox = new VisualizerBox(cardboardView);
visualizerBox.visualizations.add( new GeometricVisualization(visualizerBox));
visualizerBox.visualizations.add( new WaveformVisualization(visualizerBox));
visualizerBox.visualizations.add( new FFTVisualization(visualizerBox));
```

运行项目，我们有一个充满可视化的 3D 场景！

![多个同时可视化](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/cdbd-vr-pj-andr/img/B05144_09_05.jpg)

# 随机可视化

我们可以通过随着时间的推移添加和删除可视化来在可视化之间切换。在以下示例中，我们从一个活动可视化开始，然后每隔几秒切换一个随机可视化。

首先，在抽象的`Visualization`类中添加一个`activate`方法，它接受一个布尔类型的`enabled`参数。布尔类型的`active`变量是只读的：

```kt
    public boolean active = true;
    public abstract void activate(boolean enabled);
```

其实现将取决于具体的可视化。`RenderBox`库提供了一个`enabled`标志，用于渲染对象。最容易的是那些实例化单个`Plane`组件的可视化，比如`WaveformVisualization`和`FFTVisualization`。对于这些，添加以下代码：

```kt
    @Override
    public void activate(boolean enabled) {
        active = enabled;
        plane.enabled = enabled;
    }
```

对于`GeometricVisualization`类，我们可以启用（和禁用）每个组件立方体：

```kt
    @Override
    public void activate(boolean enabled) {
        active = enabled;
        for(int i = 0; i < cubes.length; i++) {
            cubeRenderers[i].enabled = enabled;
        }
    }
```

现在我们可以在`MainActivity`类中控制这个。

从不活动的`visualizations`开始。将此初始化添加到`MainActivity`的`setup()`中：

```kt
        for (Visualization viz : visualizerBox.visualizations) {
            viz.activate(false);
        }
```

在`MainActivity`的`preDraw`中，我们将检查当前时间（使用`RenderBox`库的`Time`类），并在每 3 秒后切换一个随机可视化。首先，在类的顶部添加一些变量：

```kt
    float timeToChange = 0f;
    final float CHANGE_DELAY = 3f;
    final Random rand = new Random();
```

现在我们可以修改`preDraw`来检查时间并修改`visualizations`列表：

```kt
    public void preDraw() {
        if (Time.getTime() > timeToChange) {
            int idx = rand.nextInt( visualizerBox.visualizations.size() );
            Visualization viz = visualizerBox.visualizations.get(idx);
            viz.activate(!viz.active);
            timeToChange += CHANGE_DELAY;
        }
        visualizerBox.preDraw();
    }
```

类似的时间控制结构（或增量时间）可以用于实现许多种动画，比如改变可视化对象的位置、旋转和/或比例，或者随着时间的推移演变几何本身。

# 进一步的增强

我们希望我们给了你一些工具，让你开始制作自己的音乐可视化。正如我们在本章中所建议的，选项是无限的。不幸的是，空间限制我们在这里编写更多有趣的代码。

+   **动画**：我们对每个可视化应用了最简单的变换：简单的位置、比例，也许是 90 度的旋转。当然，位置、旋转和比例可以进行动画处理，即与音乐协调更新每一帧，或者独立于音乐使用`Time.deltaTime`。东西可以在你周围虚拟飞来飞去！

+   **高级纹理和着色器**：我们的着色器和数据驱动纹理是最基本的：基本上渲染与音频字节值对应的单色像素。音频数据可以输入到更复杂和有趣的算法中，以生成新的图案和颜色，或者用于变形预加载的纹理。

+   **纹理映射**：项目中的纹理材料只是映射到一个平面上。嘿，伙计，这是虚拟现实！将纹理映射到一个全景照片或其他几何图形上，完全沉浸你的用户。

+   **渲染到纹理**：我们的轨迹模式对于这些可视化看起来还不错，但对于任何足够复杂的东西可能会变得一团糟。相反，您可以将其专门用于纹理平面的表面。设置 RTs 是复杂的，超出了本书的范围。基本上，您向场景引入另一个摄像机，指示 OpenGL 将后续绘制调用渲染到您创建的新表面，并将该表面用作要渲染到其上的对象的纹理缓冲区。RT 是一个强大的概念，可以实现反射和游戏内安全摄像头等技术。此外，您可以对表面应用变换，使轨迹看起来飞向远处，这是传统可视化器（如 MilkDrop）中的一种受欢迎的效果。

+   **参数几何**：音频数据可以用来驱动定义和渲染各种复杂度的 3D 几何模型。想想分形、晶体和 3D 多面体。参考 Goldberg 多面体（参考[`schoengeometry.com/`](http://schoengeometry.com/)）和神圣几何（参考[`www.geometrycode.com/sacred-geometry/`](http://www.geometrycode.com/sacred-geometry/)）以获取灵感。

## 社区邀请

我们邀请您与本书的其他读者和 Cardboard 社区分享您自己的可视化效果。一种方法是通过我们的 GitHub 存储库。如果您创建了一个新的可视化效果，请将其作为拉取请求提交到项目[`github.com/cardbookvr/visualizevr`](https://github.com/cardbookvr/visualizevr)，或者创建您自己的整个项目的分支！

# 总结

在本章中，我们构建了一个作为 Cardboard VR 应用程序运行的音乐可视化器。我们设计了一个通用架构，让您可以定义多个可视化效果，将它们插入到应用程序中，并在它们之间进行过渡。该应用程序使用 Android 的`Visualization` API 从手机当前的音频播放器中捕获波形和 FFT 数据。

首先，我们定义了`VisualizerBox`类，负责与 Android 的`Visualizer` API 的活动和回调函数。然后，我们定义了一个抽象的`Visualization`类来实现各种可视化效果。然后，我们将波形音频数据捕获到`VisualizerBox`中，并使用它来参数化地动画化一系列立方体，制作成一个 3D 波浪箱。接下来，我们编写了第二个可视化器；这次使用波形数据动态生成纹理，并使用材质着色器程序进行渲染。最后，我们捕获了 FFT 音频数据，并用它进行了第三个可视化。然后，我们增加了更多有趣的内容，比如迷幻轨迹模式和多个并发的可视化效果，随机进行过渡。

我们承认，视觉示例非常简单，但希望它们能激发您的想象力。我们挑战您构建自己的 3D 虚拟现实音乐可视化，也许利用了这个项目中的技术以及本书中的其他内容。

# 前往未来

我们希望您喜欢这个介绍和通过 Cardboard 虚拟现实开发的旅程。在整本书中，我们探索了 Google Cardboard Java SDK，OpenGL ES 2.0 图形和 Android 开发。我们涉及了许多 VR 最佳实践，并看到了在移动平台上进行低级图形开发的局限性。但是，如果您跟随我们的步伐，您已经成功地实现了一个合理的通用 3D 图形和 VR 开发库。您创建了各种各样的 VR 应用程序，包括应用程序启动器、太阳系模拟、360 度媒体画廊、3D 模型查看器和音乐可视化器。

自然地，我们期待 Cardboard Java SDK 从此时开始发生变化、演变和成熟。没有人真正知道未来会发生什么，甚至包括谷歌在内。然而，我们现在站在一个崭新未来的悬崖边。预测未来的最好方法就是帮助创造它。现在轮到你了！
