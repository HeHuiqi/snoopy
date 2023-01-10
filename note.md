https://blog.csdn.net/Kevinhanser/article/details/121374767

pip install markdown #view视图中获取到数据库的数据，修饰为html语句，传到前端
pip install Pygments #实现代码高亮
安装第二个包后还要执行
pygmentize -S default -f html -a .codehilite > markdown_highlighy.css
pygmentize -S default -f html -a .codehilite > default.css
pygmentize -S monokai  -f html -a .codehilite > monokai.css


pip install django-mdeditor
pip install mongoengine 