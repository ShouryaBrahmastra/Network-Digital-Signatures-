import turtle, math
objs = []
def startTurtle():
	global myTurtle,screen,objs
	myTurtle = turtle.Turtle()
	screen = turtle.Screen()
	screen.tracer(0,0)
	myTurtle.speed(1000000)
	myTurtle.hideturtle()
	turtle.colormode(255)
	objs = []
def per_pro(x,y,z):
	return (x/z*100,y/z*100)
def goto3d(x,y,z):
	global myTurtle
	myTurtle.goto(per_pro(x,y,z)[0],per_pro(x,y,z)[1])
def frame():
	global myTurtle,screen,objs
	screen.update()
	myTurtle.clear()
	objs = []

class Obj():
	def __init__(self,args):
		self.args=args
		if self.args[-1] == 1:
			self.run()
	def run(self):
		global myTurtle,screen,shapes,obj
		objs.append(self)
		#2d
		if self.args[0] == "ellipse":
			myTurtle.pencolor(self.args[5])
			myTurtle.penup()
			t = 0
			for i in range(math.ceil(2*math.pi*10)+1):
				myTurtle.goto(self.args[1]+self.args[3]*math.sin(t),self.args[2]+self.args[4]*math.cos(t))
				myTurtle.pendown()
				t+=0.1
		elif self.args[0] == "rectangle":
			myTurtle.pencolor(self.args[5])
			myTurtle.penup()
			myTurtle.goto(self.args[1]+self.args[3]/2,self.args[2]+self.args[4]/2)
			myTurtle.pendown()
			myTurtle.goto(self.args[1]+self.args[3]/2,self.args[2]-self.args[4]/2)
			myTurtle.goto(self.args[1]-self.args[3]/2,self.args[2]-self.args[4]/2)
			myTurtle.goto(self.args[1]-self.args[3]/2,self.args[2]+self.args[4]/2)
			myTurtle.goto(self.args[1]+self.args[3]/2,self.args[2]+self.args[4]/2)
		elif self.args[0] == "polyline":
			myTurtle.pencolor(self.args[2])
			myTurtle.penup()
			myTurtle.goto(self.args[1][0][0],self.args[1][0][1])
			myTurtle.pendown()
			for i in range(len(self.args[1])-1):
				myTurtle.goto(self.args[1][i+1][0],self.args[1][i+1][1])
		#3d
		elif self.args[0] == "rect prism":
			myTurtle.penup()
			myTurtle.pencolor(self.args[7])
			goto3d(self.args[1]-self.args[4]/2,self.args[2]-self.args[5]/2,self.args[3]-self.args[6]/2)
			myTurtle.pendown()
			goto3d(self.args[1]-self.args[4]/2,self.args[2]-self.args[5]/2,self.args[3]+self.args[6]/2)
			goto3d(self.args[1]-self.args[4]/2,self.args[2]+self.args[5]/2,self.args[3]+self.args[6]/2)
			goto3d(self.args[1]-self.args[4]/2,self.args[2]+self.args[5]/2,self.args[3]-self.args[6]/2)
			goto3d(self.args[1]-self.args[4]/2,self.args[2]-self.args[5]/2,self.args[3]-self.args[6]/2)
			goto3d(self.args[1]+self.args[4]/2,self.args[2]-self.args[5]/2,self.args[3]-self.args[6]/2)
			goto3d(self.args[1]+self.args[4]/2,self.args[2]-self.args[5]/2,self.args[3]+self.args[6]/2)
			goto3d(self.args[1]-self.args[4]/2,self.args[2]-self.args[5]/2,self.args[3]+self.args[6]/2)
			goto3d(self.args[1]+self.args[4]/2,self.args[2]-self.args[5]/2,self.args[3]+self.args[6]/2)
			goto3d(self.args[1]+self.args[4]/2,self.args[2]+self.args[5]/2,self.args[3]+self.args[6]/2)
			goto3d(self.args[1]-self.args[4]/2,self.args[2]+self.args[5]/2,self.args[3]+self.args[6]/2)
			goto3d(self.args[1]+self.args[4]/2,self.args[2]+self.args[5]/2,self.args[3]+self.args[6]/2)
			goto3d(self.args[1]+self.args[4]/2,self.args[2]+self.args[5]/2,self.args[3]-self.args[6]/2)
			goto3d(self.args[1]-self.args[4]/2,self.args[2]+self.args[5]/2,self.args[3]-self.args[6]/2)
			goto3d(self.args[1]+self.args[4]/2,self.args[2]+self.args[5]/2,self.args[3]-self.args[6]/2)
			goto3d(self.args[1]+self.args[4]/2,self.args[2]-self.args[5]/2,self.args[3]-self.args[6]/2)
		elif self.args[0] == "hello":
			pass
		else:
			raise ValueError("Not a shape")