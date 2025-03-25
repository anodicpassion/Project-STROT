import pickle, time, os

with open("owl", "rb") as adf:
	animation = pickle.load(adf)

while True:
	for i in range(1, 11, 1):
		os.system("clear")
		print(animation[i])
		time.sleep(0.5)
