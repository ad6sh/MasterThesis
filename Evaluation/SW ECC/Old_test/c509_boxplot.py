# Import libraries
import matplotlib.pyplot as plt
import numpy as np
import statistics
 
 
# Creating dataset
#np.random.seed(10)
#data = np.random.normal(100, 20, 200)
c509_pro_time = [203953, 201036, 200123, 200144, 202499, 206988, 207046, 203853, 208452, 197382, 202981, 201116, 204915, 198808, 203917, 202837, 198321, 197666, 198047, 204277, 201967, 201251, 201161, 204308, 199200, 203357, 202683, 204804, 204246, 206252, 200468, 200112, 204474, 195452, 200188, 201631, 203549, 204934, 201973, 204367, 200502, 197468, 206076, 199223, 198814, 204470, 203899, 205164, 202575, 203903, 200327, 200679, 203281, 204713, 193766, 200767, 203859, 197287, 208350, 200753, 206844, 207513, 197022, 203421, 201073, 203463, 199158, 204693, 202825, 199813, 205196, 196391, 200642, 203172, 201456, 199856, 199120, 202450, 205755, 202795, 200787, 199840, 201981, 196142, 200173, 197458, 205457, 202005, 204717, 202500, 202879, 198787, 203452, 192217, 200153, 197448, 201760, 199620, 203003, 202534, 
]

newList = [x / 1000 for x in c509_pro_time]

mean_ms = statistics.mean(newList)
print("mean ms: ",mean_ms)

median_ms = statistics.median(newList)
print("median ms: ",median_ms)

stddev = statistics.stdev(newList)
print("std dev: ",stddev)


fig = plt.figure(figsize =(10, 7))
#plt.title('C509 processig time on nrf52840 dongle')
#plt.xlabel('categories')
plt.ylabel('time [ms]')

 
# Creating plot
plt.boxplot(newList,patch_artist=False, meanline=True, showmeans=True,notch=True)
plt.xticks([1], ["C509 processig time on nrf52840 dongle"])
 
# show plot
plt.show()


