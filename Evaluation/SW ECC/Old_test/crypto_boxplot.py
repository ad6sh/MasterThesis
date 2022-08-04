# Import libraries
import matplotlib.pyplot as plt
import numpy as np
import statistics
 
# Creating dataset
#np.random.seed(10)
#data = np.random.normal(100, 20, 200)
crypto_time = [180340, 183094, 184615, 184821, 185652, 186252, 186271, 186632, 186719, 186824, 187048, 187120, 187178, 187252, 187575, 187576, 187737, 187742, 187785, 188010, 188092, 188457, 188573, 188594, 188611, 188681, 188714, 188719, 189027, 189144, 189361, 189504, 189589, 189647, 189655, 190066, 190171, 190190, 190270, 190554, 190661, 190673, 190758, 190789, 190795, 190878, 190915, 191098, 191180, 191368, 191403, 191433, 191535, 191851, 191919, 192034, 192165, 192185, 192202, 192257, 192277, 192343, 192578, 192583, 192660, 192683, 192717, 192768, 192896, 192920, 193090, 193217, 193248, 193283, 193331, 193540, 193792, 193821, 193851, 194032, 194330, 194451, 194515, 194526, 194544, 194581, 194717, 194778, 194915, 194978, 195095, 195198, 195460, 195512, 195574, 195793, 195967, 196344, 196770, 197419
]
fig = plt.figure(figsize =(10, 7))

newList = [x / 1000 for x in crypto_time]

mean_ms = statistics.mean(newList)
print("mean ms: ",mean_ms)

median_ms = statistics.median(newList)
print("median ms: ",median_ms)

#plt.title('signature verification time on nrf52840 dongle')
#plt.xlabel('categories')
plt.ylabel('time [ms]')
 
# Creating plot
plt.boxplot(newList,patch_artist=False, meanline=True, showmeans=True,notch=True)
plt.xticks([1], ["signature verification time on nrf52840 dongle"])
 
# show plot
plt.show()
