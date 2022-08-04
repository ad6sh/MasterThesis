# Import libraries
import matplotlib.pyplot as plt
import numpy as np
import statistics
 
 
# Creating dataset
c509_pro_time_us =[203030, 201191, 199818, 203771, 205019, 201073, 199774, 201262, 199818, 201768, 195406, 203152, 199046, 203132, 208151, 204412, 202937, 203575, 200655, 196517, 201055, 204835, 203859, 201191, 203475, 201353, 203921, 202369, 198963, 205415, 201643, 205036, 204867, 202950, 201145, 195841, 204458, 207255, 201555, 205119, 207456, 201997, 197847, 197816, 196530, 198965, 207221, 202592, 201771, 206118, 199383, 200813, 201370, 194734, 199734, 199887, 194687, 202017, 200124, 196746, 203991, 203997, 203386, 202764, 204845, 202194, 195875, 198633, 204247, 206679, 201331, 202228, 204331, 204550, 203738, 204937, 203637, 200102, 197190, 201040, 204876, 206712, 198451, 201140, 198035, 202604, 197472, 199793, 203208, 198380, 198664, 208082, 200764, 202579, 202094, 204805, 202992, 196082, 197237, 207898]
crypto_time_us = [191371, 189531, 188159, 192111, 193360, 189414, 188115, 189602, 188159, 190108, 183747, 191493, 187387, 191472, 196492, 192753, 191278, 191916, 188995, 184857, 189396, 193176, 192199, 189531, 191816, 189694, 192262, 190709, 187303, 193756, 189984, 193377, 193208, 191291, 189485, 184181, 192799, 195596, 189896, 193459, 195796, 190337, 186188, 186156, 184871, 187306, 195562, 190932, 190112, 194459, 187723, 189153, 189710, 183074, 188075, 188227, 183027, 190357, 188464, 185087, 192332, 192338, 191727, 191105, 193185, 190535, 184216, 186974, 192587, 195019, 189672, 190568, 192672, 192891, 192078, 193278, 191977, 188443, 185531, 189381, 193216, 195053, 186791, 189480, 186376, 190945, 185813, 188133, 191549, 186720, 187004, 196423, 189105, 190920, 190435, 193146, 191333, 184422, 185578, 196239]
module_time_us = [element1 - element2 for (element1, element2) in zip(c509_pro_time_us, crypto_time_us)]

c509_pro_time_ms = [x / 1000 for x in c509_pro_time_us]
crypto_time_ms = [x / 1000 for x in crypto_time_us]
module_time_ms = [x / 1000 for x in module_time_us]

print("mean crypto_time_ms:",statistics.mean(crypto_time_ms))
print("mean module_time_ms:",statistics.mean(module_time_ms))

""" fig, ax = plt.subplots()
columns = [c509_pro_time_ms,module_time_ms,crypto_time_ms]
ax.boxplot(columns, patch_artist=False, meanline=True, showmeans=True,notch=True)
ax.set_ylim(ymin=0)
plt.xticks([1, 2,3], ["c509","module","uEcc"])

plt.title('CPU overhead with hardware cryptography')
plt.ylabel('time [ms]') """

fig, ax = plt.subplots()
columns = [module_time_ms,crypto_time_ms]
ax.boxplot(columns, patch_artist=False, meanline=True, showmeans=True,notch=True)
ax.set_ylim(ymin=0)
ax.set_ylim(ymax=200)
plt.xticks([1, 2], ["c509-module","sw-crypto"])

#plt.title('CPU overhead with crypto-software')
plt.ylabel('time [ms]')

# show plot
plt.show()
