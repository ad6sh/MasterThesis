# Import libraries
import matplotlib.pyplot as plt
import numpy as np
import statistics
 
 
# Creating dataset for hw crypto
hw_c509_pro_time_us = [31781, 32353, 31682, 32121, 32347, 32621, 32326, 32405, 32053, 32613, 31949, 32797, 32278, 32382, 32961, 32706, 31916, 32589, 31728, 32318, 32575, 32513, 32611, 32543, 33115, 32570, 32249, 32582, 32309, 32302, 32663, 32239, 32258, 32869, 32283, 32747, 32419, 33207, 31502, 32769, 32261, 32156, 32571, 32534, 32116, 32718, 31960, 32064, 32448, 32582, 32405, 32017, 32412, 32809, 31736, 32321, 31890, 32482, 33053, 32630, 32344, 32346, 32350, 31610, 32163, 33017, 32592, 31840, 31747, 32770, 32546, 33365, 32570, 32345, 32536, 32075, 33192, 32909, 32761, 32707, 32618, 32267, 32021, 32564, 33064, 32637, 32543, 32279, 32707, 32158, 32861, 32178, 32770, 31886, 32396, 32720, 33181, 32309, 32124, 32611]
hw_crypto_time_us = [20111, 20684, 20013, 20452, 20678, 20951, 20657, 20736, 20384, 20944, 20280, 21128, 20609, 20713, 21292, 21037, 20247, 20920, 20059, 20649, 20906, 20844, 20942, 20874, 21445, 20900, 20580, 20913, 20640, 20633, 20994, 20570, 20588, 21200, 20614, 21078, 20750, 21539, 19833, 21100, 20593, 20486, 20903, 20865, 20447, 21049, 20292, 20396, 20780, 20913, 20737, 20348, 20744, 21141, 20067, 20653, 20221, 20813, 21384, 20961, 20675, 20678, 20681, 19942, 20495, 21348, 20924, 20172, 20079, 21101, 20877, 21697, 20901, 20675, 20867, 20407, 21523, 21240, 21093, 21039, 20948, 20598, 20353, 20895, 21395, 20969, 20875, 20610, 21038, 20490, 21193, 20510, 21102, 20217, 20728, 21051, 21513, 20641, 20456, 20943]
hw_module_time_us = [element1 - element2 for (element1, element2) in zip(hw_c509_pro_time_us, hw_crypto_time_us)]

hw_c509_pro_time_ms = [x / 1000 for x in hw_c509_pro_time_us]
hw_crypto_time_ms = [x / 1000 for x in hw_crypto_time_us]
hw_module_time_ms = [x / 1000 for x in hw_module_time_us]

#statistics for hw crypto
mean_ms = statistics.mean(hw_crypto_time_ms)
print("hw_crypto-mean: ",mean_ms)
median_ms = statistics.median(hw_crypto_time_ms)
print("hw_crypto-median: ",median_ms)
stddev = statistics.stdev(hw_crypto_time_ms)
print("hw_crypto-stddev: ",stddev)

#statistics for hw-module
mean_ms = statistics.mean(hw_module_time_ms)
print("hw_module-mean: ",mean_ms)
median_ms = statistics.median(hw_module_time_ms)
print("hw_module-median: ",median_ms)
stddev = statistics.stdev(hw_module_time_ms)
print("hw_module-stddev: ",stddev)



# Creating dataset for sw crypto
sw_c509_pro_time_us =[203030, 201191, 199818, 203771, 205019, 201073, 199774, 201262, 199818, 201768, 195406, 203152, 199046, 203132, 208151, 204412, 202937, 203575, 200655, 196517, 201055, 204835, 203859, 201191, 203475, 201353, 203921, 202369, 198963, 205415, 201643, 205036, 204867, 202950, 201145, 195841, 204458, 207255, 201555, 205119, 207456, 201997, 197847, 197816, 196530, 198965, 207221, 202592, 201771, 206118, 199383, 200813, 201370, 194734, 199734, 199887, 194687, 202017, 200124, 196746, 203991, 203997, 203386, 202764, 204845, 202194, 195875, 198633, 204247, 206679, 201331, 202228, 204331, 204550, 203738, 204937, 203637, 200102, 197190, 201040, 204876, 206712, 198451, 201140, 198035, 202604, 197472, 199793, 203208, 198380, 198664, 208082, 200764, 202579, 202094, 204805, 202992, 196082, 197237, 207898]
sw_crypto_time_us = [191371, 189531, 188159, 192111, 193360, 189414, 188115, 189602, 188159, 190108, 183747, 191493, 187387, 191472, 196492, 192753, 191278, 191916, 188995, 184857, 189396, 193176, 192199, 189531, 191816, 189694, 192262, 190709, 187303, 193756, 189984, 193377, 193208, 191291, 189485, 184181, 192799, 195596, 189896, 193459, 195796, 190337, 186188, 186156, 184871, 187306, 195562, 190932, 190112, 194459, 187723, 189153, 189710, 183074, 188075, 188227, 183027, 190357, 188464, 185087, 192332, 192338, 191727, 191105, 193185, 190535, 184216, 186974, 192587, 195019, 189672, 190568, 192672, 192891, 192078, 193278, 191977, 188443, 185531, 189381, 193216, 195053, 186791, 189480, 186376, 190945, 185813, 188133, 191549, 186720, 187004, 196423, 189105, 190920, 190435, 193146, 191333, 184422, 185578, 196239]
sw_module_time_us = [element1 - element2 for (element1, element2) in zip(sw_c509_pro_time_us, sw_crypto_time_us)]

sw_c509_pro_time_ms = [x / 1000 for x in sw_c509_pro_time_us]
sw_crypto_time_ms = [x / 1000 for x in sw_crypto_time_us]
sw_module_time_ms = [x / 1000 for x in sw_module_time_us]

#statistics for hw crypto
mean_ms = statistics.mean(sw_crypto_time_ms)
print("sw_crypto-mean: ",mean_ms)
median_ms = statistics.median(sw_crypto_time_ms)
print("sw_crypto-median: ",median_ms)
stddev = statistics.stdev(sw_crypto_time_ms)
print("sw_crypto-stddev: ",stddev)

#statistics for hw-module
mean_ms = statistics.mean(sw_module_time_ms)
print("sw_module-mean: ",mean_ms)
median_ms = statistics.median(sw_module_time_ms)
print("sw_module-median: ",median_ms)
stddev = statistics.stdev(sw_module_time_ms)
print("sw_module-stddev: ",stddev)

""" fig, ax = plt.subplots()
columns = [c509_pro_time_ms,module_time_ms,crypto_time_ms]
ax.boxplot(columns, patch_artist=False, meanline=True, showmeans=True,notch=True)
ax.set_ylim(ymin=0)
plt.xticks([1, 2,3], ["c509","module","hw-crypto"])

plt.title('CPU overhead with hardware cryptography')
plt.ylabel('time [ms]') """

fig, ax = plt.subplots()
#columns = [hw_module_time_ms,hw_crypto_time_ms,sw_module_time_ms,sw_crypto_time_ms]
columns = [sw_module_time_ms,sw_crypto_time_ms,hw_module_time_ms,hw_crypto_time_ms]

ax.boxplot(columns, patch_artist=False, meanline=True, showmeans=True,notch=True)
ax.set_ylim(ymin=0)
#plt.xticks([1, 2,3,4], ["module-hw","hw-crypto","module-sw","sw-crypto"])
plt.xticks([1, 2,3,4], ["C509-module","crypto-software","C509-module","crypto-hardware"])


#plt.title('CPU overhead')
plt.ylabel('time [ms]')

# show plot
plt.show()
