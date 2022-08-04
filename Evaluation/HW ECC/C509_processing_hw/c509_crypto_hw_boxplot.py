# Import libraries
import matplotlib.pyplot as plt
import numpy as np
import statistics
 
 
# Creating dataset
c509_pro_time_us = [31781, 32353, 31682, 32121, 32347, 32621, 32326, 32405, 32053, 32613, 31949, 32797, 32278, 32382, 32961, 32706, 31916, 32589, 31728, 32318, 32575, 32513, 32611, 32543, 33115, 32570, 32249, 32582, 32309, 32302, 32663, 32239, 32258, 32869, 32283, 32747, 32419, 33207, 31502, 32769, 32261, 32156, 32571, 32534, 32116, 32718, 31960, 32064, 32448, 32582, 32405, 32017, 32412, 32809, 31736, 32321, 31890, 32482, 33053, 32630, 32344, 32346, 32350, 31610, 32163, 33017, 32592, 31840, 31747, 32770, 32546, 33365, 32570, 32345, 32536, 32075, 33192, 32909, 32761, 32707, 32618, 32267, 32021, 32564, 33064, 32637, 32543, 32279, 32707, 32158, 32861, 32178, 32770, 31886, 32396, 32720, 33181, 32309, 32124, 32611]
crypto_time_us = [20111, 20684, 20013, 20452, 20678, 20951, 20657, 20736, 20384, 20944, 20280, 21128, 20609, 20713, 21292, 21037, 20247, 20920, 20059, 20649, 20906, 20844, 20942, 20874, 21445, 20900, 20580, 20913, 20640, 20633, 20994, 20570, 20588, 21200, 20614, 21078, 20750, 21539, 19833, 21100, 20593, 20486, 20903, 20865, 20447, 21049, 20292, 20396, 20780, 20913, 20737, 20348, 20744, 21141, 20067, 20653, 20221, 20813, 21384, 20961, 20675, 20678, 20681, 19942, 20495, 21348, 20924, 20172, 20079, 21101, 20877, 21697, 20901, 20675, 20867, 20407, 21523, 21240, 21093, 21039, 20948, 20598, 20353, 20895, 21395, 20969, 20875, 20610, 21038, 20490, 21193, 20510, 21102, 20217, 20728, 21051, 21513, 20641, 20456, 20943]
module_time_us = [element1 - element2 for (element1, element2) in zip(c509_pro_time_us, crypto_time_us)]

c509_pro_time_ms = [x / 1000 for x in c509_pro_time_us]
crypto_time_ms = [x / 1000 for x in crypto_time_us]
module_time_ms = [x / 1000 for x in module_time_us]

""" fig, ax = plt.subplots()
columns = [c509_pro_time_ms,module_time_ms,crypto_time_ms]
ax.boxplot(columns, patch_artist=False, meanline=True, showmeans=True,notch=True)
ax.set_ylim(ymin=0)
plt.xticks([1, 2,3], ["c509","module","hw-crypto"])

plt.title('CPU overhead with hardware cryptography')
plt.ylabel('time [ms]') """

fig, ax = plt.subplots()
columns = [module_time_ms,crypto_time_ms]
ax.boxplot(columns, patch_artist=False, meanline=True, showmeans=True,notch=True)
ax.set_ylim(ymin=0)
ax.set_ylim(ymax=200)
plt.xticks([1, 2], ["c509-module","hw-crypto"])

#plt.title('CPU overhead with crypto-hardware acceleration')
plt.ylabel('time [ms]')

# show plot
plt.show()
