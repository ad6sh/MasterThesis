# Import libraries
import matplotlib.pyplot as plt
import numpy as np
import statistics
  
# Creating dataset
client_total_lookup_time =[66884, 70247, 68661, 65890, 65344, 65453, 69967, 67629, 68617, 67497, 68516, 69299, 66961, 68728, 66255, 68497, 68317, 68636, 69265, 68263, 68582, 68666, 70175, 68307, 66640, 67808, 67330, 69052, 68778, 69125, 68661, 67915, 68823, 69440, 66428, 68653, 69090, 67351, 68781, 69842, 68665, 66668, 68000, 67249, 70524, 69494, 69538, 66711, 66313, 70421, 68774, 69856, 67840, 68546, 70233, 68302, 67832, 67056, 68509, 70212, 66153, 67955, 66883, 67331, 68280, 69560, 68840, 66333, 70417, 67477, 69488, 67894, 70351, 68542, 69097, 69588, 68194, 68102, 70275, 70923, 70153, 67349, 70060, 67869, 67496, 68257, 67524, 68427, 67635, 66647, 67872, 67413, 66104, 69154, 69846, 69052, 69592, 70061, 67797, 67913]
client_prepare_rqst =[63, 64, 64, 63, 63, 64, 63, 63, 63, 64, 63, 63, 63, 63, 63, 85, 85, 63, 63, 63, 63, 64, 85, 63, 64, 63, 63, 63, 63, 63, 63, 63, 64, 63, 64, 63, 64, 64, 63, 63, 84, 85, 63, 63, 63, 63, 64, 63, 63, 63, 63, 63, 64, 63, 63, 63, 63, 63, 63, 84, 63, 64, 64, 63, 63, 63, 63, 63, 84, 64, 63, 63, 63, 63, 63, 63, 135, 84, 63, 63, 63, 63, 63, 63, 63, 64, 64, 63, 85, 64, 63, 63, 63, 63, 63, 63, 63, 63, 63, 84]
client_rtt_rd_process =[34334, 37261, 36362, 33802, 33435, 33375, 37582, 35401, 35982, 35034, 35980, 36682, 34977, 36315, 34020, 36363, 36300, 36360, 36363, 35661, 35982, 35936, 36943, 36042, 34442, 35023, 35038, 36682, 35342, 36580, 36042, 35342, 36634, 37002, 33374, 36301, 35980, 35020, 36362, 36943, 36314, 34014, 35342, 34655, 37900, 37002, 36941, 34395, 34123, 37961, 36041, 36959, 34714, 36301, 37262, 36255, 35083, 34397, 35662, 37642, 34063, 35720, 34394, 35021, 35996, 37003, 35982, 33742, 37901, 34977, 36622, 35724, 37322, 36255, 36682, 36682, 35616, 36301, 37582, 38542, 38282, 35342, 37322, 35662, 34980, 35662, 35355, 35678, 35083, 34079, 35036, 35022, 33757, 36942, 37321, 36302, 36941, 37901, 35083, 35343]
client_c509_process_total=[32479, 32914, 32226, 32016, 31838, 32005, 32313, 32157, 32564, 32390, 32464, 32545, 31912, 32341, 32163, 32040, 31923, 32204, 32831, 32529, 32529, 32657, 33138, 32193, 32125, 32714, 32220, 32299, 33364, 32473, 32547, 32501, 32116, 32367, 32982, 32280, 33037, 32259, 32347, 32827, 32258, 32561, 32586, 32523, 32552, 32420, 32524, 32245, 32118, 32389, 32661, 32826, 33054, 32173, 32899, 31975, 32677, 32587, 32776, 32477, 32018, 32163, 32416, 32238, 32213, 32485, 32787, 32519, 32423, 32427, 32794, 32098, 32957, 32216, 32344, 32834, 32434, 31708, 32621, 32310, 31799, 31935, 32667, 32135, 32443, 32523, 32097, 32677, 32458, 32495, 32765, 32319, 32275, 32140, 32454, 32678, 32580, 32088, 32642, 32477]
client_veritfy=[20808, 21243, 20556, 20346, 20167, 20335, 20643, 20486, 20893, 20720, 20794, 20875, 20242, 20671, 20493, 20370, 20253, 20534, 21160, 20860, 20858, 20987, 21468, 20523, 20455, 21043, 20550, 20628, 21694, 20803, 20877, 20831, 20446, 20696, 21311, 20610, 21367, 20588, 20677, 21157, 20588, 20890, 20916, 20852, 20882, 20750, 20854, 20574, 20448, 20718, 20991, 21155, 21383, 20503, 21229, 20305, 21007, 20917, 21105, 20807, 20348, 20492, 20746, 20568, 20542, 20815, 21116, 20849, 20753, 20757, 21124, 20428, 21287, 20545, 20673, 21164, 20764, 20038, 20951, 20639, 20129, 20265, 20996, 20465, 20774, 20852, 20426, 21007, 20788, 20825, 21094, 20649, 20605, 20470, 20783, 21008, 20909, 20418, 20972, 20807]
rd_total_process=[19882, 19881, 19943, 19941, 19942, 19882, 19882, 19942, 19881, 19942, 19881, 19942, 19882, 19942, 19882, 19942, 19881, 19943, 19942, 19882, 19882, 19881, 19882, 19943, 19942, 19882, 19942, 19943, 19882, 19882, 19944, 19881, 19942, 19943, 19883, 19882, 19881, 19882, 19942, 19882, 19942, 19881, 19882, 19882, 19881, 19943, 19882, 19943, 19943, 19943, 19942, 19942, 19942, 19881, 19881, 19882, 19943, 19943, 19883, 19942, 19883, 19942, 19942, 19881, 19942, 19943, 19882, 19882, 19881, 19882, 19882, 19944, 19942, 19882, 19942, 19943, 19883, 19882, 19882, 19882, 19942, 19882, 19942, 19882, 19882, 19881, 19942, 19942, 19942, 19942, 19942, 19883, 19944, 19881, 19942, 19882, 19882, 19883, 19943, 19882]
rd_sign=[19701, 19701, 19762, 19761, 19762, 19702, 19702, 19761, 19701, 19762, 19701, 19762, 19702, 19762, 19702, 19762, 19701, 19762, 19762, 19701, 19702, 19701, 19702, 19762, 19762, 19702, 19762, 19762, 19701, 19702, 19763, 19702, 19762, 19762, 19702, 19701, 19701, 19702, 19762, 19702, 19762, 19701, 19703, 19702, 19701, 19762, 19701, 19762, 19762, 19762, 19762, 19762, 19762, 19702, 19701, 19701, 19762, 19763, 19702, 19762, 19702, 19762, 19762, 19702, 19762, 19763, 19702, 19702, 19701, 19701, 19702, 19764, 19762, 19702, 19762, 19762, 19702, 19702, 19701, 19702, 19762, 19702, 19762, 19702, 19702, 19701, 19762, 19763, 19762, 19762, 19762, 19702, 19763, 19702, 19762, 19701, 19702, 19702, 19762, 19702]

rd_process_module = [element1 - element2 for (element1, element2) in zip(rd_total_process, rd_sign)]
client_c509_module = [element1 - element2 for (element1, element2) in zip(client_c509_process_total, client_veritfy)]
rtt = [element1 - element2 for (element1, element2) in zip(client_rtt_rd_process, rd_total_process)]

rtt_sub = [element1 - element2 for (element1, element2) in zip(client_total_lookup_time, client_prepare_rqst)]
rtt_sub = [element1 - element2 for (element1, element2) in zip(rtt_sub, rd_total_process)]
rtt_sub = [element1 - element2 for (element1, element2) in zip(rtt_sub, client_c509_process_total)]

#print("mean rtt:",statistics.mean(rtt))
#print("mean rtt_sub:",statistics.mean(rtt_sub))

client_total_lookup_time = [x / 1000 for x in client_total_lookup_time]
client_prepare_rqst = [x / 1000 for x in client_prepare_rqst]
rd_process_module = [x / 1000 for x in rd_process_module]
rd_sign = [x / 1000 for x in rd_sign]
client_c509_module = [x / 1000 for x in client_c509_module]
client_veritfy = [x / 1000 for x in client_veritfy]
rtt_sub = [x / 1000 for x in rtt_sub]

print("mean client_total_lookup_time:",statistics.mean(client_total_lookup_time))
print("mean client_prepare_rqst:",statistics.mean(client_prepare_rqst))
print("mean rd_process_module:",statistics.mean(rd_process_module))
print("mean rd_sign:",statistics.mean(rd_sign))
print("mean client_c509_module:",statistics.mean(client_c509_module))
print("mean client_veritfy:",statistics.mean(client_veritfy))
print("mean rtt_sub:",statistics.mean(rtt_sub))


# Creating plot
fig, ax = plt.subplots()
columns = [client_total_lookup_time,client_prepare_rqst ,rtt_sub,rd_process_module,rd_sign,client_c509_module,client_veritfy]
ax.boxplot(columns, patch_artist=False, meanline=True, showmeans=True,notch=True)
ax.set_ylim(ymin=0)
#ax.set_ylim(ymax=200)
plt.xticks([1, 2, 3, 4,5,6,7], ["total\nduration","prepare\nrequest","rtt","rd\nmodule","rd\nsign","client\nmodule","client\nverify"])

#plt.title('Total duration teardown with crypto-hw')
#plt.xlabel('Number of cert stored in rd')
plt.ylabel('time [ms]')

# show plot
plt.show() 