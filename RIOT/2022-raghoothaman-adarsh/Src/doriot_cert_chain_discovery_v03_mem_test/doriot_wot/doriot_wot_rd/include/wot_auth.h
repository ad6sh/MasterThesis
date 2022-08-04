/**
 * @file wot_auth.h
 * @author adarsh.raghoothaman@st.ovgu.de
 * @brief 
 * @version 0.1
 * @date 2022-02-16
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#ifndef WOT_AUTH_H
#define WOT_AUTH_H


#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief function to add certificate verification method
 * 
 * @param verify_pos 
 * @return int 
 */
int wot_add_verify_method(int verify_pos);



#ifdef __cplusplus
}
#endif

#endif /* WOT_AUTH_H */
