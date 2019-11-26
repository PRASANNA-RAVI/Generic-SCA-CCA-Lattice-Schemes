#include "api.h"
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>

#define LAC_ETA 1

#define LAC_128    1
#define LAC_256    0

#define NTESTS 10

int main(void)
{

  int choice_u;

  #if LAC_128 == 1

  int choice_v;
  int i;
  int choice;
  uint16_t bit_1, bit_2;
  int succ_coeff_array[2*LAC_ETA+1];
  int other_succ_coeff_array[2*LAC_ETA+1];
  int sum = 0;
  int flag = 0;

  uint8_t decrypt_success_array[2*LAC_ETA+1];

  int decompressed_v;

  int choice_2;

  // For LAC128, 192...

  int temp;
  int low=Q/4;
  int high=Q*3/4;

  for(i=0;i<2*LAC_ETA+1;i++)
    succ_coeff_array[i] = 0;

    for(choice_u = 0; choice_u<Q; choice_u++)
    {
        for(int ii=0;ii<2*LAC_ETA+1;ii++)
            other_succ_coeff_array[ii] = 0;

        for(choice_2 = -1*LAC_ETA;choice_2 <= LAC_ETA;choice_2++)
        {
            temp=(0-(choice_2*choice_u)+Q)%Q;

            //recover m from m*q/2+e, RATIO=q/2
            if(temp>=low && temp<high)
            {
                bit_2 = 1;
            }
            else
            {
                bit_2 = 0;
            }

            other_succ_coeff_array[choice_2+LAC_ETA] = bit_2;
        }

        int sum_other_coeff_array = 0;
        for(int ii = 0;ii<2*LAC_ETA+1;ii++)
        {
            sum_other_coeff_array+=other_succ_coeff_array[ii];
        }

        for(choice_v = 0; choice_v<Q; choice_v++)
        {
            sum = 0;
            for(i=0;i<2*LAC_ETA+1;i++)
            {
                sum += succ_coeff_array[i];
            }

            if(sum == 2*LAC_ETA+1)
            {
                flag = 1;
                break;
            }

            for(int ii=0;ii<2*LAC_ETA+1;ii++)
                decrypt_success_array[ii] = 0;

            for(choice = -1*LAC_ETA;choice<=LAC_ETA;choice++)
            {

                decompressed_v = ((choice_v+0x08)&0xF0);

                //compute m*q/2+e in [0,Q]
        		temp=(decompressed_v-(choice*choice_u)+Q)%Q;

        		//recover m from m*q/2+e, RATIO=q/2
        		if(temp>=low && temp<high)
        		{
        			bit_1 = 1;
        		}
                else
                {
                    bit_1 = 0;
                }

                if((bit_1 == 1 && sum_other_coeff_array == 0))
                {
                    decrypt_success_array[choice+LAC_ETA] = 1;
                }
                else
                {
                    decrypt_success_array[choice+LAC_ETA] = 0;
                }
            }

            if(sum_other_coeff_array == 0)
            {
                printf("Choice_u, Choice_v: %d, %d\n",choice_u, decompressed_v);
                for(int i=0;i<2*LAC_ETA+1;i++)
                    printf("%d, ",decrypt_success_array[i]);
                printf("\n");
            }
        }
    }

    // For LAC256...
    #elif LAC_256 == 1

    int i;
    int choice_11, choice_12, choice_21, choice_22;
    int choice_v1,choice_v2;
    uint16_t bit_1, bit_2;
    int succ_coeff_array[(2*LAC_ETA+1)*(2*LAC_ETA+1)];
    int other_succ_coeff_array[(2*LAC_ETA+1)*(2*LAC_ETA+1)];
    int sum = 0;
    int flag = 0;
    int temp1, temp2;

    int sum_other_coeff_array = 0;

    uint8_t decrypt_success_array[(2*LAC_ETA+1)*(2*LAC_ETA+1)];
    int decompressed_v1, decompressed_v2;

    for(i=0;i<(2*LAC_ETA+1)*(2*LAC_ETA+1);i++)
      succ_coeff_array[i] = 0;

        for(choice_u = 0; choice_u<Q; choice_u++)
        {
            for(int ii=0;ii<(2*LAC_ETA+1)*(2*LAC_ETA+1);ii++)
              other_succ_coeff_array[ii] = 0;

            for(choice_21 = -1*LAC_ETA;choice_21 <= LAC_ETA;choice_21++)
            {
                for(choice_22 = -1*LAC_ETA;choice_22 <= LAC_ETA;choice_22++)
                {
                    //compute m*q/2+e in [0,Q]
                    temp1=(0-(choice_21*choice_u)+Q)%Q;
                    temp2=(0-(choice_22*choice_u)+Q)%Q;

                    //shift
                    if(temp1<Q/2)
                    {
                        temp1=Q/2-temp1+Q/2;//mirror around Q/2
                    }
                    if(temp2<Q/2)
                    {
                        temp2=Q/2-temp2+Q/2;//mirror around Q/2
                    }
                    //merge erors
                    temp1+=temp2-Q;

                    //recover m from m*q/2+e1 + m*q/2+e2, RATIO=q/2
                    if(temp1<Q/2)
                    {
                        bit_2 = 1;
                    }
                    else
                    {
                        bit_2 = 0;
                    }

                    other_succ_coeff_array[(choice_21+LAC_ETA)*(2*LAC_ETA+1)+(choice_22)+LAC_ETA] = bit_2;
                }
            }

            sum_other_coeff_array = 0;
            for(int ii = 0;ii<(2*LAC_ETA+1)*(2*LAC_ETA+1);ii++)
            {
              sum_other_coeff_array+=other_succ_coeff_array[ii];
            }


            for(choice_v1 = 0; choice_v1<Q; choice_v1++)
            {
                for(choice_v2 = 0; choice_v2<Q; choice_v2++)
                {
                    sum = 0;
                    for(i=0;i<(2*LAC_ETA+1)*(2*LAC_ETA+1);i++)
                    {
                        sum += succ_coeff_array[i];
                    }

                    if(sum == (2*LAC_ETA+1)*(2*LAC_ETA+1))
                    {
                        flag = 1;
                        break;
                    }

                    for(int ii=0;ii<(2*LAC_ETA+1)*(2*LAC_ETA+1);ii++)
                        decrypt_success_array[ii] = 0;

                    for(choice_11 = -1*LAC_ETA;choice_11<=LAC_ETA;choice_11++)
                    {
                        for(choice_12 = -1*LAC_ETA;choice_12<=LAC_ETA;choice_12++)
                        {

                            decompressed_v1 = ((choice_v1+0x08)&0xF0);
                            decompressed_v2 = ((choice_v2+0x08)&0xF0);

                            //compute m*q/2+e in [0,Q]
                            temp1=(decompressed_v1-(choice_11*choice_u)+Q)%Q;
                            temp2=(decompressed_v2-(choice_12*choice_u)+Q)%Q;

                            //shift
                    		if(temp1<Q/2)
                    		{
                    			temp1=Q/2-temp1+Q/2;//mirror around Q/2
                    		}
                    		if(temp2<Q/2)
                    		{
                    			temp2=Q/2-temp2+Q/2;//mirror around Q/2
                    		}
                    		//merge erors
                    		temp1+=temp2-Q;

                    		//recover m from m*q/2+e1 + m*q/2+e2, RATIO=q/2
                    		if(temp1<Q/2)
                    		{
                    			bit_1 = 1;
                    		}
                            else
                            {
                                bit_1 = 0;
                            }

                            if((bit_1 == 1 && sum_other_coeff_array == 0))
                            {
                                decrypt_success_array[(choice_11+LAC_ETA)*(2*LAC_ETA+1)+(choice_12)+LAC_ETA] = 1;
                            }
                            else
                            {
                                decrypt_success_array[(choice_11+LAC_ETA)*(2*LAC_ETA+1)+(choice_12)+LAC_ETA] = 0;
                            }
                        }
                    }


                    if(sum_other_coeff_array == 0)
                    {
                        printf("Choice_u, Choice_v1, Choice_v2: %d, %d, %d\n",choice_u, decompressed_v1, decompressed_v2);
                        for(int i=0;i<(2*LAC_ETA+1)*(2*LAC_ETA+1);i++)
                            printf("%d, ",decrypt_success_array[i]);
                        printf("\n");
                    }
                }
            }
        }

    #endif

  return 0;
}
