/* asn1-der.c - Manage DER encoding
 *      Copyright (C) 2000,2001  Fabio Fiorina
 *      Copyright (C) 2001 Free Software Foundation, Inc.
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdlib.h>
#include <string.h>

#include "asn1-der.h"
#include "util.h"
#include "reader.h"

#define TAG_BOOLEAN          0x01
#define TAG_INTEGER          0x02
#define TAG_SEQUENCE         0x10
#define TAG_SET              0x11
#define TAG_OCTET_STRING     0x04
#define TAG_BIT_STRING       0x03
#define TAG_UTCTime          0x17
#define TAG_GENERALIZEDTime  0x18
#define TAG_OBJECT_ID        0x06
#define TAG_ENUMERATED       0x0A
#define TAG_NULL             0x05

#define UNIVERSAL  (CLASS_UNIVERSAL << 6)
#define STRUCTURED 0x20

static AsnNode 
find_up (AsnNode  node)
{
  AsnNode p;

  if (node == NULL)
    return NULL;

  p = node;

  while ((p->left != NULL) && (p->left->right == p))
    p = p->left;

  return p->left;
}


char *
_asn1_ltostr (long v, char *str)
{
  long d, r, v2;
  char temp[20];
  int count, k, start;

  if (v < 0)
    {
      str[0] = '-';
      start = 1;
      v = -v;
    }
  else
    start = 0;

  count = 0;
  do
    {
      d = v / 10;
      r = v - d * 10;
      temp[start + count] = '0' + (char) r;
      count++;
      v = d;
    }
  while (v);

  for (k = 0; k < count; k++)
    str[k + start] = temp[start + count - k - 1];
  str[count + start] = 0;
  return str;
}


void
_asn1_length_der (unsigned long len, unsigned char *ans, int *ans_len)
{
  int k;
  unsigned char temp[128];

  if (len < 128)
    {
      /* short form */
      if (ans != NULL)
	ans[0] = (unsigned char) len;
      *ans_len = 1;
    }
  else
    {
      /* Long form */
      k = 0;
      while (len)
	{
	  temp[k++] = len & 0xFF;
	  len = len >> 8;
	}
      *ans_len = k + 1;
      if (ans != NULL)
	{
	  ans[0] = ((unsigned char) k & 0x7F) + 128;
	  while (k--)
	    ans[*ans_len - 1 - k] = temp[k];
	}
    }
}


unsigned long
_ksba_asn_get_length_der (unsigned char *der, int *len)
{
  unsigned long ans;
  int k, punt;

  if (!(der[0] & 128))
    {
      /* short form */
      *len = 1;
      return der[0];
    }
  else
    {
      /* Long form */
      k = der[0] & 0x7F;
      punt = 1;
      ans = 0;
      while (punt <= k)
	ans = ans * 256 + der[punt++];

      *len = punt;
      return ans;
    }
}


void
_asn1_tag_der (unsigned char class, unsigned int tag_value,
	       unsigned char *ans, int *ans_len)
{
  int k;
  unsigned char temp[128];

  if (tag_value < 30)
    {
      /* short form */
      ans[0] = (class & 0xE0) + ((unsigned char) (tag_value & 0x1F));
      *ans_len = 1;
    }
  else
    {
      /* Long form */
      ans[0] = (class & 0xE0) + 31;
      k = 0;
      while (tag_value)
	{
	  temp[k++] = tag_value & 0x7F;
	  tag_value = tag_value >> 7;
	}
      *ans_len = k + 1;
      while (k--)
	ans[*ans_len - 1 - k] = temp[k] + 128;
      ans[*ans_len - 1] -= 128;
    }
}


unsigned int
_asn1_get_tag_der (unsigned char *der, unsigned char *class, int *len)
{
  unsigned long ans;
  int punt, ris;

  /* tag format:  CCFTTTTT
   *      C = class: 00 = universal
   *                 01 = application
   *                 10 = context specific
   *                 11 = private
   *      F = form: 0 = primitive
   *                1 = constructed
   *      T = tag value
   * For tags 0..30 the length is one byte
   * For tags >= 31 the last octect is is marked by a cleared bit 7.
   */
  *class = der[0] & 0xE0;  /* class includes the form */
  if ((der[0] & 0x1F) != 0x1F)
    {
      /* short form */
      *len = 1;
      ris = der[0] & 0x1F;
    }
  else
    {
      /* Long form */
      punt = 1;
      ris = 0;
      while (der[punt] & 128)
	ris = ris * 128 + (der[punt++] & 0x7F);
      ris = ris * 128 + (der[punt++] & 0x7F);
      *len = punt;
    }
  return ris;
}


void
_asn1_octet_der (unsigned char *str, int str_len, unsigned char *der,
		 int *der_len)
{
  int len_len;

  if (der == NULL)
    return;
  _asn1_length_der (str_len, der, &len_len);
  memcpy (der + len_len, str, str_len);
  *der_len = str_len + len_len;
}


int
_asn1_get_octet_der (unsigned char *der, int *der_len, unsigned char *str,
		     int str_size, int *str_len)
{
  int len_len;

  if (str == NULL)
    return ASN_OK;
  *str_len = _ksba_asn_get_length_der (der, &len_len);
  if (str_size > *str_len)
    memcpy (str, der + len_len, *str_len);
  else
    return ASN_MEM_ERROR;
  *der_len = *str_len + len_len;

  return ASN_OK;
}


void
_asn1_time_der (unsigned char *str, unsigned char *der, int *der_len)
{
  int len_len;

  if (der == NULL)
    return;
  _asn1_length_der (strlen (str), der, &len_len);
  memcpy (der + len_len, str, strlen (str));
  *der_len = len_len + strlen (str);
}


/*
void
_asn1_get_utctime_der(unsigned char *der,int *der_len,unsigned char *str)
{
  int len_len,str_len;
  char temp[20];

  if(str==NULL) return;
  str_len=_ksba_asn_get_length_der(der,&len_len);
  memcpy(temp,der+len_len,str_len);
  *der_len=str_len+len_len;
  switch(str_len){
  case 11:
    temp[10]=0;
    strcat(temp,"00+0000");
    break;
  case 13:
    temp[12]=0;
    strcat(temp,"+0000");
    break;
  case 15:
    temp[15]=0;
    memmove(temp+12,temp+10,6);
    temp[10]=temp[11]='0';
    break;
  case 17:
    temp[17]=0;
    break;
  default:
    return;
  }
  strcpy(str,temp);
}
*/


void
_asn1_get_time_der (unsigned char *der, int *der_len, unsigned char *str)
{
  int len_len, str_len;

  if (str == NULL)
    return;
  str_len = _ksba_asn_get_length_der (der, &len_len);
  memcpy (str, der + len_len, str_len);
  str[str_len] = 0;
  *der_len = str_len + len_len;
}

void
_asn1_objectid_der (unsigned char *str, unsigned char *der, int *der_len)
{
  int len_len, counter, k, first;
  char temp[128], *n_end, *n_start;
  unsigned char bit7;
  unsigned long val, val1;

  if (der == NULL)
    return;

  strcpy (temp, str);
  strcat (temp, " ");

  counter = 0;
  n_start = temp;
  while ((n_end = strchr (n_start, ' ')))
    {
      *n_end = 0;
      val = strtoul (n_start, NULL, 10);
      counter++;

      if (counter == 1)
	val1 = val;
      else if (counter == 2)
	{
	  der[0] = 40 * val1 + val;
	  *der_len = 1;
	}
      else
	{
	  first = 0;
	  for (k = 4; k >= 0; k--)
	    {
	      bit7 = (val >> (k * 7)) & 0x7F;
	      if (bit7 || first || !k)
		{
		  if (k)
		    bit7 |= 0x80;
		  der[*der_len] = bit7;
		  (*der_len)++;
		  first = 1;
		}
	    }

	}
      n_start = n_end + 1;
    }

  _asn1_length_der (*der_len, NULL, &len_len);
  memmove (der + len_len, der, *der_len);
  _asn1_length_der (*der_len, der, &len_len);
  *der_len += len_len;
}


void
_asn1_get_objectid_der (unsigned char *der, int *der_len, unsigned char *str)
{
  int len_len, len, k;
  char temp[20];
  unsigned long val, val1;

  if (str == NULL)
    return;
  len = _ksba_asn_get_length_der (der, &len_len);

  val1 = der[len_len] / 40;
  val = der[len_len] - val1 * 40;

  strcpy (str, _asn1_ltostr (val1, temp));
  strcat (str, " ");
  strcat (str, _asn1_ltostr (val, temp));

  val = 0;
  for (k = 1; k < len; k++)
    {
      val = val << 7;
      val |= der[len_len + k] & 0x7F;
      if (!(der[len_len + k] & 0x80))
	{
	  strcat (str, " ");
	  strcat (str, _asn1_ltostr (val, temp));
	  val = 0;
	}
    }
  *der_len = len + len_len;
}



char bit_mask[] = { 0xFF, 0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0x80 };

void
_asn1_bit_der (unsigned char *str, int bit_len, unsigned char *der,
	       int *der_len)
{
  int len_len, len_byte, len_pad;

  if (der == NULL)
    return;
  len_byte = bit_len >> 3;
  len_pad = 8 - (bit_len & 7);
  if (len_pad == 8)
    len_pad = 0;
  else
    len_byte++;
  _asn1_length_der (len_byte + 1, der, &len_len);
  der[len_len] = len_pad;
  memcpy (der + len_len + 1, str, len_byte);
  der[len_len + len_byte] &= bit_mask[len_pad];
  *der_len = len_byte + len_len + 1;
}


int
_asn1_get_bit_der (unsigned char *der, int *der_len, unsigned char *str,
		   int str_size, int *bit_len)
{
  int len_len, len_byte;

  if (str == NULL)
    return ASN_OK;
  len_byte = _ksba_asn_get_length_der (der, &len_len) - 1;

  if (str_size > len_byte)
    memcpy (str, der + len_len + 1, len_byte);
  else
    return ASN_MEM_ERROR;

  *bit_len = len_byte * 8 - der[len_len];
  *der_len = len_byte + len_len + 1;

  return ASN_OK;
}




#define UP    1
#define DOWN  2
#define RIGHT 3


void
_asn1_complete_explicit_tag (AsnNode  node, unsigned char *der,
			     int *counter)
{
  AsnNode p;
  int tag_len, is_tag_implicit, len2, len3;
  unsigned char class, class_implicit, temp[10];
  unsigned long tag_implicit;

  is_tag_implicit = 0;

  if (node->flags.has_tag)
    {
      p = node->down;
      while (p)
	{
	  if (p->type == TYPE_TAG)
	    {
	      if (p->flags.explicit)
		{
		  len2 = strtol (p->name, NULL, 10);
		  _ksba_asn_set_name (p, NULL);
		  _asn1_length_der (*counter - len2, temp, &len3);
		  memmove (der + len2 + len3, der + len2, *counter - len2);
		  memcpy (der + len2, temp, len3);
		  *counter += len3;
		  is_tag_implicit = 0;
		}
	      else
		{	
		  if (!is_tag_implicit)
		    {
		      is_tag_implicit = 1;
		    }
		}
	    }
	  p = p->right;
	}
    }
}


int
_asn1_insert_tag_der (AsnNode  node, unsigned char *der, int *counter)
{
  AsnNode p;
  int tag_len, is_tag_implicit, len2, len3;
  unsigned char class, class_implicit, temp[10];
  unsigned long tag_implicit;


  is_tag_implicit = 0;

  if (node->flags.has_tag)
    {
      p = node->down;
      while (p)
        {
	  if (p->type == TYPE_TAG)
            {
              class = p->flags.class << 6;
	      if (p->flags.explicit)
		{
		  if (is_tag_implicit)
		    _asn1_tag_der (class_implicit, tag_implicit,
				   der + *counter, &tag_len);
		  else
		    _asn1_tag_der (class | STRUCTURED,
				   strtoul (p->value, NULL, 10),
				   der + *counter, &tag_len);
		  *counter += tag_len;
		  _asn1_ltostr (*counter, temp);
		  _ksba_asn_set_name (p, temp);

		  is_tag_implicit = 0;
		}
	      else
		{	
		  if (!is_tag_implicit)
		    {
		      if (node->type == TYPE_SEQUENCE 
                          || node->type == TYPE_SEQUENCE_OF
                          || node->type == TYPE_SET
                          || node->type == TYPE_SET_OF)
			class |= STRUCTURED;

		      class_implicit = class;
		      tag_implicit = strtoul (p->value, NULL, 10);
		      is_tag_implicit = 1;
		    }
		}
	    }
	  p = p->right;
	}
    }

  if (is_tag_implicit)
    {
      _asn1_tag_der (class_implicit, tag_implicit, der + *counter, &tag_len);
    }
  else
    {
      switch (node->type)
	{
	case TYPE_NULL:
	  _asn1_tag_der (UNIVERSAL, TAG_NULL, der + *counter, &tag_len);
	  break;
	case TYPE_BOOLEAN:
	  _asn1_tag_der (UNIVERSAL, TAG_BOOLEAN, der + *counter, &tag_len);
	  break;
	case TYPE_INTEGER:
	  _asn1_tag_der (UNIVERSAL, TAG_INTEGER, der + *counter, &tag_len);
	  break;
	case TYPE_ENUMERATED:
	  _asn1_tag_der (UNIVERSAL, TAG_ENUMERATED, der + *counter, &tag_len);
	  break;
	case TYPE_OBJECT_ID:
	  _asn1_tag_der (UNIVERSAL, TAG_OBJECT_ID, der + *counter, &tag_len);
	  break;
	case TYPE_TIME:
	  if (node->flags.is_utc_time)
	    {
	      _asn1_tag_der (UNIVERSAL, TAG_UTCTime, der + *counter,
			     &tag_len);
	    }
	  else
	    _asn1_tag_der (UNIVERSAL, TAG_GENERALIZEDTime, der + *counter,
			   &tag_len);
	  break;
	case TYPE_OCTET_STRING:
	  _asn1_tag_der (UNIVERSAL, TAG_OCTET_STRING, der + *counter,
			 &tag_len);
	  break;
	case TYPE_BIT_STRING:
	  _asn1_tag_der (UNIVERSAL, TAG_BIT_STRING, der + *counter, &tag_len);
	  break;
	case TYPE_SEQUENCE:
	case TYPE_SEQUENCE_OF:
	  _asn1_tag_der (UNIVERSAL | STRUCTURED, TAG_SEQUENCE, der + *counter,
			 &tag_len);
	  break;
	case TYPE_SET:
	case TYPE_SET_OF:
	  _asn1_tag_der (UNIVERSAL | STRUCTURED, TAG_SET, der + *counter,
			 &tag_len);
	  break;
	case TYPE_TAG:
	  tag_len = 0;
	  break;
	case TYPE_CHOICE:
	  tag_len = 0;
	  break;
	case TYPE_ANY:
	  tag_len = 0;
	  break;
	default:
	  return ASN_GENERIC_ERROR;
	}
    }

  *counter += tag_len;

  return ASN_OK;
}


int
_asn1_extract_tag_der (AsnNode  node, unsigned char *der, int *der_len)
{
  AsnNode p;
  int counter, len2, len3, is_tag_implicit;
  unsigned long tag, tag_implicit;
  unsigned char class, class2, class_implicit;

  counter = is_tag_implicit = 0;
  if (node->flags.has_tag)
    {
      p = node->down;
      while (p)
	{
	  if (p->type == TYPE_TAG)
	    {
	      class2 = p->flags.class << 6;

	      if (p->flags.explicit)
		{
		  tag = _asn1_get_tag_der (der + counter, &class, &len2);
		  counter += len2;
		  len3 = _ksba_asn_get_length_der (der + counter, &len2);
		  counter += len2;
		  if (!is_tag_implicit)
		    {
		      if ((class != (class2 | STRUCTURED))
			  || (tag != strtoul (p->value, NULL, 10)))
			return ASN_TAG_ERROR;
		    }
		  else
		    {		/* TAG_IMPLICIT */
		      if ((class != class_implicit) || (tag != tag_implicit))
			return ASN_TAG_ERROR;
		    }

		  is_tag_implicit = 0;
		}
	      else
		{		/* TAG_IMPLICIT */
		  if (!is_tag_implicit)
		    {
		      if (node->type == TYPE_SEQUENCE
                          || node->type == TYPE_SEQUENCE_OF
                          || node->type == TYPE_SET
                          || node->type == TYPE_SET_OF)
			class2 |= STRUCTURED;

		      class_implicit = class2;
		      tag_implicit = strtoul (p->value, NULL, 10);
		      is_tag_implicit = 1;
		    }
		}
	    }
	  p = p->right;
	}
    }

  if (is_tag_implicit)
    {
      tag = _asn1_get_tag_der (der + counter, &class, &len2);
      if ((class != class_implicit) || (tag != tag_implicit))
	return ASN_TAG_ERROR;
    }
  else
    {
      if (node->type == TYPE_TAG)
	{
	  counter = 0;
	  *der_len = counter;
	  return ASN_OK;
	}

      tag = _asn1_get_tag_der (der + counter, &class, &len2);
      switch (node->type)
	{
	case TYPE_NULL:
	  if ((class != UNIVERSAL) || (tag != TAG_NULL))
	    return ASN_DER_ERROR;
	  break;
	case TYPE_BOOLEAN:
	  if ((class != UNIVERSAL) || (tag != TAG_BOOLEAN))
	    return ASN_DER_ERROR;
	  break;
	case TYPE_INTEGER:
	  if ((class != UNIVERSAL) || (tag != TAG_INTEGER))
	    return ASN_DER_ERROR;
	  break;
	case TYPE_ENUMERATED:
	  if ((class != UNIVERSAL) || (tag != TAG_ENUMERATED))
	    return ASN_DER_ERROR;
	  break;
	case TYPE_OBJECT_ID:
	  if ((class != UNIVERSAL) || (tag != TAG_OBJECT_ID))
	    return ASN_DER_ERROR;
	  break;
	case TYPE_TIME:
	  if (node->flags.is_utc_time)
	    {
	      if ((class != UNIVERSAL) || (tag != TAG_UTCTime))
		return ASN_DER_ERROR;
	    }
	  else
	    {
	      if ((class != UNIVERSAL) || (tag != TAG_GENERALIZEDTime))
		return ASN_DER_ERROR;
	    }
	  break;
	case TYPE_OCTET_STRING:
	  if ((class != UNIVERSAL) || (tag != TAG_OCTET_STRING))
	    return ASN_DER_ERROR;
	  break;
	case TYPE_BIT_STRING:
	  if ((class != UNIVERSAL) || (tag != TAG_BIT_STRING))
	    return ASN_DER_ERROR;
	  break;
	case TYPE_SEQUENCE:
	case TYPE_SEQUENCE_OF:
	  if ((class != (UNIVERSAL | STRUCTURED)) || (tag != TAG_SEQUENCE))
	    return ASN_DER_ERROR;
	  break;
	case TYPE_SET:
	case TYPE_SET_OF:
	  if ((class != (UNIVERSAL | STRUCTURED)) || (tag != TAG_SET))
	    return ASN_DER_ERROR;
	  break;
	case TYPE_ANY:
	  counter -= len2;
	  break;
	default:
	  return ASN_DER_ERROR;
	  break;
	}
    }

  counter += len2;
  *der_len = counter;
  return ASN_OK;
}


void
_asn1_ordering_set (unsigned char *der, AsnNode  node)
{
  struct vet
  {
    int end;
    unsigned long value;
    struct vet *next, *prev;
  };

  int counter, len, len2;
  struct vet *first, *last, *p_vet, *p2_vet;
  AsnNode p;
  unsigned char class, *temp;
  unsigned long tag;

  counter = 0;

  if (node->type != TYPE_SET)
    return;

  p = node->down;
  while (p->type == TYPE_TAG || p->type == TYPE_SIZE)
    p = p->right;

  if (!p || !p->right )
    return;

  first = last = NULL;
  while (p)
    {
      p_vet = xmalloc (sizeof (struct vet));
      p_vet->next = NULL;
      p_vet->prev = last;
      if (first == NULL)
	first = p_vet;
      else
	last->next = p_vet;
      last = p_vet;

      /* tag value calculation */
      tag = _asn1_get_tag_der (der + counter, &class, &len2);
      p_vet->value = (class << 24) | tag;
      counter += len2;

      /* extraction  and length */
      len2 = _ksba_asn_get_length_der (der + counter, &len);
      counter += len + len2;

      p_vet->end = counter;
      p = p->right;
    }

  p_vet = first;

  while (p_vet)
    {
      p2_vet = p_vet->next;
      counter = 0;
      while (p2_vet)
	{
	  if (p_vet->value > p2_vet->value)
	    {
	      /* change position */
	      temp = xmalloc (p_vet->end - counter);
	      memcpy (temp, der + counter, p_vet->end - counter);
	      memmove (der + counter, der + p_vet->end,
		       p2_vet->end - p_vet->end);
	      memcpy (der + p_vet->end, temp, p_vet->end - counter);
	      xfree (temp);

	      tag = p_vet->value;
	      p_vet->value = p2_vet->value;
	      p2_vet->value = tag;

	      p_vet->end = counter + (p2_vet->end - p_vet->end);
	    }
	  counter = p_vet->end;

	  p2_vet = p2_vet->next;
	  p_vet = p_vet->next;
	}

      if (p_vet != first)
	p_vet->prev->next = NULL;
      else
	first = NULL;
      xfree (p_vet);
      p_vet = first;
    }
}


void
_asn1_ordering_set_of (unsigned char *der, AsnNode  node)
{
  struct vet
  {
    int end;
    struct vet *next, *prev;
  };

  int counter, len, len2, change;
  struct vet *first, *last, *p_vet, *p2_vet;
  AsnNode p;
  unsigned char *temp, class;
  unsigned long k, max;

  counter = 0;

  if (node->type != TYPE_SET_OF)
    return;

  p = node->down;
  while (p->type == TYPE_TAG || p->type == TYPE_SIZE)
    p = p->right;
  p = p->right;

  if ((p == NULL) || (p->right == NULL))
    return;

  first = last = NULL;
  while (p)
    {
      p_vet = xmalloc (sizeof (struct vet));
      p_vet->next = NULL;
      p_vet->prev = last;
      if (first == NULL)
	first = p_vet;
      else
	last->next = p_vet;
      last = p_vet;

      /* extraction of tag and length */
      _asn1_get_tag_der (der + counter, &class, &len);
      counter += len;
      len2 = _ksba_asn_get_length_der (der + counter, &len);
      counter += len + len2;

      p_vet->end = counter;
      p = p->right;
    }

  p_vet = first;

  while (p_vet)
    {
      p2_vet = p_vet->next;
      counter = 0;
      while (p2_vet)
	{
	  if ((p_vet->end - counter) > (p2_vet->end - p_vet->end))
	    max = p_vet->end - counter;
	  else
	    max = p2_vet->end - p_vet->end;

	  change = -1;
	  for (k = 0; k < max; k++)
	    if (der[counter + k] > der[p_vet->end + k])
	      {
		change = 1;
		break;
	      }
	    else if (der[counter + k] < der[p_vet->end + k])
	      {
		change = 0;
		break;
	      }

	  if ((change == -1)
	      && ((p_vet->end - counter) > (p2_vet->end - p_vet->end)))
	    change = 1;

	  if (change == 1)
	    {
	      /* change position */
	      temp = xmalloc (p_vet->end - counter);
	      memcpy (temp, der + counter, p_vet->end - counter);
	      memmove (der + counter, der + p_vet->end,
		       p2_vet->end - p_vet->end);
	      memcpy (der + p_vet->end, temp, p_vet->end - counter);
	      xfree (temp);

	      p_vet->end = counter + (p2_vet->end - p_vet->end);
	    }
	  counter = p_vet->end;

	  p2_vet = p2_vet->next;
	  p_vet = p_vet->next;
	}

      if (p_vet != first)
	p_vet->prev->next = NULL;
      else
	first = NULL;
      xfree (p_vet);
      p_vet = first;
    }
}


int
asn1_create_der (AsnNode  root, char *name, unsigned char *der, int *len)
{
  AsnNode node, p, p2, p3;
  char temp[20];
  int counter, counter_old, len2, len3, len4, move, ris;

  node = _ksba_asn_find_node (root, name);
  if (node == NULL)
    return ASN_ELEMENT_NOT_FOUND;

  counter = 0;
  move = DOWN;
  p = node;
  while (1)
    {

      counter_old = counter;
      if (move != UP)
	ris = _asn1_insert_tag_der (p, der, &counter);

      switch (p->type)
	{
	case TYPE_NULL:
	  der[counter] = 0;
	  counter++;
	  move = RIGHT;
	  break;
	case TYPE_BOOLEAN:
	  if (p->flags.is_default && !p->value)
	    counter = counter_old;
	  else
	    {
	      der[counter++] = 1;
	      if (p->value[0] == 'F')
		der[counter++] = 0;
	      else
		der[counter++] = 0xFF;
	    }
	  move = RIGHT;
	  break;
	case TYPE_INTEGER:
	case TYPE_ENUMERATED:
	  if (p->flags.is_default && !p->value)
	    counter = counter_old;
	  else
	    {
	      len2 = _ksba_asn_get_length_der (p->value, &len3);
	      memcpy (der + counter, p->value, len3 + len2);
	      counter += len3 + len2;
	    }
	  move = RIGHT;
	  break;
	case TYPE_OBJECT_ID:
	  _asn1_objectid_der (p->value, der + counter, &len2);
	  counter += len2;
	  move = RIGHT;
	  break;
	case TYPE_TIME:
	  _asn1_time_der (p->value, der + counter, &len2);
	  counter += len2;
	  move = RIGHT;
	  break;
	case TYPE_OCTET_STRING:
	  len2 = _ksba_asn_get_length_der (p->value, &len3);
	  memcpy (der + counter, p->value, len3 + len2);
	  counter += len3 + len2;
	  move = RIGHT;
	  break;
	case TYPE_BIT_STRING:
	  len2 = _ksba_asn_get_length_der (p->value, &len3);
	  memcpy (der + counter, p->value, len3 + len2);
	  counter += len3 + len2;
	  move = RIGHT;
	  break;
	case TYPE_SEQUENCE:
	case TYPE_SET:
	  if (move != UP)
	    {
	      _asn1_ltostr (counter, temp);
	      _ksba_asn_set_value (p, temp, strlen (temp) + 1);
	      move = DOWN;
	    }
	  else
	    {			/* move==UP */
	      len2 = strtol (p->value, NULL, 10);
	      _ksba_asn_set_value (p, NULL, 0);
	      if (p->type == TYPE_SET)
		_asn1_ordering_set (der + len2, p);
	      _asn1_length_der (counter - len2, temp, &len3);
	      memmove (der + len2 + len3, der + len2, counter - len2);
	      memcpy (der + len2, temp, len3);
	      counter += len3;
	      move = RIGHT;
	    }
	  break;
	case TYPE_SEQUENCE_OF:
	case TYPE_SET_OF:
	  if (move != UP)
	    {
	      _asn1_ltostr (counter, temp);
	      _ksba_asn_set_value (p, temp, strlen (temp) + 1);
	      p = p->down;
	      while (p->type == TYPE_TAG || p->type == TYPE_SIZE)
		p = p->right;
	      if (p->right)
		{
		  p = p->right;
		  move = RIGHT;
		  continue;
		}
	      else
		p = find_up (p);
	      move = UP;
	    }
	  if (move == UP)
	    {
	      len2 = strtol (p->value, NULL, 10);
	      _ksba_asn_set_value (p, NULL, 0);
	      if (p->type == TYPE_SET_OF)
		_asn1_ordering_set_of (der + len2, p);
	      _asn1_length_der (counter - len2, temp, &len3);
	      memmove (der + len2 + len3, der + len2, counter - len2);
	      memcpy (der + len2, temp, len3);
	      counter += len3;
	      move = RIGHT;
	    }
	  break;
	case TYPE_ANY:
	  len2 = _ksba_asn_get_length_der (p->value, &len3);
	  memcpy (der + counter, p->value + len3, len2);
	  counter += len2;
	  move = RIGHT;
	  break;
	default:
	  move = (move == UP) ? RIGHT : DOWN;
	  break;
	}

      if ((move != DOWN) && (counter != counter_old))
	_asn1_complete_explicit_tag (p, der, &counter);

      if (p == node && move != DOWN)
	break;

      if (move == DOWN)
	{
	  if (p->down)
	    p = p->down;
	  else
	    move = RIGHT;
	}
      if (move == RIGHT)
	{
	  if (p->right)
	    p = p->right;
	  else
	    move = UP;
	}
      if (move == UP)
	p = find_up (p);
    }

  *len = counter;
  return ASN_OK;
}


/**
 * asn1_get_der:
 * @root: Pointer to the structure that you want to fill.
 * @der:  Buffer that contains the DER encoding. 
 * @len:  Length of this buffer
 * 
 * Fill the structure @root with the DER encoded buffer @der of
 * length @len. The structure must have been created
 * using asn1_create_stucture().
 * 
 * Return value: 
 *   ASN_OK:                 DER encoding OK
 *   ASN_ELEMENT_NOT_FOUND:  NAME is not a valid element.
 *   ASN_TAG_ERROR:          Encoding does not match the structure
 *   ASN_DER_ERROR:          Ditto.
 **/
int
asn1_get_der (AsnNode  root, unsigned char *der, int len)
{
  AsnNode node, p, p2, p3;
  char temp[128];
  int counter, len2, len3, len4, move, ris;
  unsigned char class, *temp2;
  unsigned int tag;
  long val;

  node = root;
  if (node == NULL)
    return ASN_ELEMENT_NOT_FOUND;

  if (node->flags.is_optional)
    return ASN_GENERIC_ERROR;

  counter = 0;
  move = DOWN;
  p = node;
  while (1)
    {
      ris = ASN_OK;

      if (move != UP)
	{
	  if (p->flags.is_set)
	    {
	      p2 = find_up (p);
	      len2 = strtol (p2->value, NULL, 10);
	      if (counter == len2)
		{
		  p = p2;
		  move = UP;
		  continue;
		}
	      else if (counter > len2)
		return ASN_DER_ERROR;
	      p2 = p2->down;
	      while (p2)
		{
		  if (p2->flags.is_set && p2->flags.is_not_used)
		    {		/* CONTROLLARE */
		      if (p2->type != TYPE_CHOICE)
			ris = _asn1_extract_tag_der (p2, der + counter, &len2);
		      else
			{
			  p3 = p2->down;
			  while (p3)
			    {
			      ris =
				_asn1_extract_tag_der (p3, der + counter,
						       &len2);
			      if (ris == ASN_OK)
				break;
			      //if(ris==ASN_ERROR_TYPE_ANY) return ASN_ERROR_TYPE_ANY;
			      p3 = p3->right;
			    }
			}
		      if (ris == ASN_OK)
			{
                          p2->flags.is_not_used = 0;
			  p = p2;
			  break;
			}
		      //else if(ris==ASN_ERROR_TYPE_ANY) return ASN_ERROR_TYPE_ANY;
		    }
		  p2 = p2->right;
		}
	      if (p2 == NULL)
		return ASN_DER_ERROR;
	    }

	  if (p->type == TYPE_CHOICE)
	    {
	      while (p->down)
		{
		  ris = _asn1_extract_tag_der (p->down, der + counter, &len2);
		  if (ris == ASN_OK)
		    {
		      while (p->down->right)
			ksba_asn_delete_structure (p->down->right);
		      break;
		    }
		  else if (ris == ASN_ERROR_TYPE_ANY)
		    return ASN_ERROR_TYPE_ANY;
		  else
		    ksba_asn_delete_structure (p->down);
		}
	      if (p->down == NULL)
		return ASN_DER_ERROR;
	      p = p->down;
	    }

	  if (p->flags.is_optional || p->flags.is_default)
	    {
	      p2 = find_up (p);
	      len2 = strtol (p2->value, NULL, 10);
	      if (counter >= len2)
		ris = ASN_TAG_ERROR;
	    }

	  if (ris == ASN_OK)
	    ris = _asn1_extract_tag_der (p, der + counter, &len2);
	  if (ris != ASN_OK)
	    {
	      //if(ris==ASN_ERROR_TYPE_ANY) return ASN_ERROR_TYPE_ANY;
	      if (p->flags.is_optional)
		{
                  p->flags.is_not_used = 1;
		  move = RIGHT;
		}
	      else if (p->flags.is_default)
		{
		  _ksba_asn_set_value (p, NULL, 0);
		  move = RIGHT;
		}
	      else
		{
		  //return (type_field(p->type)!=TYPE_ANY)?ASN_TAG_ERROR:ASN_ERROR_TYPE_ANY;
		  return ASN_TAG_ERROR;
		}
	    }
	  else
	    counter += len2;
	} /* move != UP */

      if (ris == ASN_OK)
	{
	  switch (p->type)
	    {
	    case TYPE_NULL:
	      if (der[counter])
		return ASN_DER_ERROR;
	      counter++;
	      move = RIGHT;
	      break;
	    case TYPE_BOOLEAN:
	      if (der[counter++] != 1)
		return ASN_DER_ERROR;
	      if (der[counter++] == 0)
		_ksba_asn_set_value (p, "F", 1);
	      else
		_ksba_asn_set_value (p, "T", 1);
	      move = RIGHT;
	      break;
	    case TYPE_INTEGER:
	    case TYPE_ENUMERATED:
	      len2 = _ksba_asn_get_length_der (der + counter, &len3);
	      _ksba_asn_set_value (p, der + counter, len3 + len2);
	      counter += len3 + len2;
	      move = RIGHT;
	      break;
	    case TYPE_OBJECT_ID:
	      _asn1_get_objectid_der (der + counter, &len2, temp);
	      _ksba_asn_set_value (p, temp, strlen (temp) + 1);
	      counter += len2;
	      move = RIGHT;
	      break;
	    case TYPE_TIME:
	      _asn1_get_time_der (der + counter, &len2, temp);
	      _ksba_asn_set_value (p, temp, strlen (temp) + 1);
	      counter += len2;
	      move = RIGHT;
	      break;
	    case TYPE_OCTET_STRING:
	      len2 = _ksba_asn_get_length_der (der + counter, &len3);
	      _ksba_asn_set_value (p, der + counter, len3 + len2);
	      counter += len3 + len2;
	      move = RIGHT;
	      break;
	    case TYPE_BIT_STRING:
	      len2 = _ksba_asn_get_length_der (der + counter, &len3);
	      _ksba_asn_set_value (p, der + counter, len3 + len2);
	      counter += len3 + len2;
	      move = RIGHT;
	      break;
	    case TYPE_SEQUENCE:
	    case TYPE_SET:;
	      if (move == UP)
		{
		  len2 = strtol (p->value, NULL, 10);
		  _ksba_asn_set_value (p, NULL, 0);
		  if (len2 != counter)
		    return ASN_DER_ERROR;
		  move = RIGHT;
		}
	      else
		{		/* move==DOWN || move==RIGHT */
		  len3 = _ksba_asn_get_length_der (der + counter, &len2);
		  counter += len2;
		  _asn1_ltostr (counter + len3, temp);
		  _ksba_asn_set_value (p, temp, strlen (temp) + 1);
		  move = DOWN;
		}
	      break;
	    case TYPE_SEQUENCE_OF:
	    case TYPE_SET_OF:
	      if (move == UP)
		{
		  len2 = strtol (p->value, NULL, 10);
		  if (len2 > counter)
		    {
		      _asn1_append_sequence_set (p);
		      p = p->down;
		      while (p->right)
			p = p->right;
		      move = RIGHT;
		      continue;
		    }
		  _ksba_asn_set_value (p, NULL, 0);
		  if (len2 != counter)
		    return ASN_DER_ERROR;
		}
	      else
		{		/* move==DOWN || move==RIGHT */
		  len3 = _ksba_asn_get_length_der (der + counter, &len2);
		  counter += len2;
		  if (len3)
		    {
		      _asn1_ltostr (counter + len3, temp);
		      _ksba_asn_set_value (p, temp, strlen (temp) + 1);
		      p2 = p->down;
		      while (p2->type == TYPE_TAG || p2->type == TYPE_SIZE)
			p2 = p2->right;
		      if (p2->right == NULL)
			_asn1_append_sequence_set (p);
		      p = p2;
		    }
		}
	      move = RIGHT;
	      break;
	    case TYPE_ANY:
	      tag = _asn1_get_tag_der (der + counter, &class, &len2);
	      len2 += _ksba_asn_get_length_der (der + counter + len2, &len3);
	      _asn1_length_der (len2 + len3, NULL, &len4);
	      temp2 = xmalloc (len2 + len3 + len4);
	      _asn1_octet_der (der + counter, len2 + len3, temp2, &len4);
	      _ksba_asn_set_value (p, temp2, len4);
	      xfree (temp2);
	      counter += len2 + len3;
	      move = RIGHT;
	      break;
	    default:
	      move = (move == UP) ? RIGHT : DOWN;
	      break;
	    }
	}

      if (p == node && move != DOWN)
	break;

      if (move == DOWN)
	{
	  if (p->down)
	    p = p->down;
	  else
	    move = RIGHT;
	}
      if (move == RIGHT && !p->flags.is_set)
	{
	  if (p->right)
	    p = p->right;
	  else
	    move = UP;
	}
      if (move == UP)
	p = find_up (p);
    }

  _ksba_asn_delete_not_used (root);

  return (counter == len) ? ASN_OK : ASN_DER_ERROR;
}



int
asn1_get_start_end_der (AsnNode  root, unsigned char *der, int len,
			char *name_element, int *start, int *end)
{
  AsnNode node, node_to_find, p, p2, p3;
  char temp[128];
  int counter, len2, len3, move, ris;
  unsigned char class;
  unsigned int tag;
  long val;

  node = root;
  node_to_find = _ksba_asn_find_node (root, name_element);

  if (node_to_find == NULL)
    return ASN_ELEMENT_NOT_FOUND;

  if (node_to_find == node)
    {
      *start = 0;
      *end = len - 1;
      return ASN_OK;
    }

  if (node == NULL)
    return ASN_ELEMENT_NOT_FOUND;

  if (node->flags.is_optional)
    return ASN_GENERIC_ERROR;

  counter = 0;
  move = DOWN;
  p = node;
  while (1)
    {
      ris = ASN_OK;

      if ((p == node_to_find) && (move != UP))
	*start = counter;

      if (move != UP)
	{
	  if (p->flags.is_set)
	    {
	      p2 = find_up (p);
	      len2 = strtol (p2->value, NULL, 10);
	      if (counter == len2)
		{
		  p = p2;
		  move = UP;
		  continue;
		}
	      else if (counter > len2)
		return ASN_DER_ERROR;
	      p2 = p2->down;
	      while (p2)
		{
		  if (p2->flags.is_set && p2->flags.is_not_used)
		    {		/* CONTROLLARE */
		      if (p2->type != TYPE_CHOICE)
			ris =  _asn1_extract_tag_der (p2, der+counter, &len2);
		      else
			{
			  p3 = p2->down;
			  ris =
			    _asn1_extract_tag_der (p3, der + counter, &len2);
			}
		      if (ris == ASN_OK)
			{
                          p2->flags.is_not_used = 0;
			  p = p2;
			  break;
			}
		    }
		  p2 = p2->right;
		}
	      if (p2 == NULL)
		return ASN_DER_ERROR;
	    }

	  if (p->type == TYPE_CHOICE)
	    {
	      p = p->down;
	      ris = _asn1_extract_tag_der (p, der + counter, &len2);
	    }

	  if (ris == ASN_OK)
	    ris = _asn1_extract_tag_der (p, der + counter, &len2);
	  if (ris != ASN_OK)
	    {
	      if (p->flags.is_optional)
		{
                  p->flags.is_not_used = 1;
		  move = RIGHT;
		}
	      else if (p->flags.is_default)
		{
		  move = RIGHT;
		}
	      else
		{
		  return ASN_TAG_ERROR;
		}
	    }
	  else
	    counter += len2;
	}

      if (ris == ASN_OK)
	{
	  switch (p->type)
	    {
	    case TYPE_NULL:
	      if (der[counter])
		return ASN_DER_ERROR;
	      counter++;
	      move = RIGHT;
	      break;
	    case TYPE_BOOLEAN:
	      if (der[counter++] != 1)
		return ASN_DER_ERROR;
	      counter++;
	      move = RIGHT;
	      break;
	    case TYPE_INTEGER:
	    case TYPE_ENUMERATED:
	      len2 = _ksba_asn_get_length_der (der + counter, &len3);
	      counter += len3 + len2;
	      move = RIGHT;
	      break;
	    case TYPE_OBJECT_ID:
	      len2 = _ksba_asn_get_length_der (der + counter, &len3);
	      counter += len2 + len3;
	      move = RIGHT;
	      break;
	    case TYPE_TIME:
	      len2 = _ksba_asn_get_length_der (der + counter, &len3);
	      counter += len2 + len3;
	      move = RIGHT;
	      break;
	    case TYPE_OCTET_STRING:
	      len2 = _ksba_asn_get_length_der (der + counter, &len3);
	      counter += len3 + len2;
	      move = RIGHT;
	      break;
	    case TYPE_BIT_STRING:
	      len2 = _ksba_asn_get_length_der (der + counter, &len3);
	      counter += len3 + len2;
	      move = RIGHT;
	      break;
	    case TYPE_SEQUENCE:
	    case TYPE_SET:
	      if (move != UP)
		{
		  len3 = _ksba_asn_get_length_der (der + counter, &len2);
		  counter += len2;
		  move = DOWN;
		}
	      else
		move = RIGHT;
	      break;
	    case TYPE_SEQUENCE_OF:
	    case TYPE_SET_OF:
	      if (move != UP)
		{
		  len3 = _ksba_asn_get_length_der (der + counter, &len2);
		  counter += len2;
		  if (len3)
		    {
		      p2 = p->down;
		      while (p2->type == TYPE_TAG || p2->type == TYPE_SIZE)
			p2 = p2->right;
		      p = p2;
		    }
		}
	      move = RIGHT;
	      break;
	    case TYPE_ANY:
	      tag = _asn1_get_tag_der (der + counter, &class, &len2);
	      len2 += _ksba_asn_get_length_der (der + counter + len2, &len3);
	      counter += len3 + len2;
	      move = RIGHT;
	      break;
	    default:
	      move = (move == UP) ? RIGHT : DOWN;
	      break;
	    }
	}

      if ((p == node_to_find) && (move == RIGHT))
	{
	  *end = counter - 1;
	  return ASN_OK;
	}

      if (p == node && move != DOWN)
	break;

      if (move == DOWN)
	{
	  if (p->down)
	    p = p->down;
	  else
	    move = RIGHT;
	}
      if ((move == RIGHT) && !p->flags.is_set)
	{
	  if (p->right)
	    p = p->right;
	  else
	    move = UP;
	}
      if (move == UP)
	p = find_up (p);
    }

  return ASN_ELEMENT_NOT_FOUND;
}
