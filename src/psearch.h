static inline alloc_data_t *file_add_data(alloc_data_t *data, const uint64_t offset, const unsigned int content)
{
  if(!(data->start <= offset && offset <= data->end))
  {
    log_critical("file_add_data: bug\n");
    return data;
  }
  if(data->start==offset)
  {
    data->data=content;
    return data;
  }
  if(data->data==content)
    return data;
  {
    alloc_data_t *datanext=(alloc_data_t*)MALLOC(sizeof(*datanext));
    memcpy(datanext, data, sizeof(*datanext));
    data->end=offset-1;
    datanext->start=offset;
    datanext->file_stat=NULL;
    datanext->data=content;
    td_list_add(&datanext->list, &data->list);
    return datanext;
  }
}

static inline void file_recovery_cpy(file_recovery_t *dst, file_recovery_t *src)
{
  memcpy(dst, src, sizeof(*dst));
  dst->location.list.prev=&dst->location.list;
  dst->location.list.next=&dst->location.list;
}

/* Check if the block looks like an indirect/double-indirect block */
static inline int ind_block(const unsigned char *buffer, const unsigned int blocksize)
{
  const uint32_t *p32=(const uint32_t *)buffer;
  unsigned int i;
  unsigned int diff=1;	/* IND: Indirect block */
  if(le32(p32[0])==0)
    return 0;
  if(le32(p32[1])==le32(p32[0])+blocksize/4+1)
    diff=blocksize/4+1;	/* DIND: Double Indirect block */
  for(i=0;i<blocksize/4-1 && le32(p32[i+1])!=0;i++)
  {
    if(le32(p32[i+1])!=le32(p32[i])+diff)
    {
      return 0;
    }
  }
  i++;
  for(;i<blocksize/4 && le32(p32[i])==0;i++);
  if(i<blocksize/4)
  {
    return 0;
  }
  return 1;	/* Ok: ind_block points to non-fragmented block */
}


