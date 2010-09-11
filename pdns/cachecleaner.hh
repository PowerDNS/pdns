#ifndef PDNS_CACHECLEANER_HH
#define PDNS_CACHECLEANER_HH

// this function can clean any cache that has a getTTD() method on its entries, and a 'sequence' index as its second index
// the ritual is that the oldest entries are in *front* of the sequence collection, so on a hit, move an item to the end
// on a miss, move it to the beginning
template <typename T> void pruneCollection(T& collection, unsigned int maxCached, unsigned int scanFraction=1000)
{
  uint32_t now=(uint32_t)time(0);
  unsigned int toTrim=0;
  
  unsigned int cacheSize=collection.size();

  if(maxCached && cacheSize > maxCached) {
    toTrim = cacheSize - maxCached;
  }

//  cout<<"Need to trim "<<toTrim<<" from cache to meet target!\n";

  typedef typename T::template nth_index<1>::type sequence_t;
  sequence_t& sidx=collection.get<1>();

  unsigned int tried=0, lookAt, erased=0;

  // two modes - if toTrim is 0, just look through 1/scanFraction of all records 
  // and nuke everything that is expired
  // otherwise, scan first 5*toTrim records, and stop once we've nuked enough
  if(toTrim)
    lookAt=5*toTrim;
  else
    lookAt=cacheSize/scanFraction;

  typename sequence_t::iterator iter=sidx.begin(), eiter;
  for(; iter != sidx.end() && tried < lookAt ; ++tried) {
    if(iter->getTTD() < now) { 
      sidx.erase(iter++);
      erased++;
    }
    else
      ++iter;

    if(toTrim && erased > toTrim)
      break;
  }

  //cout<<"erased "<<erased<<" records based on ttd\n";
  
  if(erased >= toTrim) // done
    return;

  toTrim -= erased;

  //if(toTrim)
    // cout<<"Still have "<<toTrim - erased<<" entries left to erase to meet target\n"; 

  eiter=iter=sidx.begin();
  std::advance(eiter, toTrim); 
  sidx.erase(iter, eiter);      // just lob it off from the beginning
}


template <typename T> void moveCacheItemToFrontOrBack(T& collection, typename T::iterator& iter, bool front)
{
  typedef typename T::template nth_index<1>::type sequence_t;
  sequence_t& sidx=collection.get<1>();
  typename sequence_t::iterator si=collection.project<1>(iter);
  if(front)
    sidx.relocate(sidx.begin(), si); // at the beginning of the delete queue
  else
    sidx.relocate(sidx.end(), si);  // back
}

template <typename T> void moveCacheItemToFront(T& collection, typename T::iterator& iter)
{
  moveCacheItemToFrontOrBack(collection, iter, true);
}

template <typename T> void moveCacheItemToBack(T& collection, typename T::iterator& iter)
{
  moveCacheItemToFrontOrBack(collection, iter, false);
}

#endif
