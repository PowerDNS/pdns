#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

using namespace std;

typedef vector<string> words_t;

void printAndClearWords(words_t& words)
{
  bool firstparen=false, noparen=true;
  if(words.size() > 1) {
    for(words_t::iterator iter = words.begin() ; iter != words.end(); ++iter) {
      if(iter->find('(') != string::npos)
	noparen=false;

      if(iter != words.begin()) 
	cout<<" ";
      else if((*iter)[0]=='(') {
	iter->assign(iter->c_str()+1);
	firstparen=1;
      }

      if((firstparen || noparen) && iter + 1 == words.end() && (*iter)[iter->length()-1]==')')
	iter->resize(iter->length()-1);

      cout<<*iter;
    }
    cout<<"\n";
  }
  words.clear();
}

int main()
{
  int c;
  words_t words;
  string word;
  bool inword=false;
  int offset;
  while((c=getchar())!=EOF) {
    if(inword) {
      if(isspace(c) || c=='.' || c==',') {
	int offset=0;
	if(word[0]=='(') {
	  offset = 1;
	}

	if(word=="van" || word=="der" || word =="den" || (word.size() > 1 +offset  && isupper(word[offset]) && islower(word[offset+1]))) {
	  words.push_back(word);
	}
	else
	  printAndClearWords(words);

	if(ispunct(c))
	  printAndClearWords(words);

	word.clear();
	inword=false;
      }
      else 
	word.append(1, (char)c);
      continue;
    }
    
    if(!isspace(c)) {
      word.append(1, (char) c);
      inword=true;
    }
  }
}


