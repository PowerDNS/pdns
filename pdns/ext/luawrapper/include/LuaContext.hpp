/*
Copyright (c) 2013, Pierre KRIEGER
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the <organization> nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef INCLUDE_LUACONTEXT_HPP
#define INCLUDE_LUACONTEXT_HPP

#include <algorithm>
#include <array>
#include <cassert>
#include <cmath>
#include <cstring>
#include <functional>
#include <limits>
#include <list>
#include <map>
#include <memory>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
#include <sstream>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <boost/any.hpp>
#include <boost/mpl/distance.hpp>
#include <boost/mpl/transform.hpp>
#include <boost/optional.hpp>
#include <boost/variant.hpp>
#include <boost/type_traits.hpp>
#include <lua.hpp>

#ifdef _MSC_VER
#   include "misc/exception.hpp"
#endif

#ifdef _GNUC
#   define ATTR_UNUSED __attribute__((unused))
#else
#   define ATTR_UNUSED
#endif

/**
 * Defines a Lua context
 * A Lua context is used to interpret Lua code. Since everything in Lua is a variable (including functions),
 * we only provide few functions like readVariable and writeVariable.
 *
 * You can also write variables with C++ functions so that they are callable by Lua. Note however that you HAVE TO convert
 * your function to std::function (not directly std::bind or a lambda function) so the class can detect which argument types
 * it wants. These arguments may only be of basic types (int, float, etc.) or std::string.
 */
class LuaContext {
    struct ValueInRegistry;
    template<typename TFunctionObject, typename TFirstParamType> struct Binder;
    template<typename T> struct IsOptional;
    enum Globals_t { Globals }; // tag for "global variables"
public:
    /**
     * @param openDefaultLibs True if luaL_openlibs should be called
     */
    explicit LuaContext(bool openDefaultLibs = true)
    {
        // luaL_newstate can return null if allocation failed
        mState = luaL_newstate();
        if (mState == nullptr)
            throw std::bad_alloc();

        // setting the panic function
        lua_atpanic(mState, [](lua_State* state) -> int {
            const std::string str = lua_tostring(state, -1);
            lua_pop(state, 1);
            assert(false && "lua_atpanic triggered");
            exit(0);
        });

        // opening default library if required to do so
        if (openDefaultLibs)
            luaL_openlibs(mState);
    }

    /**
     * Move constructor
     */
    LuaContext(LuaContext&& s) :
        mState(s.mState)
    {
        s.mState = luaL_newstate();
    }
    
    /**
     * Move operator
     */
    LuaContext& operator=(LuaContext&& s) noexcept
    {
        std::swap(mState, s.mState);
        return *this;
    }

    /**
     * Copy is forbidden
     */
    LuaContext(const LuaContext&) = delete;
    
    /**
     * Copy is forbidden
     */
    LuaContext& operator=(const LuaContext&) = delete;

    /**
     * Destructor
     */
    ~LuaContext() noexcept
    {
        assert(mState);
        lua_close(mState);
    }
    
    /**
     * Thrown when an error happens during execution of lua code (like not enough parameters for a function)
     */
    class ExecutionErrorException : public std::runtime_error
    {
    public:
        ExecutionErrorException(const std::string& msg) :
            std::runtime_error(msg)
        {
        }
    };

    /**
     * Thrown when a syntax error happens in a lua script
     */
    class SyntaxErrorException : public std::runtime_error
    {
    public:
        SyntaxErrorException(const std::string& msg) :
            std::runtime_error(msg)
        {
        }
    };

    /**
     * Thrown when trying to cast a Lua variable to an unvalid type, eg. trying to read a number when the variable is a string
     */
    class WrongTypeException : public std::runtime_error
    {
    public:
        WrongTypeException(std::string luaType, const std::type_info& destination) :
            std::runtime_error("Trying to cast a lua variable from \"" + luaType + "\" to \"" + destination.name() + "\""),
            luaType(luaType),
            destination(destination)
        {
        }
        
        std::string luaType;
        const std::type_info& destination;
    };

    /**
     * Function object that can call a function stored by Lua
     * This type is copiable and movable, but not constructible. It can only be created through readVariable.
     * @tparam TFunctionType    Function type (eg. "int (int, bool)")
     */
    template<typename TFunctionType>
    class LuaFunctionCaller;

    /**
     * Opaque type that identifies a Lua thread
     */
    struct ThreadID {
        ThreadID() = default;
        ThreadID(ThreadID&& o) : state(o.state), threadInRegistry(std::move(o.threadInRegistry)) { }
        ThreadID& operator=(ThreadID&& o) { std::swap(state, o.state); std::swap(threadInRegistry, o.threadInRegistry); return *this; }
    public:
        friend LuaContext;
        lua_State* state;
        std::unique_ptr<ValueInRegistry> threadInRegistry;
    };

    /**
     * Type that is considered as an empty array
     */
    enum EmptyArray_t { EmptyArray };

    /**
     * Type for a metatable
     */
    enum Metatable_t { Metatable };

    /**
     * Executes lua code from the stream
     * @param code      A stream that Lua will read its code from
     */
    void executeCode(std::istream& code)
    {
        auto toCall = load(mState, code);
        call<std::tuple<>>(mState, std::move(toCall));
    }

    /**
     * Executes lua code from the stream and returns a value
     * @param code      A stream that Lua will read its code from
     * @tparam TType    The type that the executing code should return
     */
    template<typename TType>
    auto executeCode(std::istream& code)
        -> TType
    {
        auto toCall = load(mState, code);
        return call<TType>(mState, std::move(toCall));
    }

    /**
     * Executes lua code given as parameter
     * @param code      A string containing code that will be executed by Lua
     */
    void executeCode(const std::string& code)
    {
        executeCode(code.c_str());
    }
    
    /*
     * Executes Lua code from the stream and returns a value
     * @param code      A string containing code that will be executed by Lua
     * @tparam TType    The type that the executing code should return
     */
    template<typename TType>
    auto executeCode(const std::string& code)
        -> TType
    {
        return executeCode<TType>(code.c_str());
    }

    /**
     * Executes Lua code
     * @param code      A string containing code that will be executed by Lua
     */
    void executeCode(const char* code)
    {
        auto toCall = load(mState, code);
        call<std::tuple<>>(mState, std::move(toCall));
    }

    /*
     * Executes Lua code from the stream and returns a value
     * @param code      A string containing code that will be executed by Lua
     * @tparam TType    The type that the executing code should return
     */
    template<typename TType>
    auto executeCode(const char* code)
        -> TType
    {
        auto toCall = load(mState, code);
        return call<TType>(mState, std::move(toCall));
    }

    /**
     * Executes lua code from the stream
     * @param code      A stream that Lua will read its code from
     */
    void executeCode(const ThreadID& thread, std::istream& code)
    {
        auto toCall = load(thread.state, code);
        call<std::tuple<>>(thread.state, std::move(toCall));
    }

    /**
     * Executes lua code from the stream and returns a value
     * @param code      A stream that Lua will read its code from
     * @tparam TType    The type that the executing code should return
     */
    template<typename TType>
    auto executeCode(const ThreadID& thread, std::istream& code)
        -> TType
    {
        auto toCall = load(thread.state, code);
        return call<TType>(thread.state, std::move(toCall));
    }

    /**
     * Executes lua code given as parameter
     * @param code      A string containing code that will be executed by Lua
     */
    void executeCode(const ThreadID& thread, const std::string& code)
    {
        executeCode(thread, code.c_str());
    }
    
    /*
     * Executes Lua code from the stream and returns a value
     * @param code      A string containing code that will be executed by Lua
     * @tparam TType    The type that the executing code should return
     */
    template<typename TType>
    auto executeCode(const ThreadID& thread, const std::string& code)
        -> TType
    {
        return executeCode<TType>(thread, code.c_str());
    }

    /**
     * Executes Lua code
     * @param code      A string containing code that will be executed by Lua
     */
    void executeCode(const ThreadID& thread, const char* code)
    {
        auto toCall = load(thread.state, code);
        call<std::tuple<>>(thread.state, std::move(toCall));
    }

    /*
     * Executes Lua code from the stream and returns a value
     * @param code      A string containing code that will be executed by Lua
     * @tparam TType    The type that the executing code should return
     */
    template<typename TType>
    auto executeCode(const ThreadID& thread, const char* code)
        -> TType
    {
        auto toCall = load(thread.state, code);
        return call<TType>(thread.state, std::move(toCall));
    }
    
    /**
     * Tells that Lua will be allowed to access an object's function
     * This is the version "registerFunction(name, &Foo::function)"
     */
    template<typename TPointerToMemberFunction>
    auto registerFunction(const std::string& name, TPointerToMemberFunction pointer)
        -> typename std::enable_if<std::is_member_function_pointer<TPointerToMemberFunction>::value>::type
    {
        registerFunctionImpl(name, std::mem_fn(pointer), tag<TPointerToMemberFunction>{});
    }

    /**
     * Tells that Lua will be allowed to access an object's function
     * This is the version with an explicit template parameter: "registerFunction<void (Foo::*)()>(name, [](Foo&) { })"
     * @param fn                Function object which takes as first parameter a reference to the object
     * @tparam TFunctionType    Pointer-to-member function type
     */
    template<typename TFunctionType, typename TType>
    void registerFunction(const std::string& functionName, TType fn)
    {
        static_assert(std::is_member_function_pointer<TFunctionType>::value, "registerFunction must take a member function pointer type as template parameter");
        registerFunctionImpl(functionName, std::move(fn), tag<TFunctionType>{});
    }

    /**
     * Tells that Lua will be allowed to access an object's function
     * This is the alternative version with an explicit template parameter: "registerFunction<Foo, void (*)()>(name, [](Foo&) { })"
     * @param fn                Function object which takes as first parameter a reference to the object
     * @tparam TObject          Object to register this function to
     * @tparam TFunctionType    Function type
     */
    template<typename TObject, typename TFunctionType, typename TType>
    void registerFunction(const std::string& functionName, TType fn)
    {
        static_assert(std::is_function<TFunctionType>::value, "registerFunction must take a function type as template parameter");
        registerFunctionImpl(functionName, std::move(fn), tag<TObject>{}, tag<TFunctionType>{});
    }

    /**
     * Inverse operation of registerFunction
     * @tparam TType Type whose function belongs to
     */
    template<typename TType>
    void unregisterFunction(const std::string& functionName)
    {
        lua_pushlightuserdata(mState, const_cast<std::type_info*>(&typeid(TType)));
        lua_pushnil(mState);
        lua_settable(mState, LUA_REGISTRYINDEX);
        checkTypeRegistration(mState, &typeid(TType));
        
        lua_pushlightuserdata(mState, const_cast<std::type_info*>(&typeid(TType*)));
        lua_pushnil(mState);
        lua_settable(mState, LUA_REGISTRYINDEX);
        checkTypeRegistration(mState, &typeid(TType*));
        
        lua_pushlightuserdata(mState, const_cast<std::type_info*>(&typeid(std::shared_ptr<TType>)));
        lua_pushnil(mState);
        lua_settable(mState, LUA_REGISTRYINDEX);
        checkTypeRegistration(mState, &typeid(std::shared_ptr<TType>));
    }
    
    /**
     * Registers a member variable
     * This is the version "registerMember(name, &Foo::member)"
     */
    template<typename TObject, typename TVarType>
    void registerMember(const std::string& name, TVarType TObject::*member)
    {
        // implementation simply calls the custom member with getter and setter
        const auto getter = [=](const TObject& obj) -> TVarType { return obj.*member; };
        const auto setter = [=](TObject& obj, const TVarType& value) { obj.*member = value; };
        registerMember<TVarType (TObject::*)>(name, getter, setter);
    }

    /**
     * Registers a member variable
     * This is the version "registerMember<Foo, int>(name, getter, setter)"
     * @tparam TObject       Type to register the member to
     * @tparam TVarType      Type of the member
     * @param name           Name of the member to register
     * @param readFunction   Function of type "TVarType (const TObject&)"
     * @param writeFunction  Function of type "void (TObject&, const TVarType&)"
     */
    template<typename TObject, typename TVarType, typename TReadFunction, typename TWriteFunction>
    void registerMember(const std::string& name, TReadFunction readFunction, TWriteFunction writeFunction)
    {
        registerMemberImpl<TObject,TVarType>(name, std::move(readFunction), std::move(writeFunction));
    }

    /**
     * Registers a member variable
     * This is the version "registerMember<int (Foo::*)>(name, getter, setter)"
     * @tparam TMemberType   Pointer to member object representing the type
     * @param name           Name of the member to register
     * @param readFunction   Function of type "TVarType (const TObject&)"
     * @param writeFunction  Function of type "void (TObject&, const TVarType&)"
     */
    template<typename TMemberType, typename TReadFunction, typename TWriteFunction>
    void registerMember(const std::string& name, TReadFunction readFunction, TWriteFunction writeFunction)
    {
        static_assert(std::is_member_object_pointer<TMemberType>::value, "registerMember must take a member object pointer type as template parameter");
        registerMemberImpl(tag<TMemberType>{}, name, std::move(readFunction), std::move(writeFunction));
    }

    /**
     * Registers a non-modifiable member variable
     * This is the version "registerMember<Foo, int>(name, getter)"
     * @tparam TObject       Type to register the member to
     * @tparam TVarType      Type of the member
     * @param name           Name of the member to register
     * @param readFunction   Function of type "TVarType (const TObject&)"
     */
    template<typename TObject, typename TVarType, typename TReadFunction>
    void registerMember(const std::string& name, TReadFunction readFunction)
    {
        registerMemberImpl<TObject,TVarType>(name, std::move(readFunction));
    }

    /**
     * Registers a non-modifiable member variable
     * This is the version "registerMember<int (Foo::*)>(name, getter)"
     * @tparam TMemberType   Pointer to member object representing the type
     * @param name           Name of the member to register
     * @param readFunction   Function of type "TVarType (const TObject&)"
     */
    template<typename TMemberType, typename TReadFunction>
    void registerMember(const std::string& name, TReadFunction readFunction)
    {
        static_assert(std::is_member_object_pointer<TMemberType>::value, "registerMember must take a member object pointer type as template parameter");
        registerMemberImpl(tag<TMemberType>{}, name, std::move(readFunction));
    }

    /**
     * Registers a dynamic member variable
     * This is the version "registerMember<Foo, int>(getter, setter)"
     * @tparam TObject       Type to register the member to
     * @tparam TVarType      Type of the member
     * @param readFunction   Function of type "TVarType (const TObject&, const std::string&)"
     * @param writeFunction  Function of type "void (TObject&, const std::string&, const TVarType&)"
     */
    template<typename TObject, typename TVarType, typename TReadFunction, typename TWriteFunction>
    void registerMember(TReadFunction readFunction, TWriteFunction writeFunction)
    {
        registerMemberImpl<TObject,TVarType>(std::move(readFunction), std::move(writeFunction));
    }

    /**
     * Registers a dynamic member variable
     * This is the version "registerMember<int (Foo::*)>(getter, setter)"
     * @tparam TMemberType   Pointer to member object representing the type
     * @param readFunction   Function of type "TVarType (const TObject&, const std::string&)"
     * @param writeFunction  Function of type "void (TObject&, const std::string&, const TVarType&)"
     */
    template<typename TMemberType, typename TReadFunction, typename TWriteFunction>
    void registerMember(TReadFunction readFunction, TWriteFunction writeFunction)
    {
        static_assert(std::is_member_object_pointer<TMemberType>::value, "registerMember must take a member object pointer type as template parameter");
        registerMemberImpl(tag<TMemberType>{}, std::move(readFunction), std::move(writeFunction));
    }

    /**
     * Registers a dynamic non-modifiable member variable
     * This is the version "registerMember<Foo, int>(getter)"
     * @tparam TObject       Type to register the member to
     * @tparam TVarType      Type of the member
     * @param readFunction   Function of type "TVarType (const TObject&, const std::string&)"
     */
    template<typename TObject, typename TVarType, typename TReadFunction>
    void registerMember(TReadFunction readFunction)
    {
        registerMemberImpl<TObject, TVarType>(std::move(readFunction));
    }

    /**
     * Registers a dynamic non-modifiable member variable
     * This is the version "registerMember<int (Foo::*)>(getter)"
     * @tparam TMemberType   Pointer to member object representing the type
     * @param readFunction   Function of type "TVarType (const TObject&, const std::string&)"
     */
    template<typename TMemberType, typename TReadFunction>
    void registerMember(TReadFunction readFunction)
    {
        static_assert(std::is_member_object_pointer<TMemberType>::value, "registerMember must take a member object pointer type as template parameter");
        registerMemberImpl(tag<TMemberType>{}, std::move(readFunction));
    }

    /**
     * Creates a new thread
     * A Lua thread is not really a thread, but rather an "execution stack".
     * You can destroy the thread by calling destroyThread
     * @sa destroyThread
     */
    auto createThread()
        -> ThreadID
    {
        ThreadID result;

        result.state = lua_newthread(mState);
        result.threadInRegistry = std::unique_ptr<ValueInRegistry>(new ValueInRegistry(mState));
        lua_pop(mState, 1);

        return std::move(result);
    }

    /**
     * Destroys a thread created with createThread
     * @sa createThread
     */
    void destroyThread(ThreadID& id)
    {
        id.threadInRegistry.reset();
    }
    
    /**
     * Reads the content of a Lua variable
     * 
     * @tparam TType                Type requested for the read
     * @throw WrongTypeException    When the variable is not convertible to the requested type
     * @sa writeVariable
     *
     * Readable types are all types accepted by writeVariable except nullptr, std::unique_ptr and function pointers
     * Additionaly supported:
     *  - LuaFunctionCaller<FunctionType>, which is an alternative to std::function
     *  - references to custom objects, in which case it will return the object in-place
     *
     * After the variable name, you can add other parameters.
     * If the variable is an array, it will instead get the element of that array whose offset is the second parameter.
     * Same applies for third, fourth, etc. parameters.
    */
    template<typename TType, typename... TTypes>
    TType readVariable(const std::string& name, TTypes&&... elements) const
    {
        lua_getglobal(mState, name.c_str());
        lookIntoStackTop(mState, std::forward<TTypes>(elements)...);
        return readTopAndPop<TType>(mState, PushedObject{mState, 1});
    }
    
    /**
     * @sa readVariable
     */
    template<typename TType, typename... TTypes>
    TType readVariable(const char* name, TTypes&&... elements) const
    {
        lua_getglobal(mState, name);
        lookIntoStackTop(mState, std::forward<TTypes>(elements)...);
        return readTopAndPop<TType>(mState, PushedObject{mState, 1});
    }
    
    /**
     * @sa readVariable
     */
    template<typename TType, typename... TTypes>
    TType readVariable(const ThreadID& thread, const std::string& name, TTypes&&... elements) const
    {
        lua_getglobal(thread.state, name.c_str());
        lookIntoStackTop(thread.state, std::forward<TTypes>(elements)...);
        return readTopAndPop<TType>(thread.state, PushedObject{thread.state, 1});
    }
    
    /**
     * @sa readVariable
     */
    template<typename TType, typename... TTypes>
    TType readVariable(const ThreadID& thread, const char* name, TTypes&&... elements) const
    {
        lua_getglobal(thread.state, name);
        lookIntoStackTop(thread.state, std::forward<TTypes>(elements)...);
        return readTopAndPop<TType>(thread.state, PushedObject{thread.state, 1});
    }
    
    /**
     * Changes the content of a Lua variable
     * 
     * Accepted values are:
     * - all base types (char, short, int, float, double, bool)
     * - std::string
     * - enums
     * - std::vector<>
     * - std::vector<std::pair<>>, std::map<> and std::unordered_map<> (the key and value must also be accepted values)
     * - std::function<> (all parameters must be accepted values, and return type must be either an accepted value for readVariable or a tuple)
     * - std::shared_ptr<> (std::unique_ptr<> are converted to std::shared_ptr<>)
     * - nullptr (writes nil)
     * - any object
     *
     * All objects are passed by copy and destroyed by the garbage collector if necessary.
     */
    template<typename... TData>
    void writeVariable(TData&&... data) noexcept {
        static_assert(sizeof...(TData) >= 2, "You must pass at least a variable name and a value to writeVariable");
        typedef typename std::decay<typename std::tuple_element<sizeof...(TData) - 1,std::tuple<TData...>>::type>::type
            RealDataType;
        static_assert(!std::is_same<typename Tupleizer<RealDataType>::type,RealDataType>::value, "Error: you can't use LuaContext::writeVariable with a tuple");
        
        setTable<RealDataType>(mState, Globals, std::forward<TData>(data)...);
    }
    
    /**
     * Equivalent to writeVariable(varName, ..., std::function<TFunctionType>(data));
     * This version is more effecient than writeVariable if you want to write functions
     */
    template<typename TFunctionType, typename... TData>
    void writeFunction(TData&&... data) noexcept {
        static_assert(sizeof...(TData) >= 2, "You must pass at least a variable name and a value to writeFunction");
        
        setTable<TFunctionType>(mState, Globals, std::forward<TData>(data)...);
    }

    /**
     * Same as the other writeFunction, except that the template parameter is automatically detected
     * This only works if the data is either a native function pointer, or contains one operator() (this is the case for lambdas)
     */
    template<typename... TData>
    void writeFunction(TData&&... data) noexcept {
        static_assert(sizeof...(TData) >= 2, "You must pass at least a variable name and a value to writeFunction");
        typedef typename std::decay<typename std::tuple_element<sizeof...(TData) - 1,std::tuple<TData...>>::type>::type
            RealDataType;
        typedef typename FunctionTypeDetector<RealDataType>::type
            DetectedFunctionType;
        
        return writeFunction<DetectedFunctionType>(std::forward<TData>(data)...);
    }
    

private:
    // the state is the most important variable in the class since it is our interface with Lua
    //  - registered members and functions are stored in tables at offset &typeid(type) of the registry
    //    each table has its getter functions at offset 0, getter members at offset 1, default getter at offset 2
    //    offset 3 is unused, setter members at offset 4, default setter at offset 5
    lua_State*                  mState;

    
    /**************************************************/
    /*                 PUSH OBJECT                    */
    /**************************************************/
    struct PushedObject {
        PushedObject(lua_State* state, int num = 1) : state(state), num(num) {}
        ~PushedObject() { assert(lua_gettop(state) >= num); if (num >= 1) lua_pop(state, num); }
        
        PushedObject& operator=(const PushedObject&) = delete;
        PushedObject(const PushedObject&) = delete;
        PushedObject& operator=(PushedObject&& other) { std::swap(state, other.state); std::swap(num, other.num); return *this; }
        PushedObject(PushedObject&& other) : state(other.state), num(other.num) { other.num = 0; }

        PushedObject operator+(PushedObject&& other) && { PushedObject obj(state, num + other.num); num = 0; other.num = 0; return std::move(obj); }
        void operator+=(PushedObject&& other) { assert(state == other.state); num += other.num; other.num = 0; }
        
        auto getState() const -> lua_State* { return state; }
        auto getNum() const -> int { return num; }

        int release() { const auto n = num; num = 0; return n; }
        void pop() { if (num >= 1) lua_pop(state, num); num = 0; }
        void pop(int n) { assert(num >= n); lua_pop(state, n); num -= n; }

    private:
        lua_State* state;
        int num = 0;
    };
    

    /**************************************************/
    /*                     MISC                       */
    /**************************************************/
    // type used as a tag
    template<typename T>
    struct tag {};

    // tag for "the registry"
    enum RegistryTag { Registry };
    
    // this function takes a value representing the offset to look into
    // it will look into the top element of the stack and replace the element by its content at the given index
    template<typename OffsetType1, typename... OffsetTypeOthers>
    static void lookIntoStackTop(lua_State* state, OffsetType1&& offset1, OffsetTypeOthers&&... offsetOthers) {
        static_assert(Pusher<typename std::decay<OffsetType1>::type>::minSize == 1 && Pusher<typename std::decay<OffsetType1>::type>::maxSize == 1, "Impossible to have a multiple-values index");
        auto p1 = Pusher<typename std::decay<OffsetType1>::type>::push(state, offset1);
        lua_gettable(state, -2);
        lua_remove(state, -2);
        p1.release();

        lookIntoStackTop(state, std::forward<OffsetTypeOthers>(offsetOthers)...);
    }

    template<typename... OffsetTypeOthers>
    static void lookIntoStackTop(lua_State* state, Metatable_t, OffsetTypeOthers&&... offsetOthers) {
        lua_getmetatable(state, -1);
        lua_remove(state, -2);

        lookIntoStackTop(state, std::forward<OffsetTypeOthers>(offsetOthers)...);
    }
    
    static void lookIntoStackTop(lua_State*) {
    }
    
    // equivalent of lua_settable with t[k]=n, where t is the value at the index in the template parameter, k is the second parameter, n is the last parameter, and n is pushed by the function in the first parameter
    // if there are more than 3 parameters, parameters 3 to n-1 are considered as sub-indices into the array
    // the dataPusher MUST push only one thing on the stack
    // TTableIndex must be either LUA_REGISTERYINDEX, LUA_GLOBALSINDEX, LUA_ENVINDEX, or the position of the element on the stack
    template<typename TDataType, typename TIndex, typename TData>
    static void setTable(lua_State* state, const PushedObject&, TIndex&& index, TData&& data) noexcept
    {
        static_assert(Pusher<typename std::decay<TIndex>::type>::minSize == 1 && Pusher<typename std::decay<TIndex>::type>::maxSize == 1, "Impossible to have a multiple-values index");
        static_assert(Pusher<typename std::decay<TDataType>::type>::minSize == 1 && Pusher<typename std::decay<TDataType>::type>::maxSize == 1, "Impossible to have a multiple-values data");
        
        auto p1 = Pusher<typename std::decay<TIndex>::type>::push(state, index);
        auto p2 = Pusher<typename std::decay<TDataType>::type>::push(state, std::forward<TData>(data));

        lua_settable(state, -3);
        p1.release();
        p2.release();
    }

    template<typename TDataType, typename TData>
    static void setTable(lua_State* state, const PushedObject&, const std::string& index, TData&& data) noexcept
    {
        static_assert(Pusher<typename std::decay<TDataType>::type>::minSize == 1 && Pusher<typename std::decay<TDataType>::type>::maxSize == 1, "Impossible to have a multiple-values data");

        auto p1 = Pusher<typename std::decay<TDataType>::type>::push(state, std::forward<TData>(data));
        lua_setfield(state, -2, index.c_str());
        p1.release();
    }

    template<typename TDataType, typename TData>
    static void setTable(lua_State* state, const PushedObject&, const char* index, TData&& data) noexcept
    {
        static_assert(Pusher<typename std::decay<TDataType>::type>::minSize == 1 && Pusher<typename std::decay<TDataType>::type>::maxSize == 1, "Impossible to have a multiple-values data");
        
        auto p1 = Pusher<typename std::decay<TDataType>::type>::push(state, std::forward<TData>(data));
        lua_setfield(state, -2, index);
        p1.release();
    }

    template<typename TDataType, typename TData>
    static void setTable(lua_State* state, const PushedObject&, Metatable_t, TData&& data) noexcept
    {
        static_assert(Pusher<typename std::decay<TDataType>::type>::minSize == 1 && Pusher<typename std::decay<TDataType>::type>::maxSize == 1, "Impossible to have a multiple-values data");
        
        auto p1 = Pusher<typename std::decay<TDataType>::type>::push(state, std::forward<TData>(data));
        lua_setmetatable(state, -2);
        p1.release();
    }

    template<typename TDataType, typename TIndex1, typename TIndex2, typename TIndex3, typename... TIndices>
    static auto setTable(lua_State* state, PushedObject&, TIndex1&& index1, TIndex2&& index2, TIndex3&& index3, TIndices&&... indices) noexcept
        -> typename std::enable_if<!std::is_same<typename std::decay<TIndex1>::type, Metatable_t>::value>::type
    {
        static_assert(Pusher<typename std::decay<TIndex1>::type>::minSize == 1 && Pusher<typename std::decay<TIndex1>::type>::maxSize == 1, "Impossible to have a multiple-values index");
        
        auto p1 = Pusher<typename std::decay<TIndex1>::type>::push(state, std::forward<TIndex1>(index1));
        lua_gettable(state, -2);

        setTable<TDataType>(state, std::move(p1), std::forward<TIndex2>(index2), std::forward<TIndex3>(index3), std::forward<TIndices>(indices)...);
    }

    template<typename TDataType, typename TIndex1, typename TIndex2, typename TIndex3, typename... TIndices>
    static auto setTable(lua_State* state, PushedObject&& pushedTable, TIndex1&& index1, TIndex2&& index2, TIndex3&& index3, TIndices&&... indices) noexcept
        -> typename std::enable_if<!std::is_same<typename std::decay<TIndex1>::type, Metatable_t>::value>::type
    {
        static_assert(Pusher<typename std::decay<TIndex1>::type>::minSize == 1 && Pusher<typename std::decay<TIndex1>::type>::maxSize == 1, "Impossible to have a multiple-values index");
        
        auto p1 = Pusher<typename std::decay<TIndex1>::type>::push(state, std::forward<TIndex1>(index1)) + std::move(pushedTable);
        lua_gettable(state, -2);

        setTable<TDataType>(state, std::move(p1), std::forward<TIndex2>(index2), std::forward<TIndex3>(index3), std::forward<TIndices>(indices)...);
    }

    template<typename TDataType, typename TIndex2, typename TIndex3, typename... TIndices>
    static void setTable(lua_State* state, PushedObject& pushedObject, Metatable_t, TIndex2&& index2, TIndex3&& index3, TIndices&&... indices) noexcept
    {
        if (lua_getmetatable(state, -1) == 0)
        {
            lua_newtable(state);
            PushedObject p1{state, 1};

            setTable<TDataType>(state, p1, std::forward<TIndex2>(index2), std::forward<TIndex3>(index3), std::forward<TIndices>(indices)...);

            lua_setmetatable(state, -2);
            p1.release();
        }
        else
        {
            setTable<TDataType>(state, pushedObject, std::forward<TIndex2>(index2), std::forward<TIndex3>(index3), std::forward<TIndices>(indices)...);
        }
    }

    template<typename TDataType, typename TIndex2, typename TIndex3, typename... TIndices>
    static void setTable(lua_State* state, PushedObject&& pushedObject, Metatable_t, TIndex2&& index2, TIndex3&& index3, TIndices&&... indices) noexcept
    {
        if (lua_getmetatable(state, -1) == 0)
        {
            lua_newtable(state);
            PushedObject p1{state, 1};

            setTable<TDataType>(state, p1, std::forward<TIndex2>(index2), std::forward<TIndex3>(index3), std::forward<TIndices>(indices)...);

            lua_setmetatable(state, -2);
            p1.release();
        }
        else
        {
            setTable<TDataType>(state, std::move(pushedObject), std::forward<TIndex2>(index2), std::forward<TIndex3>(index3), std::forward<TIndices>(indices)...);
        }
    }

    template<typename TDataType, typename TIndex, typename TData>
    static void setTable(lua_State* state, RegistryTag, TIndex&& index, TData&& data) noexcept
    {
        static_assert(Pusher<typename std::decay<TIndex>::type>::minSize == 1 && Pusher<typename std::decay<TIndex>::type>::maxSize == 1, "Impossible to have a multiple-values index");
        static_assert(Pusher<typename std::decay<TDataType>::type>::minSize == 1 && Pusher<typename std::decay<TDataType>::type>::maxSize == 1, "Impossible to have a multiple-values data");
        
        auto p1 = Pusher<typename std::decay<TIndex>::type>::push(state, index);
        auto p2 = Pusher<typename std::decay<TDataType>::type>::push(state, std::forward<TData>(data));

        lua_settable(state, LUA_REGISTRYINDEX);
        p1.release();
        p2.release();
    }

    template<typename TDataType, typename TData>
    static void setTable(lua_State* state, RegistryTag, const std::string& index, TData&& data) noexcept
    {
        static_assert(Pusher<typename std::decay<TDataType>::type>::minSize == 1 && Pusher<typename std::decay<TDataType>::type>::maxSize == 1, "Impossible to have a multiple-values data");

        auto p1 = Pusher<typename std::decay<TDataType>::type>::push(state, std::forward<TData>(data));
        lua_setfield(state, LUA_REGISTRYINDEX, index.c_str());
        p1.release();
    }

    template<typename TDataType, typename TData>
    static void setTable(lua_State* state, RegistryTag, const char* index, TData&& data) noexcept
    {
        static_assert(Pusher<typename std::decay<TDataType>::type>::minSize == 1 && Pusher<typename std::decay<TDataType>::type>::maxSize == 1, "Impossible to have a multiple-values data");

        auto p1 = Pusher<typename std::decay<TDataType>::type>::push(state, std::forward<TData>(data));
        lua_setfield(state, LUA_REGISTRYINDEX, index);
        p1.release();
    }

    template<typename TDataType, typename TIndex1, typename TIndex2, typename TIndex3, typename... TIndices>
    static void setTable(lua_State* state, RegistryTag, TIndex1&& index1, TIndex2&& index2, TIndex3&& index3, TIndices&&... indices) noexcept
    {
        static_assert(Pusher<typename std::decay<TIndex1>::type>::minSize == 1 && Pusher<typename std::decay<TIndex1>::type>::maxSize == 1, "Impossible to have a multiple-values index");
        
        auto p1 = Pusher<typename std::decay<TIndex1>::type>::push(state, std::forward<TIndex1>(index1));
        lua_gettable(state, LUA_REGISTRYINDEX);

        setTable<TDataType>(state, std::move(p1), std::forward<TIndex2>(index2), std::forward<TIndex3>(index3), std::forward<TIndices>(indices)...);
    }

    template<typename TDataType, typename TIndex, typename TData>
    static void setTable(lua_State* state, Globals_t, TIndex&& index, TData&& data) noexcept
    {
        static_assert(Pusher<typename std::decay<TIndex>::type>::minSize == 1 && Pusher<typename std::decay<TIndex>::type>::maxSize == 1, "Impossible to have a multiple-values index");
        static_assert(Pusher<typename std::decay<TDataType>::type>::minSize == 1 && Pusher<typename std::decay<TDataType>::type>::maxSize == 1, "Impossible to have a multiple-values data");
        
        
#       if LUA_VERSION_NUM >= 502

            lua_pushglobaltable(state);
            PushedObject p3{state, 1};
            auto p1 = Pusher<typename std::decay<TIndex>::type>::push(state, index);
            auto p2 = Pusher<typename std::decay<TDataType>::type>::push(state, std::forward<TData>(data));
            lua_settable(state, -3);

#       else
            
            auto p1 = Pusher<typename std::decay<TIndex>::type>::push(state, index);
            auto p2 = Pusher<typename std::decay<TDataType>::type>::push(state, std::forward<TData>(data));
            lua_settable(state, LUA_GLOBALSINDEX);

#       endif

        p1.release();
        p2.release();
    }

    template<typename TDataType, typename TData>
    static void setTable(lua_State* state, Globals_t, const std::string& index, TData&& data) noexcept
    {
        static_assert(Pusher<typename std::decay<TDataType>::type>::minSize == 1 && Pusher<typename std::decay<TDataType>::type>::maxSize == 1, "Impossible to have a multiple-values data");

        auto p1 = Pusher<typename std::decay<TDataType>::type>::push(state, std::forward<TData>(data));
        lua_setglobal(state, index.c_str());
        p1.release();
    }

    template<typename TDataType, typename TData>
    static void setTable(lua_State* state, Globals_t, const char* index, TData&& data) noexcept
    {
        static_assert(Pusher<typename std::decay<TDataType>::type>::minSize == 1 && Pusher<typename std::decay<TDataType>::type>::maxSize == 1, "Impossible to have a multiple-values data");

        auto p1 = Pusher<typename std::decay<TDataType>::type>::push(state, std::forward<TData>(data));
        lua_setglobal(state, index);
        p1.release();
    }

    template<typename TDataType, typename TIndex1, typename TIndex2, typename TIndex3, typename... TIndices>
    static void setTable(lua_State* state, Globals_t, TIndex1&& index1, TIndex2&& index2, TIndex3&& index3, TIndices&&... indices) noexcept
    {
        static_assert(Pusher<typename std::decay<TIndex1>::type>::minSize == 1 && Pusher<typename std::decay<TIndex1>::type>::maxSize == 1, "Impossible to have a multiple-values index");
        
#       if LUA_VERSION_NUM >= 502

            lua_pushglobaltable(state);
            auto p1 = Pusher<typename std::decay<TIndex1>::type>::push(state, std::forward<TIndex1>(index1)) + PushedObject{state, 1};
            lua_gettable(state, -2);

#       else

            auto p1 = Pusher<typename std::decay<TIndex1>::type>::push(state, std::forward<TIndex1>(index1));
            lua_gettable(state, LUA_GLOBALSINDEX);

#       endif

        setTable<TDataType>(state, std::move(p1), std::forward<TIndex2>(index2), std::forward<TIndex3>(index3), std::forward<TIndices>(indices)...);
    }

    // TODO: g++ reports "ambiguous overload"
    /*template<typename TDataType, typename TIndex2, typename TIndex3, typename... TIndices>
    static void setTable(lua_State* state, Globals_t, const char* index, TIndex2&& index2, TIndex3&& index3, TIndices&&... indices) noexcept
    {
        lua_getglobal(state, index);
        PushedObject p1{state, 1};

        setTable<TDataType>(state, std::move(p1), std::forward<TIndex2>(index2), std::forward<TIndex3>(index3), std::forward<TIndices>(indices)...);
    }

    template<typename TDataType, typename TIndex2, typename TIndex3, typename... TIndices>
    static void setTable(lua_State* state, Globals_t, const std::string& index, TIndex2&& index2, TIndex3&& index3, TIndices&&... indices) noexcept
    {
        lua_getglobal(state, index.c_str());
        PushedObject p1{state, 1};

        setTable<TDataType>(state, std::move(p1), std::forward<TIndex2>(index2), std::forward<TIndex3>(index3), std::forward<TIndices>(indices)...);
    }*/

    // simple function that reads the "nb" first top elements of the stack, pops them, and returns the value
    // warning: first parameter is the number of parameters, not the parameter index
    // if read generates an exception, stack is poped anyway
    template<typename TReturnType>
    static auto readTopAndPop(lua_State* state, PushedObject object)
        -> TReturnType
    {
        auto val = Reader<typename std::decay<TReturnType>::type>::read(state, -object.getNum());
        if (!val.is_initialized())
            throw WrongTypeException{lua_typename(state, lua_type(state, -object.getNum())), typeid(TReturnType)};
        return val.get();
    }

    // checks that the offsets for a type's registrations are set in the registry
    static void checkTypeRegistration(lua_State* state, const std::type_info* type)
    {
        lua_pushlightuserdata(state, const_cast<std::type_info*>(type));
        lua_gettable(state, LUA_REGISTRYINDEX);
        if (!lua_isnil(state, -1)) {
            lua_pop(state, 1);
            return;
        }
        lua_pop(state, 1);

        lua_pushlightuserdata(state, const_cast<std::type_info*>(type));
        lua_newtable(state);

        lua_pushinteger(state, 0);
        lua_newtable(state);
        lua_settable(state, -3);

        lua_pushinteger(state, 1);
        lua_newtable(state);
        lua_settable(state, -3);

        lua_pushinteger(state, 3);
        lua_newtable(state);
        lua_settable(state, -3);

        lua_pushinteger(state, 4);
        lua_newtable(state);
        lua_settable(state, -3);

        lua_settable(state, LUA_REGISTRYINDEX);
    }

    // 
#   ifdef _MSC_VER
        __declspec(noreturn)
#   else
        [[noreturn]]
#   endif
    static void luaError(lua_State* state)
    {
        lua_error(state);
        assert(false);
        std::terminate();   // removes compilation warning
    }
    

    /**************************************************/
    /*            FUNCTIONS REGISTRATION              */
    /**************************************************/
    // the "registerFunction" public functions call this one
    template<typename TFunctionType, typename TRetValue, typename TObject, typename... TOtherParams>
    void registerFunctionImpl(const std::string& functionName, TFunctionType function, tag<TObject>, tag<TRetValue (TOtherParams...)>)
    {
        static_assert(std::is_class<TObject>::value || std::is_pointer<TObject>::value, "registerFunction can only be used for a class or a pointer");

        checkTypeRegistration(mState, &typeid(TObject));
        setTable<TRetValue(TObject&, TOtherParams...)>(mState, Registry, &typeid(TObject), 0, functionName, std::move(function));
        
        checkTypeRegistration(mState, &typeid(TObject*));
        setTable<TRetValue(TObject*, TOtherParams...)>(mState, Registry, &typeid(TObject*), 0, functionName, [=](TObject* obj, TOtherParams... rest) { assert(obj); return function(*obj, std::forward<TOtherParams>(rest)...); });
        
        checkTypeRegistration(mState, &typeid(std::shared_ptr<TObject>));
        setTable<TRetValue(std::shared_ptr<TObject>, TOtherParams...)>(mState, Registry, &typeid(std::shared_ptr<TObject>), 0, functionName, [=](const std::shared_ptr<TObject>& obj, TOtherParams... rest) { assert(obj); return function(*obj, std::forward<TOtherParams>(rest)...); });
    }
    
    template<typename TFunctionType, typename TRetValue, typename TObject, typename... TOtherParams>
    void registerFunctionImpl(const std::string& functionName, TFunctionType function, tag<const TObject>, tag<TRetValue (TOtherParams...)> fTypeTag)
    {
        registerFunctionImpl(functionName, function, tag<TObject>{}, fTypeTag);

        checkTypeRegistration(mState, &typeid(TObject const*));
        setTable<TRetValue(TObject const*, TOtherParams...)>(mState, Registry, &typeid(TObject const*), 0, functionName, [=](TObject const* obj, TOtherParams... rest) { assert(obj); return function(*obj, std::forward<TOtherParams>(rest)...); });
        
        checkTypeRegistration(mState, &typeid(std::shared_ptr<TObject const>));
        setTable<TRetValue(std::shared_ptr<TObject const>, TOtherParams...)>(mState, Registry, &typeid(std::shared_ptr<TObject const>), 0, functionName, [=](const std::shared_ptr<TObject const>& obj, TOtherParams... rest) { assert(obj); return function(*obj, std::forward<TOtherParams>(rest)...); });
    }

    template<typename TFunctionType, typename TRetValue, typename TObject, typename... TOtherParams>
    void registerFunctionImpl(const std::string& functionName, TFunctionType function, tag<TRetValue (TObject::*)(TOtherParams...)>)
    {
        registerFunctionImpl(functionName, std::move(function), tag<TObject>{}, tag<TRetValue (TOtherParams...)>{});
    }

    template<typename TFunctionType, typename TRetValue, typename TObject, typename... TOtherParams>
    void registerFunctionImpl(const std::string& functionName, TFunctionType function, tag<TRetValue (TObject::*)(TOtherParams...) const>)
    {
        registerFunctionImpl(functionName, std::move(function), tag<const TObject>{}, tag<TRetValue (TOtherParams...)>{});
    }

    template<typename TFunctionType, typename TRetValue, typename TObject, typename... TOtherParams>
    void registerFunctionImpl(const std::string& functionName, TFunctionType function, tag<TRetValue (TObject::*)(TOtherParams...) volatile>)
    {
        registerFunctionImpl(functionName, std::move(function), tag<TObject>{}, tag<TRetValue (TOtherParams...)>{});
    }

    template<typename TFunctionType, typename TRetValue, typename TObject, typename... TOtherParams>
    void registerFunctionImpl(const std::string& functionName, TFunctionType function, tag<TRetValue (TObject::*)(TOtherParams...) const volatile>)
    {
        registerFunctionImpl(functionName, std::move(function), tag<const TObject>{}, tag<TRetValue (TOtherParams...)>{});
    }

    // the "registerMember" public functions call this one
    template<typename TObject, typename TVarType, typename TReadFunction>
    void registerMemberImpl(const std::string& name, TReadFunction readFunction)
    {
        static_assert(std::is_class<TObject>::value || std::is_pointer<TObject>::value, "registerMember can only be called on a class or a pointer");
        
        checkTypeRegistration(mState, &typeid(TObject));
        setTable<TVarType (TObject&)>(mState, Registry, &typeid(TObject), 1, name, [readFunction](TObject const& object) {
            return readFunction(object);
        });
        
        checkTypeRegistration(mState, &typeid(TObject*));
        setTable<TVarType (TObject*)>(mState, Registry, &typeid(TObject*), 1, name, [readFunction](TObject const* object) {
            assert(object);
            return readFunction(*object);
        });
        
        checkTypeRegistration(mState, &typeid(TObject const*));
        setTable<TVarType (TObject const*)>(mState, Registry, &typeid(TObject const*), 1, name, [readFunction](TObject const* object) {
            assert(object);
            return readFunction(*object);
        });
        
        checkTypeRegistration(mState, &typeid(std::shared_ptr<TObject>));
        setTable<TVarType (std::shared_ptr<TObject>)>(mState, Registry, &typeid(std::shared_ptr<TObject>), 1, name, [readFunction](const std::shared_ptr<TObject>& object) {
            assert(object);
            return readFunction(*object);
        });
        
        checkTypeRegistration(mState, &typeid(std::shared_ptr<TObject const>));
        setTable<TVarType (std::shared_ptr<TObject const>)>(mState, Registry, &typeid(std::shared_ptr<TObject const>), 1, name, [readFunction](const std::shared_ptr<TObject const>& object) {
            assert(object);
            return readFunction(*object);
        });
    }

    template<typename TObject, typename TVarType, typename TReadFunction, typename TWriteFunction>
    void registerMemberImpl(const std::string& name, TReadFunction readFunction, TWriteFunction writeFunction)
    {
        registerMemberImpl<TObject,TVarType>(name, readFunction);

        setTable<void (TObject&, TVarType)>(mState, Registry, &typeid(TObject), 4, name, [writeFunction](TObject& object, const TVarType& value) {
            writeFunction(object, value);
        });
        
        setTable<void (TObject*, TVarType)>(mState, Registry, &typeid(TObject*), 4, name, [writeFunction](TObject* object, const TVarType& value) {
            assert(object);
            writeFunction(*object, value);
        });
        
        setTable<void (std::shared_ptr<TObject>, TVarType)>(mState, Registry, &typeid(std::shared_ptr<TObject>), 4, name, [writeFunction](std::shared_ptr<TObject> object, const TVarType& value) {
            assert(object);
            writeFunction(*object, value);
        });
    }

    template<typename TObject, typename TVarType, typename TReadFunction, typename TWriteFunction>
    void registerMemberImpl(tag<TVarType (TObject::*)>, const std::string& name, TReadFunction readFunction, TWriteFunction writeFunction)
    {
        registerMemberImpl<TObject,TVarType>(name, std::move(readFunction), std::move(writeFunction));
    }

    template<typename TObject, typename TVarType, typename TReadFunction>
    void registerMemberImpl(tag<TVarType(TObject::*)>, const std::string& name, TReadFunction readFunction)
    {
        registerMemberImpl<TObject, TVarType>(name, std::move(readFunction));
    }

    // the "registerMember" public functions call this one
    template<typename TObject, typename TVarType, typename TReadFunction>
    void registerMemberImpl(TReadFunction readFunction)
    {
        checkTypeRegistration(mState, &typeid(TObject));
        setTable<TVarType (TObject const&, std::string)>(mState, Registry, &typeid(TObject), 2, [readFunction](TObject const& object, const std::string& name) {
            return readFunction(object, name);
        });
        
        checkTypeRegistration(mState, &typeid(TObject*));
        setTable<TVarType (TObject*, std::string)>(mState, Registry, &typeid(TObject*), 2, [readFunction](TObject const* object, const std::string& name) {
            assert(object);
            return readFunction(*object, name);
        });
        
        checkTypeRegistration(mState, &typeid(TObject const*));
        setTable<TVarType (TObject const*, std::string)>(mState, Registry, &typeid(TObject const*), 2, [readFunction](TObject const* object, const std::string& name) {
            assert(object);
            return readFunction(*object, name);
        });
        
        checkTypeRegistration(mState, &typeid(std::shared_ptr<TObject>));
        setTable<TVarType (std::shared_ptr<TObject>, std::string)>(mState, Registry, &typeid(std::shared_ptr<TObject>), 2, [readFunction](const std::shared_ptr<TObject>& object, const std::string& name) {
            assert(object);
            return readFunction(*object, name);
        });
        
        checkTypeRegistration(mState, &typeid(std::shared_ptr<TObject const>));
        setTable<TVarType (std::shared_ptr<TObject const>, std::string)>(mState, Registry, &typeid(std::shared_ptr<TObject const>), 2, [readFunction](const std::shared_ptr<TObject const>& object, const std::string& name) {
            assert(object);
            return readFunction(*object, name);
        });
    }

    template<typename TObject, typename TVarType, typename TReadFunction, typename TWriteFunction>
    void registerMemberImpl(TReadFunction readFunction, TWriteFunction writeFunction)
    {
        registerMemberImpl<TObject,TVarType>(readFunction);

        setTable<void (TObject&, std::string, TVarType)>(mState, Registry, &typeid(TObject), 5, [writeFunction](TObject& object, const std::string& name, const TVarType& value) {
            writeFunction(object, name, value);
        });
        
        setTable<void (TObject*, std::string, TVarType)>(mState, Registry, &typeid(TObject*), 2, [writeFunction](TObject* object, const std::string& name, const TVarType& value) {
            assert(object);
            writeFunction(*object, name, value);
        });
        
        setTable<void (std::shared_ptr<TObject>, std::string, TVarType)>(mState, Registry, &typeid(std::shared_ptr<TObject>), 2, [writeFunction](const std::shared_ptr<TObject>& object, const std::string& name, const TVarType& value) {
            assert(object);
            writeFunction(*object, name, value);
        });
    }

    template<typename TObject, typename TVarType, typename TReadFunction, typename TWriteFunction>
    void registerMemberImpl(tag<TVarType (TObject::*)>, TReadFunction readFunction, TWriteFunction writeFunction)
    {
        registerMemberImpl<TObject,TVarType>(std::move(readFunction), std::move(writeFunction));
    }

    template<typename TObject, typename TVarType, typename TReadFunction>
    void registerMemberImpl(tag<TVarType(TObject::*)>, TReadFunction readFunction)
    {
        registerMemberImpl<TObject, TVarType>(std::move(readFunction));
    }
    

    /**************************************************/
    /*              LOADING AND CALLING               */
    /**************************************************/
    // this function loads data from the stream and pushes a function at the top of the stack
    // throws in case of syntax error
    static PushedObject load(lua_State* state, std::istream& code) {
        // since the lua_load function requires a static function, we use this structure
        // the Reader structure is at the same time an object storing an istream and a buffer,
        //   and a static function provider
        struct Reader {
            Reader(std::istream& str) : stream(str) {}
            std::istream&           stream;
            std::array<char,512>    buffer;

            // read function ; "data" must be an instance of Reader
            static const char* read(lua_State* l, void* data, size_t* size) {
                assert(size != nullptr);
                assert(data != nullptr);
                Reader& me = *static_cast<Reader*>(data);
                if (me.stream.eof())    { *size = 0; return nullptr; }

                me.stream.read(me.buffer.data(), me.buffer.size());
                *size = static_cast<size_t>(me.stream.gcount());    // gcount could return a value larger than a size_t, but its maximum is me.buffer.size() so there's no problem
                return me.buffer.data();
            }
        };

        // we create an instance of Reader, and we call lua_load
        Reader reader{code};
        const auto loadReturnValue = lua_load(state, &Reader::read, &reader, "chunk"
#           if LUA_VERSION_NUM >= 502
                , nullptr
#           endif
        );

        // now we have to check return value
        if (loadReturnValue != 0) {
            // there was an error during loading, an error message was pushed on the stack
            const std::string errorMsg = lua_tostring(state, -1);
            lua_pop(state, 1);
            if (loadReturnValue == LUA_ERRMEM)
                throw std::bad_alloc();
            else if (loadReturnValue == LUA_ERRSYNTAX)
                throw SyntaxErrorException{errorMsg};
            throw std::runtime_error("Error while calling lua_load: " + errorMsg);
        }

        return PushedObject{state, 1};
    }
    
    // this function loads data and pushes a function at the top of the stack
    // throws in case of syntax error
    static PushedObject load(lua_State* state, const char* code) {
        auto loadReturnValue = luaL_loadstring(state, code);

        // now we have to check return value
        if (loadReturnValue != 0) {
            // there was an error during loading, an error message was pushed on the stack
            const std::string errorMsg = lua_tostring(state, -1);
            lua_pop(state, 1);
            if (loadReturnValue == LUA_ERRMEM)
                throw std::bad_alloc();
            else if (loadReturnValue == LUA_ERRSYNTAX)
                throw SyntaxErrorException{errorMsg};
            throw std::runtime_error("Error while calling lua_load: " + errorMsg);
        }

        return PushedObject{state, 1};
    }

    // this function calls what is on the top of the stack and removes it (just like lua_call)
    // if an exception is triggered, the top of the stack will be removed anyway
    template<typename TReturnType, typename... TParameters>
    static auto call(lua_State* state, PushedObject toCall, TParameters&&... input)
        -> TReturnType
    {
        typedef typename Tupleizer<TReturnType>::type
            RealReturnType;
        
        // we push the parameters on the stack
        auto inArguments = Pusher<std::tuple<TParameters...>>::push(state, std::make_tuple(std::forward<TParameters>(input)...));

        // 
        const int outArgumentsCount = std::tuple_size<RealReturnType>::value;
        auto outArguments = callRaw(state, std::move(toCall) + std::move(inArguments), outArgumentsCount);

        // pcall succeeded, we pop the returned values and return them
        return readTopAndPop<TReturnType>(state, std::move(outArguments));
    }
    
    // this function just calls lua_pcall and checks for errors
    static PushedObject callRaw(lua_State* state, PushedObject functionAndArguments, const int outArguments)
    {
        // calling pcall automatically pops the parameters and pushes output
        const auto pcallReturnValue = lua_pcall(state, functionAndArguments.getNum() - 1, outArguments, 0);
        functionAndArguments.release();

        // if pcall failed, analyzing the problem and throwing
        if (pcallReturnValue != 0) {
            PushedObject errorCode{state, 1};

            // an error occured during execution, either an error message or a std::exception_ptr was pushed on the stack
            if (pcallReturnValue == LUA_ERRMEM) {
                throw std::bad_alloc{};

            } else if (pcallReturnValue == LUA_ERRRUN) {
                if (lua_isstring(state, 1)) {
                    // the error is a string
                    const auto str = readTopAndPop<std::string>(state, std::move(errorCode));
                    throw ExecutionErrorException{str};

                } else {
                    // an exception_ptr was pushed on the stack
                    // rethrowing it with an additional ExecutionErrorException
                    try {
                        std::rethrow_exception(readTopAndPop<std::exception_ptr>(state, std::move(errorCode)));
                    } catch(...) {
                        std::throw_with_nested(ExecutionErrorException{"Exception thrown by a callback function called by Lua"});
                    }
                }
            }
        }

        return PushedObject{state, outArguments};
    }

    
    /**************************************************/
    /*                PUSH FUNCTIONS                  */
    /**************************************************/
    template<typename T>
    static PushedObject push(lua_State* state, T&& value)
    {
        return Pusher<typename std::decay<T>::type>::push(state, std::forward<T>(value));
    }

    // the Pusher structures allow you to push a value on the stack
    //  - static const int minSize : minimum size on the stack that the value can have
    //  - static const int maxSize : maximum size on the stack that the value can have
    //  - static int push(const LuaContext&, ValueType) : pushes the value on the stack and returns the size on the stack

    // implementation for custom objects
    template<typename TType, typename = void>
    struct Pusher {
        static const int minSize = 1;
        static const int maxSize = 1;

        template<typename TType2>
        static PushedObject push(lua_State* state, TType2&& value) noexcept {
            // this function is called when lua's garbage collector wants to destroy our object
            // we simply call its destructor
            const auto garbageCallbackFunction = [](lua_State* lua) -> int {
                assert(lua_gettop(lua) == 1);
                TType* ptr = static_cast<TType*>(lua_touserdata(lua, 1));
                assert(ptr);
                ptr->~TType();
                return 0;
            };

            // this function will be stored in __index in the metatable
            const auto indexFunction = [](lua_State* lua) -> int {
                try {
                    assert(lua_gettop(lua) == 2);
                    assert(lua_isuserdata(lua, 1));

                    // searching for a handler
                    lua_pushlightuserdata(lua, const_cast<std::type_info*>(&typeid(TType)));
                    lua_gettable(lua, LUA_REGISTRYINDEX);
                    assert(!lua_isnil(lua, -1));
                    
                    // looking into getter functions
                    lua_pushinteger(lua, 0);
                    lua_gettable(lua, -2);
                    lua_pushvalue(lua, 2);
                    lua_gettable(lua, -2);
                    if (!lua_isnil(lua, -1))
                        return 1;
                    lua_pop(lua, 2);
                    
                    // looking into getter members
                    lua_pushinteger(lua, 1);
                    lua_gettable(lua, -2);
                    lua_pushvalue(lua, 2);
                    lua_gettable(lua, -2);
                    if (!lua_isnil(lua, -1)) {
                        lua_pushvalue(lua, 1);
                        return callRaw(lua, PushedObject{lua, 2}, 1).release();
                    }
                    lua_pop(lua, 2);

                    // looking into default getter
                    lua_pushinteger(lua, 2);
                    lua_gettable(lua, -2);
                    if (lua_isnil(lua, -1))
                        return 1;
                    lua_pushvalue(lua, 1);
                    lua_pushvalue(lua, 2);
                    return callRaw(lua, PushedObject{lua, 3}, 1).release();

                } catch (...) {
                    Pusher<std::exception_ptr>::push(lua, std::current_exception()).release();
                    luaError(lua);
                }
            };

            // this function will be stored in __newindex in the metatable
            const auto newIndexFunction = [](lua_State* lua) -> int {
                try {
                    assert(lua_gettop(lua) == 3);
                    assert(lua_isuserdata(lua, 1));

                    // searching for a handler
                    lua_pushlightuserdata(lua, const_cast<std::type_info*>(&typeid(TType)));
                    lua_rawget(lua, LUA_REGISTRYINDEX);
                    assert(!lua_isnil(lua, -1));
                    
                    // looking into setter members
                    lua_pushinteger(lua, 4);
                    lua_rawget(lua, -2);
                    lua_pushvalue(lua, 2);
                    lua_rawget(lua, -2);
                    if (!lua_isnil(lua, -1)) {
                        lua_pushvalue(lua, 1);
                        lua_pushvalue(lua, 3);
                        callRaw(lua, PushedObject{lua, 3}, 0);
                        lua_pop(lua, 2);
                        return 0;
                    }
                    lua_pop(lua, 2);

                    // looking into default setter
                    lua_pushinteger(lua, 5);
                    lua_rawget(lua, -2);
                    if (lua_isnil(lua, -1))
                    {
                        lua_pop(lua, 2);
                        lua_pushstring(lua, "No setter found");
                        luaError(lua);
                    }
                    lua_pushvalue(lua, 1);
                    lua_pushvalue(lua, 2);
                    lua_pushvalue(lua, 3);
                    callRaw(lua, PushedObject{lua, 4}, 0);
                    lua_pop(lua, 1);
                    return 0;

                } catch (...) {
                    Pusher<std::exception_ptr>::push(lua, std::current_exception()).release();
                    luaError(lua);
                }
            };

            // writing structure for this type into the registry
            checkTypeRegistration(state, &typeid(TType));

            // creating the object
            // lua_newuserdata allocates memory in the internals of the lua library and returns it so we can fill it
            //   and that's what we do with placement-new
            const auto pointerLocation = static_cast<TType*>(lua_newuserdata(state, sizeof(TType)));
            new (pointerLocation) TType(std::forward<TType2>(value));
            PushedObject obj{state, 1};

            // creating the metatable (over the object on the stack)
            // lua_settable pops the key and value we just pushed, so stack management is easy
            // all that remains on the stack after these function calls is the metatable
            lua_newtable(state);
            PushedObject pushedTable{state, 1};

            // using the garbage collecting function we created above
            if (!boost::has_trivial_destructor<TType>::value)
            {
                lua_pushstring(state, "__gc");
                lua_pushcfunction(state, garbageCallbackFunction);
                lua_settable(state, -3);
            }

            // the _typeid index of the metatable will store the type_info*
            lua_pushstring(state, "_typeid");
            lua_pushlightuserdata(state, const_cast<std::type_info*>(&typeid(TType)));
            lua_settable(state, -3);

            // using the index function we created above
            lua_pushstring(state, "__index");
            lua_pushcfunction(state, indexFunction);
            lua_settable(state, -3);

            // using the newindex function we created above
            lua_pushstring(state, "__newindex");
            lua_pushcfunction(state, newIndexFunction);
            lua_settable(state, -3);

            // at this point, the stack contains the object at offset -2 and the metatable at offset -1
            // lua_setmetatable will bind the two together and pop the metatable
            // our custom type remains on the stack (and that's what we want since this is a push function)
            lua_setmetatable(state, -2);
            pushedTable.release();
            
            return std::move(obj);
        }
    };
    
    // this structure has a "size" int static member which is equal to the total of the push min size of all the types
    template<typename... TTypes>
    struct PusherTotalMinSize;

    // this structure has a "size" int static member which is equal to the total of the push max size of all the types
    template<typename... TTypes>
    struct PusherTotalMaxSize;
    
    // this structure has a "size" int static member which is equal to the maximum size of the push of all the types
    template<typename... TTypes>
    struct PusherMinSize;
    
    // this structure has a "size" int static member which is equal to the maximum size of the push of all the types
    template<typename... TTypes>
    struct PusherMaxSize;

    
    /**************************************************/
    /*                READ FUNCTIONS                  */
    /**************************************************/
    // the "Reader" structures allow to read data from the stack
    // - the "ReturnType" type is what is returned by the reader, and can be different than the template parameter (especially with references and constness)
    // - the "read" static function will check and read at the same time, returning an empty optional if it is the wrong type
    
    template<typename TType, typename = void>
    struct Reader {
        typedef typename std::conditional<std::is_pointer<TType>::value, TType, TType&>::type
            ReturnType;
        
        static auto read(lua_State* state, int index)
            -> boost::optional<ReturnType>
        {
            if (!test(state, index))
                return boost::none;
            return boost::optional<ReturnType>(*static_cast<TType*>(lua_touserdata(state, index)));
        }

    private:
        static bool test(lua_State* state, int index)
        {
            if (!lua_isuserdata(state, index))
                return false;
            if (!lua_getmetatable(state, index))
                return false;

            // now we have our metatable on the top of the stack
            // retrieving its _typeid member
            lua_pushstring(state, "_typeid");
            lua_gettable(state, -2);
            const auto storedTypeID = static_cast<const std::type_info*>(lua_touserdata(state, -1));
            const auto typeIDToCompare = &typeid(TType);

            // if wrong typeid, returning false
            lua_pop(state, 2);
            if (storedTypeID != typeIDToCompare)
                return false;

            return true;
        }
    };
    
    /**
     * This functions reads multiple values starting at "index" and passes them to the callback
     */
    template<typename TRetValue, typename TCallback>
    static auto readIntoFunction(lua_State* state, tag<TRetValue>, TCallback&& callback, int index)
        -> TRetValue
    {
        return callback();
    }
    template<typename TRetValue, typename TCallback, typename TFirstType, typename... TTypes>
    static auto readIntoFunction(lua_State* state, tag<TRetValue> retValueTag, TCallback&& callback, int index, tag<TFirstType>, tag<TTypes>... othersTags)
        -> typename std::enable_if<IsOptional<TFirstType>::value, TRetValue>::type
    {
        if (index >= 0) {
            Binder<TCallback, const TFirstType&> binder{ callback, {} };
            return readIntoFunction(state, retValueTag, binder, index + 1, othersTags...);
        }

        const auto& firstElem = Reader<typename std::decay<TFirstType>::type>::read(state, index);
        if (!firstElem)
            throw WrongTypeException(lua_typename(state, index), typeid(TFirstType));

        Binder<TCallback, const TFirstType&> binder{ callback, *firstElem };
        return readIntoFunction(state, retValueTag, binder, index + 1, othersTags...);
    }
    template<typename TRetValue, typename TCallback, typename TFirstType, typename... TTypes>
    static auto readIntoFunction(lua_State* state, tag<TRetValue> retValueTag, TCallback&& callback, int index, tag<TFirstType>, tag<TTypes>... othersTags)
        -> typename std::enable_if<!IsOptional<TFirstType>::value, TRetValue>::type
    {
        if (index >= 0)
            throw std::logic_error("Wrong number of parameters");

        const auto& firstElem = Reader<typename std::decay<TFirstType>::type>::read(state, index);
        if (!firstElem)
            throw WrongTypeException(lua_typename(state, index), typeid(TFirstType));

        Binder<TCallback, const TFirstType&> binder{ callback, *firstElem };
        return readIntoFunction(state, retValueTag, binder, index + 1, othersTags...);
    }


    /**************************************************/
    /*                   UTILITIES                    */
    /**************************************************/
    // structure that will ensure that a certain is stored somewhere in the registry
    struct ValueInRegistry {
        // this constructor will clone and hold the value at the top of the stack in the registry
        ValueInRegistry(lua_State* lua) : lua{lua}
        {
            lua_pushlightuserdata(lua, this);
            lua_pushvalue(lua, -2);
            lua_settable(lua, LUA_REGISTRYINDEX);
        }
        
        // removing the function from the registry
        ~ValueInRegistry()
        {
            lua_pushlightuserdata(lua, this);
            lua_pushnil(lua);
            lua_settable(lua, LUA_REGISTRYINDEX);
        }

        // loads the value and puts it at the top of the stack
        PushedObject pop()
        {
            lua_pushlightuserdata(lua, this);
            lua_gettable(lua, LUA_REGISTRYINDEX);
            return PushedObject{lua, 1};
        }

        ValueInRegistry(const ValueInRegistry&) = delete;
        ValueInRegistry& operator=(const ValueInRegistry&) = delete;

    private:
        lua_State* lua;
    };
    
    // binds the first parameter of a function object
    template<typename TFunctionObject, typename TFirstParamType>
    struct Binder {
        TFunctionObject function;
        TFirstParamType param;

        template<typename... TParams>
        auto operator()(TParams&&... params)
            -> decltype(function(param, std::forward<TParams>(params)...))
        {
            return function(param, std::forward<TParams>(params)...);
        }
    };
    
    // turns a type into a tuple
    // void is turned into std::tuple<>
    // existing tuples are untouched
    template<typename T>
    struct Tupleizer;

    // this structure takes a pointer to a member function type and returns the base function type
    template<typename TType>
    struct RemoveMemberPointerFunction { typedef void type; };          // required because of a compiler bug

    // this structure takes any object and detects its function type
    template<typename TObjectType>
    struct FunctionTypeDetector { typedef typename RemoveMemberPointerFunction<decltype(&std::decay<TObjectType>::type::operator())>::type type; };

    // this structure takes a function arguments list and has the "min" and the "max" static const member variables, whose value equal to the min and max number of parameters for the function
    // the only case where "min != max" is with boost::optional at the end of the list
    template<typename... TArgumentsList>
    struct FunctionArgumentsCounter {};
    
    // true is the template parameter is a boost::optional
    template<typename T>
    struct IsOptional : public std::false_type {};
};

/// @deprecated
static LuaContext::EmptyArray_t ATTR_UNUSED
    LuaEmptyArray {};
/// @deprecated
static LuaContext::Metatable_t ATTR_UNUSED
    LuaMetatable {};
    
/**************************************************/
/*            PARTIAL IMPLEMENTATIONS             */
/**************************************************/
template<>
inline auto LuaContext::readTopAndPop<void>(lua_State* state, PushedObject obj)
    -> void
{
}

// this structure takes a template parameter T
// if T is a tuple, it returns T ; if T is not a tuple, it returns std::tuple<T>
// we have to use this structure because std::tuple<std::tuple<...>> triggers a bug in both MSVC++ and GCC
template<typename T>
struct LuaContext::Tupleizer                        { typedef std::tuple<T>         type; };
template<typename... Args>
struct LuaContext::Tupleizer<std::tuple<Args...>>   { typedef std::tuple<Args...>   type; };
template<>
struct LuaContext::Tupleizer<void>                  { typedef std::tuple<>          type; };

// this structure takes any object and detects its function type
template<typename TRetValue, typename... TParameters>
struct LuaContext::FunctionTypeDetector<TRetValue (TParameters...)>             { typedef TRetValue type(TParameters...); };
template<typename TObjectType>
struct LuaContext::FunctionTypeDetector<TObjectType*>                           { typedef typename FunctionTypeDetector<TObjectType>::type type; };

// this structure takes a pointer to a member function type and returns the base function type
template<typename TType, typename TRetValue, typename... TParameters>
struct LuaContext::RemoveMemberPointerFunction<TRetValue (TType::*)(TParameters...)>                    { typedef TRetValue type(TParameters...); };
template<typename TType, typename TRetValue, typename... TParameters>
struct LuaContext::RemoveMemberPointerFunction<TRetValue (TType::*)(TParameters...) const>              { typedef TRetValue type(TParameters...); };
template<typename TType, typename TRetValue, typename... TParameters>
struct LuaContext::RemoveMemberPointerFunction<TRetValue (TType::*)(TParameters...) volatile>           { typedef TRetValue type(TParameters...); };
template<typename TType, typename TRetValue, typename... TParameters>
struct LuaContext::RemoveMemberPointerFunction<TRetValue (TType::*)(TParameters...) const volatile>     { typedef TRetValue type(TParameters...); };

// implementation of PusherTotalMinSize
template<typename TFirst, typename... TTypes>
struct LuaContext::PusherTotalMinSize<TFirst, TTypes...> { static const int size = Pusher<typename std::decay<TFirst>::type>::minSize + PusherTotalMinSize<TTypes...>::size; };
template<>
struct LuaContext::PusherTotalMinSize<> { static const int size = 0; };

// implementation of PusherTotalMaxSize
template<typename TFirst, typename... TTypes>
struct LuaContext::PusherTotalMaxSize<TFirst, TTypes...> { static const int size = Pusher<typename std::decay<TFirst>::type>::maxSize + PusherTotalMaxSize<TTypes...>::size; };
template<>
struct LuaContext::PusherTotalMaxSize<> { static const int size = 0; };

// implementation of PusherMinSize
template<typename TFirst, typename... TTypes>
struct LuaContext::PusherMinSize<TFirst, TTypes...> { static const int size = Pusher<typename std::decay<TFirst>::type>::minSize < PusherTotalMaxSize<TTypes...>::size ? Pusher<typename std::decay<TFirst>::type>::minSize : PusherMinSize<TTypes...>::size; };
template<>
struct LuaContext::PusherMinSize<> { static const int size = 0; };

// implementation of PusherMaxSize
template<typename TFirst, typename... TTypes>
struct LuaContext::PusherMaxSize<TFirst, TTypes...> { static const int size = Pusher<typename std::decay<TFirst>::type>::maxSize > PusherTotalMaxSize<TTypes...>::size ? Pusher<typename std::decay<TFirst>::type>::maxSize : PusherMaxSize<TTypes...>::size; };
template<>
struct LuaContext::PusherMaxSize<> { static const int size = 0; };

// implementation of FunctionArgumentsCounter
template<typename TFirst, typename... TParams>
struct LuaContext::FunctionArgumentsCounter<TFirst, TParams...> {
    typedef FunctionArgumentsCounter<TParams...>
        SubType;
    static const int min = (IsOptional<TFirst>::value && SubType::min == 0) ? 0 : 1 + SubType::min;
    static const int max = 1 + SubType::max;
};
template<>
struct LuaContext::FunctionArgumentsCounter<> {
    static const int min = 0;
    static const int max = 0;
};

// implementation of IsOptional
template<typename T>
struct LuaContext::IsOptional<boost::optional<T>> : public std::true_type {};

// implementation of LuaFunctionCaller
template<typename TFunctionType>
class LuaContext::LuaFunctionCaller { static_assert(std::is_function<TFunctionType>::value, "Template parameter of LuaFunctionCaller must be a function type"); };
template<typename TRetValue, typename... TParams>
class LuaContext::LuaFunctionCaller<TRetValue (TParams...)>
{
public:
    TRetValue operator()(TParams&&... params) const
    {
        auto obj = valueHolder->pop();
        return call<TRetValue>(state, std::move(obj), std::forward<TParams>(params)...);
    }

private:
    std::shared_ptr<ValueInRegistry>    valueHolder;
    lua_State*                          state;

private:
    friend LuaContext;
    explicit LuaFunctionCaller(lua_State* state) :
        valueHolder(std::make_shared<ValueInRegistry>(state)),
        state(state)
    {}
};


/**************************************************/
/*                PUSH FUNCTIONS                  */
/**************************************************/
// specializations of the Pusher structure

// boolean
template<>
struct LuaContext::Pusher<bool> {
    static const int minSize = 1;
    static const int maxSize = 1;

    static PushedObject push(lua_State* state, bool value) noexcept {
        lua_pushboolean(state, value);
        return PushedObject{state, 1};
    }
};

// string
template<>
struct LuaContext::Pusher<std::string> {
    static const int minSize = 1;
    static const int maxSize = 1;

    static PushedObject push(lua_State* state, const std::string& value) noexcept {
        lua_pushstring(state, value.c_str());
        return PushedObject{state, 1};
    }
};

// const char*
template<>
struct LuaContext::Pusher<const char*> {
    static const int minSize = 1;
    static const int maxSize = 1;

    static PushedObject push(lua_State* state, const char* value) noexcept {
        lua_pushstring(state, value);
        return PushedObject{state, 1};
    }
};

// const char[N]
template<int N>
struct LuaContext::Pusher<const char[N]> {
    static const int minSize = 1;
    static const int maxSize = 1;

    static PushedObject push(lua_State* state, const char* value) noexcept {
        lua_pushstring(state, value);
        return PushedObject{state, 1};
    }
};

// floating numbers
template<typename T>
struct LuaContext::Pusher<T, typename std::enable_if<std::is_floating_point<T>::value>::type> {
    static const int minSize = 1;
    static const int maxSize = 1;

    static PushedObject push(lua_State* state, T value) noexcept {
        lua_pushnumber(state, value);
        return PushedObject{state, 1};
    }
};

// integers
template<typename T>
struct LuaContext::Pusher<T, typename std::enable_if<std::is_integral<T>::value>::type> {
    static const int minSize = 1;
    static const int maxSize = 1;

    static PushedObject push(lua_State* state, T value) noexcept {
        lua_pushinteger(state, value);
        return PushedObject{state, 1};
    }
};

// nil
template<>
struct LuaContext::Pusher<std::nullptr_t> {
    static const int minSize = 1;
    static const int maxSize = 1;

    static PushedObject push(lua_State* state, std::nullptr_t value) noexcept {
        assert(value == nullptr);
        lua_pushnil(state);
        return PushedObject{state, 1};
    }
};

// empty arrays
template<>
struct LuaContext::Pusher<LuaContext::EmptyArray_t> {
    static const int minSize = 1;
    static const int maxSize = 1;

    static PushedObject push(lua_State* state, EmptyArray_t) noexcept {
        lua_newtable(state);
        return PushedObject{state, 1};
    }
};

// std::type_info* is a lightuserdata
template<>
struct LuaContext::Pusher<const std::type_info*> {
    static const int minSize = 1;
    static const int maxSize = 1;

    static PushedObject push(lua_State* state, const std::type_info* ptr) noexcept {
        lua_pushlightuserdata(state, const_cast<std::type_info*>(ptr));
        return PushedObject{state, 1};
    }
};

// thread
template<>
struct LuaContext::Pusher<LuaContext::ThreadID> {
    static const int minSize = 1;
    static const int maxSize = 1;

    static PushedObject push(lua_State* state, const LuaContext::ThreadID& value) noexcept {
        lua_pushthread(value.state);
        return PushedObject{state, 1};
    }
};

// maps
template<typename TKey, typename TValue>
struct LuaContext::Pusher<std::map<TKey,TValue>> {
    static const int minSize = 1;
    static const int maxSize = 1;

    static PushedObject push(lua_State* state, const std::map<TKey,TValue>& value) noexcept {
        static_assert(Pusher<typename std::decay<TKey>::type>::minSize == 1 && Pusher<typename std::decay<TKey>::type>::maxSize == 1, "Can't push multiple elements for a table key");
        static_assert(Pusher<typename std::decay<TValue>::type>::minSize == 1 && Pusher<typename std::decay<TValue>::type>::maxSize == 1, "Can't push multiple elements for a table value");
        
        auto obj = Pusher<EmptyArray_t>::push(state, EmptyArray);

        for (auto i = value.begin(), e = value.end(); i != e; ++i)
            setTable<TValue>(state, obj, i->first, i->second);
        
        return std::move(obj);
    }
};

// unordered_maps
template<typename TKey, typename TValue>
struct LuaContext::Pusher<std::unordered_map<TKey,TValue>> {
    static const int minSize = 1;
    static const int maxSize = 1;

    static PushedObject push(lua_State* state, const std::unordered_map<TKey,TValue>& value) noexcept {
        static_assert(Pusher<typename std::decay<TKey>::type>::minSize == 1 && Pusher<typename std::decay<TKey>::type>::maxSize == 1, "Can't push multiple elements for a table key");
        static_assert(Pusher<typename std::decay<TValue>::type>::minSize == 1 && Pusher<typename std::decay<TValue>::type>::maxSize == 1, "Can't push multiple elements for a table value");
        
        auto obj = Pusher<EmptyArray_t>::push(state, EmptyArray);

        for (auto i = value.begin(), e = value.end(); i != e; ++i)
            setTable<TValue>(state, obj, i->first, i->second);
        
        return std::move(obj);
    }
};

// vectors of pairs
template<typename TType1, typename TType2>
struct LuaContext::Pusher<std::vector<std::pair<TType1,TType2>>> {
    static const int minSize = 1;
    static const int maxSize = 1;

    static PushedObject push(lua_State* state, const std::vector<std::pair<TType1,TType2>>& value) noexcept {
        static_assert(Pusher<typename std::decay<TType1>::type>::minSize == 1 && Pusher<typename std::decay<TType1>::type>::maxSize == 1, "Can't push multiple elements for a table key");
        static_assert(Pusher<typename std::decay<TType2>::type>::minSize == 1 && Pusher<typename std::decay<TType2>::type>::maxSize == 1, "Can't push multiple elements for a table value");

        auto obj = Pusher<EmptyArray_t>::push(state, EmptyArray);

        for (auto i = value.begin(), e = value.end(); i != e; ++i)
            setTable<TType2>(state, obj, i->first, i->second);
        
        return std::move(obj);
    }
};

// vectors
template<typename TType>
struct LuaContext::Pusher<std::vector<TType>> {
    static const int minSize = 1;
    static const int maxSize = 1;

    static PushedObject push(lua_State* state, const std::vector<TType>& value) noexcept {
        static_assert(Pusher<typename std::decay<TType>::type>::minSize == 1 && Pusher<typename std::decay<TType>::type>::maxSize == 1, "Can't push multiple elements for a table value");
        
        auto obj = Pusher<EmptyArray_t>::push(state, EmptyArray);

        for (unsigned int i = 0; i < value.size(); ++i)
            setTable<TType>(state, obj, i + 1, value[i]);
        
        return std::move(obj);
    }
};

// unique_ptr
template<typename TType>
struct LuaContext::Pusher<std::unique_ptr<TType>> {
    static const int minSize = Pusher<std::shared_ptr<TType>>::minSize;
    static const int maxSize = Pusher<std::shared_ptr<TType>>::maxSize;

    static PushedObject push(lua_State* state, std::unique_ptr<TType> value) noexcept {
        return Pusher<std::shared_ptr<TType>>::push(state, std::move(value));
    }
};

// enum
template<typename TEnum>
struct LuaContext::Pusher<TEnum, typename std::enable_if<std::is_enum<TEnum>::value>::type> {
    #if !defined(__clang__) || __clang_major__ > 3 || (__clang_major__ == 3 && __clang_minor__ > 3)
        typedef typename std::underlying_type<TEnum>::type
            RealType;
    #else
        // implementation when std::underlying_type is not supported
        typedef unsigned long
            RealType;
    #endif

    static const int minSize = Pusher<RealType>::minSize;
    static const int maxSize = Pusher<RealType>::maxSize;

    static PushedObject push(lua_State* state, TEnum value) noexcept {
        return Pusher<RealType>::push(state, static_cast<RealType>(value));
    }
};

// any function
// this specialization is not directly called, but is called by other specializations
template<typename TReturnType, typename... TParameters>
struct LuaContext::Pusher<TReturnType (TParameters...)>
{
    static const int minSize = 1;
    static const int maxSize = 1;

    // counts the number of arguments
    typedef FunctionArgumentsCounter<TParameters...>
        LocalFunctionArgumentsCounter;

    // this is the version of "push" for non-trivially destructible function objects
    template<typename TFunctionObject>
    static auto push(lua_State* state, TFunctionObject fn) noexcept
        -> typename std::enable_if<!boost::has_trivial_destructor<TFunctionObject>::value, PushedObject>::type
    {
        // TODO: is_move_constructible not supported by some compilers
        //static_assert(std::is_move_constructible<TFunctionObject>::value, "The function object must be move-constructible");

        // when the lua script calls the thing we will push on the stack, we want "fn" to be executed
        // if we used lua's cfunctions system, we could not detect when the function is no longer in use, which could cause problems
        // so we use userdata instead
        
        // this function is called when the lua script tries to call our custom data type
        // we transfer execution to the "callback" function below
        const auto callCallback = [](lua_State* lua) -> int {
            assert(lua_gettop(lua) >= 1);
            assert(lua_isuserdata(lua, 1));
            auto function = static_cast<TFunctionObject*>(lua_touserdata(lua, 1));
            assert(function);

            return callback(lua, function, lua_gettop(lua) - 1).release();
        };

        // this one is called when lua's garbage collector no longer needs our custom data type
        // we call the function object's destructor
        const auto garbageCallback = [](lua_State* lua) -> int {
            assert(lua_gettop(lua) == 1);
            auto function = static_cast<TFunctionObject*>(lua_touserdata(lua, 1));
            assert(function);
            function->~TFunctionObject();
            return 0;
        };

        // creating the object
        // lua_newuserdata allocates memory in the internals of the lua library and returns it so we can fill it
        //   and that's what we do with placement-new
        const auto functionLocation = static_cast<TFunctionObject*>(lua_newuserdata(state, sizeof(TFunctionObject)));
        new (functionLocation) TFunctionObject(std::move(fn));

        // creating the metatable (over the object on the stack)
        // lua_settable pops the key and value we just pushed, so stack management is easy
        // all that remains on the stack after these function calls is the metatable
        lua_newtable(state);
        lua_pushstring(state, "__call");
        lua_pushcfunction(state, callCallback);
        lua_settable(state, -3);

        lua_pushstring(state, "__gc");
        lua_pushcfunction(state, garbageCallback);
        lua_settable(state, -3);

        // at this point, the stack contains the object at offset -2 and the metatable at offset -1
        // lua_setmetatable will bind the two together and pop the metatable
        // our custom function remains on the stack (and that's what we want)
        lua_setmetatable(state, -2);

        return PushedObject{state, 1};
    }

    // this is the version of "push" for trivially destructible objects
    template<typename TFunctionObject>
    static auto push(lua_State* state, TFunctionObject fn) noexcept
        -> typename std::enable_if<boost::has_trivial_destructor<TFunctionObject>::value, PushedObject>::type
    {
        // TODO: is_move_constructible not supported by some compilers
        //static_assert(std::is_move_constructible<TFunctionObject>::value, "The function object must be move-constructible");

        // when the lua script calls the thing we will push on the stack, we want "fn" to be executed
        // since "fn" doesn't need to be destroyed, we simply push it on the stack

        // this is the cfunction that is the callback
        const auto function = [](lua_State* state) -> int
        {
            // the function object is an upvalue
            const auto toCall = static_cast<TFunctionObject*>(lua_touserdata(state, lua_upvalueindex(1)));
            return callback(state, toCall, lua_gettop(state)).release();
        };

        // we copy the function object onto the stack
        const auto functionObjectLocation = static_cast<TFunctionObject*>(lua_newuserdata(state, sizeof(TFunctionObject)));
        new (functionObjectLocation) TFunctionObject(std::move(fn));

        // pushing the function with the function object as upvalue
        lua_pushcclosure(state, function, 1);
        return PushedObject{state, 1};
    }
    
    // this is the version of "push" for pointer to functions
    static auto push(lua_State* state, TReturnType (*fn)(TParameters...)) noexcept
        -> PushedObject
    {
        // when the lua script calls the thing we will push on the stack, we want "fn" to be executed
        // since "fn" doesn't need to be destroyed, we simply push it on the stack

        // this is the cfunction that is the callback
        const auto function = [](lua_State* state) -> int
        {
            // the function object is an upvalue
            const auto toCall = reinterpret_cast<TReturnType (*)(TParameters...)>(lua_touserdata(state, lua_upvalueindex(1)));
            return callback(state, toCall, lua_gettop(state)).release();
        };

        // we copy the function object onto the stack
        lua_pushlightuserdata(state, reinterpret_cast<void*>(fn));

        // pushing the function with the function object as upvalue
        lua_pushcclosure(state, function, 1);
        return PushedObject{state, 1};
    }
    
    // this is the version of "push" for references to functions
    static auto push(lua_State* state, TReturnType (&fn)(TParameters...)) noexcept
        -> PushedObject
    {
        return push(state, &fn);
    }

private:
    // callback that calls the function object
    // this function is used by the callbacks and handles loading arguments from the stack and pushing the return value back
    template<typename TFunctionObject>
    static auto callback(lua_State* state, TFunctionObject* toCall, int argumentsCount)
        -> PushedObject
    {
        // checking if number of parameters is correct
        if (argumentsCount < LocalFunctionArgumentsCounter::min) {
            // if not, using lua_error to return an error
            luaL_where(state, 1);
            lua_pushstring(state, "This function requires at least ");
            lua_pushnumber(state, LocalFunctionArgumentsCounter::min);
            lua_pushstring(state, " parameter(s)");
            lua_concat(state, 4);
            luaError(state);

        } else if (argumentsCount > LocalFunctionArgumentsCounter::max) {
            // if not, using lua_error to return an error
            luaL_where(state, 1);
            lua_pushstring(state, "This function requires at most ");
            lua_pushnumber(state, LocalFunctionArgumentsCounter::max);
            lua_pushstring(state, " parameter(s)");
            lua_concat(state, 4);
            luaError(state);
        }
                
        // calling the function
        try {
            return callback2(state, *toCall, argumentsCount);

        } catch (const WrongTypeException& ex) {
            // wrong parameter type, using lua_error to return an error
            luaL_where(state, 1);
            lua_pushstring(state, "Unable to convert parameter from ");
            lua_pushstring(state, ex.luaType.c_str());
            lua_pushstring(state, " to ");
            lua_pushstring(state, ex.destination.name());
            lua_concat(state, 4);
            luaError(state);

        } catch (...) {
            Pusher<std::exception_ptr>::push(state, std::current_exception()).release();
            luaError(state);
        }
    }
    
    template<typename TFunctionObject>
    static auto callback2(lua_State* state, TFunctionObject&& toCall, int argumentsCount)
        -> typename std::enable_if<!std::is_void<TReturnType>::value && !std::is_void<TFunctionObject>::value, PushedObject>::type
    {
        // pushing the result on the stack and returning number of pushed elements
        typedef Pusher<typename std::decay<TReturnType>::type>
            P;
        return P::push(state, readIntoFunction(state, tag<TReturnType>{}, toCall, -argumentsCount, tag<TParameters>{}...));
    }
    
    template<typename TFunctionObject>
    static auto callback2(lua_State* state, TFunctionObject&& toCall, int argumentsCount)
        -> typename std::enable_if<std::is_void<TReturnType>::value && !std::is_void<TFunctionObject>::value, PushedObject>::type
    {
        readIntoFunction(state, tag<TReturnType>{}, toCall, -argumentsCount, tag<TParameters>{}...);
        return PushedObject{state, 0};
    }
};

// C function pointers
template<typename TReturnType, typename... TParameters>
struct LuaContext::Pusher<TReturnType (*)(TParameters...)>
{
    // using the function-pushing implementation
    typedef Pusher<TReturnType (TParameters...)>
        SubPusher;
    static const int minSize = SubPusher::minSize;
    static const int maxSize = SubPusher::maxSize;

    template<typename TType>
    static PushedObject push(lua_State* state, TType value) noexcept {
        return SubPusher::push(state, value);
    }
};

// C function references
template<typename TReturnType, typename... TParameters>
struct LuaContext::Pusher<TReturnType (&)(TParameters...)>
{
    // using the function-pushing implementation
    typedef Pusher<TReturnType(TParameters...)>
        SubPusher;
    static const int minSize = SubPusher::minSize;
    static const int maxSize = SubPusher::maxSize;

    template<typename TType>
    static PushedObject push(lua_State* state, TType value) noexcept {
        return SubPusher::push(state, value);
    }
};

// std::function
template<typename TReturnType, typename... TParameters>
struct LuaContext::Pusher<std::function<TReturnType (TParameters...)>>
{
    // using the function-pushing implementation
    typedef Pusher<TReturnType (TParameters...)>
        SubPusher;
    static const int minSize = SubPusher::minSize;
    static const int maxSize = SubPusher::maxSize;

    static PushedObject push(lua_State* state, const std::function<TReturnType (TParameters...)>& value) noexcept {
        return SubPusher::push(state, value);
    }
};

// boost::variant
template<typename... TTypes>
struct LuaContext::Pusher<boost::variant<TTypes...>>
{
    static const int minSize = PusherMinSize<TTypes...>::size;
    static const int maxSize = PusherMaxSize<TTypes...>::size;

    static PushedObject push(lua_State* state, const boost::variant<TTypes...>& value) noexcept {
        PushedObject obj{state, 0};
        VariantWriter writer{state, obj};
        value.apply_visitor(writer);
        return std::move(obj);
    }

private:
    struct VariantWriter : public boost::static_visitor<> {
        template<typename TType>
        void operator()(TType value) noexcept
        {
            obj = Pusher<typename std::decay<TType>::type>::push(state, std::move(value));
        }

        VariantWriter(lua_State* state, PushedObject& obj) : state(state), obj(obj) {}
        lua_State* state;
        PushedObject& obj;
    };
};

// boost::optional
template<typename TType>
struct LuaContext::Pusher<boost::optional<TType>> {
    typedef Pusher<typename std::decay<TType>::type>
        UnderlyingPusher;

    static const int minSize = UnderlyingPusher::minSize < 1 ? UnderlyingPusher::minSize : 1;
    static const int maxSize = UnderlyingPusher::maxSize > 1 ? UnderlyingPusher::maxSize : 1;

    static PushedObject push(lua_State* state, const boost::optional<TType>& value) noexcept {
        if (value) {
            return UnderlyingPusher::push(state, value.get());
        } else {
            lua_pushnil(state);
            return PushedObject{state, 1};
        }
    }
};

// tuple
template<typename... TTypes>
struct LuaContext::Pusher<std::tuple<TTypes...>> {
    // TODO: NOT EXCEPTION SAFE /!\ //
    static const int minSize = PusherTotalMinSize<TTypes...>::size;
    static const int maxSize = PusherTotalMaxSize<TTypes...>::size;

    static PushedObject push(lua_State* state, const std::tuple<TTypes...>& value) noexcept {
        return PushedObject{state, push2(state, value, std::integral_constant<int,0>{})};
    }

    static PushedObject push(lua_State* state, std::tuple<TTypes...>&& value) noexcept {
        return PushedObject{state, push2(state, std::move(value), std::integral_constant<int,0>{})};
    }

private:
    template<int N>
    static int push2(lua_State* state, const std::tuple<TTypes...>& value, std::integral_constant<int,N>) noexcept {
        typedef typename std::tuple_element<N,std::tuple<TTypes...>>::type ElemType;

        return Pusher<typename std::decay<ElemType>::type>::push(state, std::get<N>(value)).release() +
            push2(state, value, std::integral_constant<int,N+1>{});
    }

    template<int N>
    static int push2(lua_State* state, std::tuple<TTypes...>&& value, std::integral_constant<int,N>) noexcept {
        typedef typename std::tuple_element<N,std::tuple<TTypes...>>::type ElemType;

        return Pusher<typename std::decay<ElemType>::type>::push(state, std::move(std::get<N>(value))).release() +
            push2(state, std::move(value), std::integral_constant<int,N+1>{});
    }
    
    static int push2(lua_State* state, const std::tuple<TTypes...>&, std::integral_constant<int,sizeof...(TTypes)>) noexcept {
        return 0;
    }
    
    static int push2(lua_State* state, std::tuple<TTypes...>&&, std::integral_constant<int,sizeof...(TTypes)>) noexcept {
        return 0;
    }
};

/**************************************************/
/*                READ FUNCTIONS                  */
/**************************************************/
// specializations of the Reader structures

// reading null
template<>
struct LuaContext::Reader<std::nullptr_t>
{
    static auto read(lua_State* state, int index)
        -> boost::optional<std::nullptr_t>
    {
        if (!lua_isnil(state, index))
            return boost::none;
        return nullptr;
    }
};

// integrals
template<typename TType>
struct LuaContext::Reader<
            TType,
            typename std::enable_if<std::is_integral<TType>::value>::type
        >
{
    static auto read(lua_State* state, int index)
        -> boost::optional<TType>
    {
#       if LUA_VERSION_NUM >= 502

            int success;
            auto value = lua_tointegerx(state, index, &success);
            if (success == 0)
                return boost::none;
            return static_cast<TType>(value);

#       else

            if (!lua_isnumber(state, index))
                return boost::none;
            return static_cast<TType>(lua_tointeger(state, index));

#       endif
    }
};

// floating points
template<typename TType>
struct LuaContext::Reader<
            TType,
            typename std::enable_if<std::is_floating_point<TType>::value>::type
        >
{
    static auto read(lua_State* state, int index)
        -> boost::optional<TType>
    {
#       if LUA_VERSION_NUM >= 502

            int success;
            auto value = lua_tonumberx(state, index, &success);
            if (success == 0)
                return boost::none;
            return static_cast<TType>(value);

#       else

            if (!lua_isnumber(state, index))
                return boost::none;
            return static_cast<TType>(lua_tonumber(state, index));

#       endif
    }
};

// boolean
template<>
struct LuaContext::Reader<bool>
{
    static auto read(lua_State* state, int index)
        -> boost::optional<bool>
    {
        if (!lua_isboolean(state, index))
            return boost::none;
        return lua_toboolean(state, index) != 0;
    }
};

// string
// lua_tostring returns a temporary pointer, but that's not a problem since we copy
//   the data into a std::string
template<>
struct LuaContext::Reader<std::string>
{
    static auto read(lua_State* state, int index)
        -> boost::optional<std::string>
    {
        const auto val = lua_tostring(state, index);
        if (val == 0)
            return boost::none;
        return std::string(val);
    }
};

// enums
template<typename TType>
struct LuaContext::Reader<
            TType,
            typename std::enable_if<std::is_enum<TType>::value>::type
        >
{
    static auto read(lua_State* state, int index)
        -> boost::optional<TType>
    {
        if (!lua_isnumber(state, index) != 0 || fmod(lua_tonumber(state, index), 1.) != 0)
            return boost::none;
        return static_cast<TType>(lua_tointeger(state, index));
    }
};

// LuaFunctionCaller
template<typename TRetValue, typename... TParameters>
struct LuaContext::Reader<LuaContext::LuaFunctionCaller<TRetValue (TParameters...)>>
{
    typedef LuaFunctionCaller<TRetValue (TParameters...)>
        ReturnType;

    static auto read(lua_State* state, int index)
        -> boost::optional<ReturnType>
    {
        if (lua_isfunction(state, index) == 0 && lua_isuserdata(state, index) == 0)
            return boost::none;
        return ReturnType(state);
    }
};

// function
template<typename TRetValue, typename... TParameters>
struct LuaContext::Reader<std::function<TRetValue (TParameters...)>>
{
    static auto read(lua_State* state, int index)
        -> boost::optional<std::function<TRetValue (TParameters...)>>
    {
		if (auto val = Reader<LuaContext::LuaFunctionCaller<TRetValue (TParameters...)>>::read(state, index))
		{
			std::function<TRetValue (TParameters...)> f{*val};
			return boost::optional<std::function<TRetValue (TParameters...)>>{std::move(f)};
		}

        return boost::none;
    }
};

// vector of pairs
template<typename TType1, typename TType2>
struct LuaContext::Reader<std::vector<std::pair<TType1,TType2>>>
{
    static auto read(lua_State* state, int index)
        -> boost::optional<std::vector<std::pair<TType1, TType2>>>
    {
        if (!lua_istable(state, index))
            return boost::none;

        std::vector<std::pair<TType1, TType2>> result;

        // we traverse the table at the top of the stack
        lua_pushnil(state);     // first key
        while (lua_next(state, (index > 0) ? index : (index - 1)) != 0) {
            // now a key and its value are pushed on the stack
            try {
                auto val1 = Reader<TType1>::read(state, -2);
                auto val2 = Reader<TType2>::read(state, -1);

                if (!val1.is_initialized() || !val2.is_initialized()) {
                    lua_pop(state, 2);      // we remove the value and the key
                    return {};
                }

                result.push_back({ std::move(val1.get()), std::move(val2.get()) });
                lua_pop(state, 1);      // we remove the value but keep the key for the next iteration

            } catch(...) {
                lua_pop(state, 2);      // we remove the value and the key
                return {};
            }
        }

        return { std::move(result) };
    }
};

// map
template<typename TKey, typename TValue>
struct LuaContext::Reader<std::map<TKey,TValue>>
{
    static auto read(lua_State* state, int index)
        -> boost::optional<std::map<TKey,TValue>>
    {
        if (!lua_istable(state, index))
            return boost::none;

        std::map<TKey,TValue> result;

        // we traverse the table at the top of the stack
        lua_pushnil(state);     // first key
        while (lua_next(state, (index > 0) ? index : (index - 1)) != 0) {
            // now a key and its value are pushed on the stack
            try {
                auto key = Reader<TKey>::read(state, -2);
                auto value = Reader<TValue>::read(state, -1);

                if (!key.is_initialized() || !value.is_initialized()) {
                    lua_pop(state, 2);      // we remove the value and the key
                    return {};
                }

                result.insert({ std::move(key.get()), std::move(value.get()) });
                lua_pop(state, 1);      // we remove the value but keep the key for the next iteration

            } catch(...) {
                lua_pop(state, 2);      // we remove the value and the key
                return {};
            }
        }

        return { std::move(result) };
    }
};

// unordered_map
template<typename TKey, typename TValue>
struct LuaContext::Reader<std::unordered_map<TKey,TValue>>
{
    static auto read(lua_State* state, int index)
        -> boost::optional<std::unordered_map<TKey,TValue>>
    {
        if (!lua_istable(state, index))
            return boost::none;

        std::unordered_map<TKey,TValue> result;

        // we traverse the table at the top of the stack
        lua_pushnil(state);     // first key
        while (lua_next(state, (index > 0) ? index : (index - 1)) != 0) {
            // now a key and its value are pushed on the stack
            try {
                auto key = Reader<TKey>::read(state, -2);
                auto value = Reader<TValue>::read(state, -1);

                if (!key.is_initialized() || !value.is_initialized()) {
                    lua_pop(state, 2);      // we remove the value and the key
                    return {};
                }

                result.insert({ std::move(key.get()), std::move(value.get()) });
                lua_pop(state, 1);      // we remove the value but keep the key for the next iteration

            } catch(...) {
                lua_pop(state, 2);      // we remove the value and the key
                return {};
            }
        }

        return { std::move(result) };
    }
};

// optional
// IMPORTANT: optional means "either nil or the value of the right type"
//  * if the value is nil, then an optional containing an empty optional is returned
//  * if the value is of the right type, then an optional containing an optional containing the value is returned
//  * if the value is of the wrong type, then an empty optional is returned
template<typename TType>
struct LuaContext::Reader<boost::optional<TType>>
{
    static auto read(lua_State* state, int index)
        -> boost::optional<boost::optional<TType>>
    {
        if (lua_isnil(state, index))
            return boost::optional<TType>{boost::none};
        if (auto&& other = Reader<TType>::read(state, index))
            return std::move(other);
        return boost::none;
    }
};

// variant
template<typename... TTypes>
struct LuaContext::Reader<boost::variant<TTypes...>>
{
	typedef boost::variant<TTypes...>
		ReturnType;

private:
    // class doing operations for a range of types from TIterBegin to TIterEnd
    template<typename TIterBegin, typename TIterEnd, typename = void>
    struct VariantReader
    {
        using SubReader = Reader<typename std::decay<typename boost::mpl::deref<TIterBegin>::type>::type>;

        static auto read(lua_State* state, int index)
            -> boost::optional<ReturnType>
        {
            // note: using SubReader::read triggers a compilation error when used with a reference
            if (const auto val = SubReader::read(state, index))
                return boost::variant<TTypes...>{*val};
            return VariantReader<typename boost::mpl::next<TIterBegin>::type, TIterEnd>::read(state, index);
        }
    };

    // specialization of class above being called when list of remaining types is empty
    template<typename TIterBegin, typename TIterEnd>
    struct VariantReader<TIterBegin, TIterEnd, typename std::enable_if<boost::mpl::distance<TIterBegin, TIterEnd>::type::value == 0>::type>
    {
        static auto read(lua_State* state, int index)
            -> boost::optional<ReturnType> 
        {
            return boost::none;
        }
    };

    // this is the main type
    typedef VariantReader<typename boost::mpl::begin<typename ReturnType::types>::type, typename boost::mpl::end<typename ReturnType::types>::type>
        MainVariantReader;

public:
    static auto read(lua_State* state, int index)
        -> boost::optional<ReturnType>
    {
        return MainVariantReader::read(state, index);
    }
};

// reading a tuple
// tuple have an additional argument for their functions, that is the maximum size to read
// if maxSize is smaller than the tuple size, then the remaining parameters will be left to default value
template<>
struct LuaContext::Reader<std::tuple<>>
{
    static auto read(lua_State* state, int index, int maxSize = 0)
        -> boost::optional<std::tuple<>>
    {
        return std::tuple<>{};
    }
};

template<typename TFirst, typename... TOthers>
struct LuaContext::Reader<std::tuple<TFirst, TOthers...>,
        typename std::enable_if<!LuaContext::IsOptional<TFirst>::value>::type       // TODO: replace by std::is_default_constructible when it works on every compiler
    >
{
    // this is the "TFirst is NOT default constructible" version

	typedef std::tuple<TFirst, TOthers...>
		ReturnType;

    static auto read(lua_State* state, int index, int maxSize = std::tuple_size<ReturnType>::value)
        -> boost::optional<ReturnType>
    {
        if (maxSize <= 0)
            return boost::none;

        auto firstVal = Reader<TFirst>::read(state, index);
        auto othersVal = Reader<std::tuple<TOthers...>>::read(state, index + 1, maxSize - 1);
        
        if (!firstVal || !othersVal)
            return boost::none;

        return std::tuple_cat(std::tuple<TFirst>(*firstVal), std::move(*othersVal));
    }
};

template<typename TFirst, typename... TOthers>
struct LuaContext::Reader<std::tuple<TFirst, TOthers...>,
        typename std::enable_if<LuaContext::IsOptional<TFirst>::value>::type        // TODO: replace by std::is_default_constructible when it works on every compiler
    >
{
    // this is the "TFirst is default-constructible" version
	
	typedef std::tuple<TFirst, TOthers...>
		ReturnType;
    
    static auto read(lua_State* state, int index, int maxSize = std::tuple_size<ReturnType>::value)
        -> boost::optional<ReturnType>
    {
        auto othersVal = Reader<std::tuple<TOthers...>>::read(state, index + 1, maxSize - 1);
        if (!othersVal)
            return boost::none;
        
        if (maxSize <= 0)
            return std::tuple_cat(std::tuple<TFirst>(), std::move(*othersVal));
        
        auto firstVal = Reader<TFirst>::read(state, index);
        if (!firstVal)
            return boost::none;

        return std::tuple_cat(std::tuple<TFirst>(*firstVal), std::move(*othersVal));
    }
};

#endif
