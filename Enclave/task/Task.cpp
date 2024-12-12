
#include "Task.h"
#include "common/tee_error.h"

int Dispatcher::dispatch(uint32_t task_type, const std::string& request, std::string& reply)
{
    for( int i = 0; i < m_vTask.size(); i ++ ){
        if ( m_vTask[i]->get_task_type() == task_type ){
            return m_vTask[i]->execute(request, reply );
        }
    }
    return TEE_ERROR_FAILED_TO_DISPATCH_REQUEST;
}

void Dispatcher::register_task(Task* task)
{
    m_vTask.push_back(task);
}

void Dispatcher::unregister_task()
{
    for (auto it = m_vTask.begin(); it != m_vTask.end();) {
        Task* task = (Task*)(*it);
        delete task;
        it = m_vTask.erase( it );
    }
}
